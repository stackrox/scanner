#!/usr/bin/env bash

set -euo pipefail

SCRIPTS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib.sh
source "$SCRIPTS_ROOT/lib.sh"

# Store the original repo root (where we were invoked from).
ORIGINAL_REPO_ROOT="$(git rev-parse --show-toplevel)"

# Flags
DRY_RUN=false
YES=false

# Temp worktree directory (set during execution).
WORKTREE_DIR=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] <VERSION>

Create a patch release for scanner.

Arguments:
  VERSION       Release version in one of these formats:
                  X.Y      - Auto-detect next patch number (e.g., 2.36)
                  X.Y.Z    - Use specific patch number (e.g., 2.36.7)

Options:
  --dry-run     Show what would happen without executing
  -y, --yes     Skip confirmations (for automation)
  -h, --help    Show this help message

Examples:
  $(basename "$0") 2.36              # Auto-detect next patch number
  $(basename "$0") 2.36.7            # Create 2.36.7 specifically
  $(basename "$0") --dry-run 2.36    # Preview what would happen

Prerequisites:
  - GitHub CLI (gh) must be installed and authenticated
  - User must have "bypass branch protection" permissions on release branches
EOF
}

log_info() {
    echo -e "${GREEN}INFO:${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}WARN:${NC} $*"
}

log_error() {
    echo -e "${RED}ERROR:${NC} $*"
}

log_dry_run() {
    echo -e "${YELLOW}[DRY-RUN]${NC} Would execute: $*"
}

# Cleanup function to remove the temporary worktree.
cleanup_worktree() {
    if [[ -n "$WORKTREE_DIR" && -d "$WORKTREE_DIR" ]]; then
        log_info "Cleaning up temporary worktree..."
        cd "$ORIGINAL_REPO_ROOT"
        git worktree remove --force "$WORKTREE_DIR" 2>/dev/null || rm -rf "$WORKTREE_DIR"
    fi
}

# Prompt user for confirmation. Returns 0 if confirmed, 1 if declined.
# If --yes flag is set, returns 0 automatically.
confirm() {
    local prompt="$1"
    local default="${2:-n}"

    if [[ "$YES" == "true" ]]; then
        log_info "Auto-confirming (--yes): $prompt"
        return 0
    fi

    local yn_prompt
    if [[ "$default" == "y" ]]; then
        yn_prompt="[Y/n]"
    else
        yn_prompt="[y/N]"
    fi

    read -r -p "$prompt $yn_prompt " response
    response="${response:-$default}"
    case "$response" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) return 1 ;;
    esac
}

# Prompt user to choose from options. Echoes the choice number (1-based).
choose() {
    local prompt="$1"
    shift
    local options=("$@")

    if [[ "$YES" == "true" ]]; then
        log_info "Auto-selecting first option (--yes)"
        echo "1"
        return 0
    fi

    echo "$prompt"
    local i=1
    for opt in "${options[@]}"; do
        echo "  $i) $opt"
        ((i++))
    done

    local choice
    while true; do
        read -r -p "Enter choice [1-${#options[@]}]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#options[@]} )); then
            echo "$choice"
            return 0
        fi
        echo "Invalid choice. Please enter a number between 1 and ${#options[@]}."
    done
}

# Get the latest tag matching a release pattern.
get_latest_tag() {
    local release="$1"
    git tag --list "${release}.*" | grep -E "^${release}\.[0-9]+$" | sort -V | tail -1
}

# Extract patch number from a version tag.
get_patch_number() {
    local tag="$1"
    echo "$tag" | sed -E 's/^[0-9]+\.[0-9]+\.([0-9]+)$/\1/'
}

# Compare two semantic versions. Returns:
#   0 if v1 == v2
#   1 if v1 > v2
#   2 if v1 < v2
semver_compare() {
    local v1="$1"
    local v2="$2"

    if [[ "$v1" == "$v2" ]]; then
        return 0
    fi

    local v1_major v1_minor v1_patch
    local v2_major v2_minor v2_patch

    IFS='.' read -r v1_major v1_minor v1_patch <<< "$v1"
    IFS='.' read -r v2_major v2_minor v2_patch <<< "$v2"

    # Default patch to 0 if not present.
    v1_patch="${v1_patch:-0}"
    v2_patch="${v2_patch:-0}"

    if (( v1_major > v2_major )); then return 1; fi
    if (( v1_major < v2_major )); then return 2; fi
    if (( v1_minor > v2_minor )); then return 1; fi
    if (( v1_minor < v2_minor )); then return 2; fi
    if (( v1_patch > v2_patch )); then return 1; fi
    if (( v1_patch < v2_patch )); then return 2; fi

    return 0
}

# Check if a version is the latest release (should be marked as GitHub "Latest").
is_latest_release() {
    local version="$1"

    local releases
    releases=$(gh release list --limit 20 --json tagName --jq '.[].tagName' 2>/dev/null || echo "")

    if [[ -z "$releases" ]]; then
        # No releases exist, this will be the latest.
        return 0
    fi

    local highest="$version"
    while IFS= read -r tag; do
        # Skip non-semver tags.
        if [[ ! "$tag" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            continue
        fi
        semver_compare "$tag" "$highest" || true
        local result=$?
        if [[ "$result" == "1" ]]; then
            highest="$tag"
        fi
    done <<< "$releases"

    [[ "$highest" == "$version" ]]
}

main() {
    # Parse arguments.
    local release=""
    local patch_number=""
    local positional_args=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -y|--yes)
                YES=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                die "Unknown option: $1"
                ;;
            *)
                positional_args+=("$1")
                shift
                ;;
        esac
    done

    if [[ ${#positional_args[@]} -lt 1 ]]; then
        usage
        die "VERSION argument is required"
    fi

    local version_arg="${positional_args[0]}"

    # Parse version argument: accept X.Y or X.Y.Z format.
    if [[ "$version_arg" =~ ^([0-9]+\.[0-9]+)\.([0-9]+)$ ]]; then
        # X.Y.Z format - extract release and patch number.
        release="${BASH_REMATCH[1]}"
        patch_number="${BASH_REMATCH[2]}"
    elif [[ "$version_arg" =~ ^[0-9]+\.[0-9]+$ ]]; then
        # X.Y format - patch number will be auto-detected.
        release="$version_arg"
        patch_number=""
    else
        die "Invalid VERSION format: $version_arg (expected X.Y or X.Y.Z, e.g., 2.36 or 2.36.7)"
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_warn "Running in dry-run mode. No changes will be made."
        echo
    fi

    # Step 1: Validate prerequisites.
    log_info "Checking prerequisites..."
    require_executable gh "GitHub CLI is required"
    require_executable git "Git is required"

    if ! gh auth status &>/dev/null; then
        die "GitHub CLI is not authenticated. Run 'gh auth login' first."
    fi

    local release_branch="release-${release}"
    if ! git ls-remote --heads origin "$release_branch" | grep -q "$release_branch"; then
        die "Release branch '$release_branch' does not exist on origin"
    fi

    log_info "Prerequisites OK"
    echo

    # Step 2: Fetch tags and determine patch number.
    log_info "Fetching tags from origin..."
    git fetch origin --tags

    local latest_tag
    latest_tag=$(get_latest_tag "$release")
    local expected_patch=1

    if [[ -n "$latest_tag" ]]; then
        local current_patch
        current_patch=$(get_patch_number "$latest_tag")
        expected_patch=$((current_patch + 1))
        log_info "Latest tag: $latest_tag"
        log_info "Expected next patch number: $expected_patch"
    else
        log_info "No existing tags for $release, starting at patch 1"
    fi

    if [[ -z "$patch_number" ]]; then
        patch_number="$expected_patch"
        log_info "Auto-detected patch number: $patch_number"
    else
        log_info "Using provided patch number: $patch_number"
        if [[ ! "$patch_number" =~ ^[0-9]+$ || "$patch_number" -lt 1 ]]; then
            log_error "Invalid patch number: '$patch_number'. Must be a positive integer (>= 1)."
            exit 1
        fi
    fi

    local version="${release}.${patch_number}"
    local previous_tag="${latest_tag:-}"

    # Check if the tag already exists
    if git rev-parse "refs/tags/$version" >/dev/null 2>&1; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log_warn "Tag '$version' already exists (dry-run mode, continuing)."
        else
            log_error "Tag '$version' already exists. Aborting release."
            exit 1
        fi
    fi
    echo

    # Step 3: Create temporary worktree for the release branch.
    log_info "Creating temporary worktree for release branch..."
    WORKTREE_DIR=$(mktemp -d "/tmp/scanner-release-${version}-XXXXXX")
    trap cleanup_worktree EXIT

    if [[ "$DRY_RUN" == "true" ]]; then
        log_dry_run "git worktree add $WORKTREE_DIR $release_branch"
        log_dry_run "cd $WORKTREE_DIR"
        log_dry_run "git pull origin $release_branch"
        log_warn "Skipping worktree creation in dry-run mode; remaining checks use current branch state"
    else
        git worktree add "$WORKTREE_DIR" "$release_branch"
        cd "$WORKTREE_DIR"
        git pull origin "$release_branch"
        log_info "Working in temporary directory: $WORKTREE_DIR"
    fi
    echo

    # Step 4: Check if release is necessary.
    # In dry-run mode, use the remote branch ref since we didn't create the worktree.
    local branch_ref="HEAD"
    if [[ "$DRY_RUN" == "true" ]]; then
        branch_ref="origin/${release_branch}"
        log_info "(Using origin/${release_branch} for dry-run checks)"
    fi

    local head_commit_msg
    head_commit_msg=$(git log -1 --format='%s' "$branch_ref")

    if [[ "$head_commit_msg" =~ ^Release\ [0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_warn "Tip of $release_branch is already a release commit: $head_commit_msg"
        if ! confirm "Create another release commit on top?"; then
            log_info "Aborted by user."
            exit 0
        fi
        echo
    fi

    if [[ "$patch_number" != "$expected_patch" ]]; then
        log_warn "Patch number $patch_number is not sequential."
        log_warn "Latest tag: ${latest_tag:-none}"
        log_warn "Expected next patch: $expected_patch"
        log_warn "Requested patch: $patch_number"
        echo

        local choice
        choice=$(choose "What would you like to do?" \
            "Use expected patch number ($expected_patch)" \
            "Proceed with requested patch number ($patch_number)" \
            "Abort")

        case "$choice" in
            1)
                patch_number="$expected_patch"
                version="${release}.${patch_number}"
                log_info "Using patch number: $patch_number"
                ;;
            2)
                log_info "Proceeding with patch number: $patch_number"
                ;;
            3)
                log_info "Aborted by user."
                exit 0
                ;;
        esac
        echo
    fi

    # Step 5: Show commits since last tag.
    log_info "Commits to be included in $version:"
    echo
    if [[ -n "$previous_tag" ]]; then
        local commits
        commits=$(git log "${previous_tag}..${branch_ref}" --oneline)
        if [[ -z "$commits" ]]; then
            log_warn "No commits since $previous_tag"
            if ! confirm "Create an empty release anyway?"; then
                log_info "Aborted by user."
                exit 0
            fi
        else
            echo "$commits"
        fi
    else
        git log "$branch_ref" --oneline -10
        log_info "(Showing last 10 commits; no previous tag to compare against)"
    fi
    echo

    # Step 6: Confirm with user.
    echo "=========================================="
    echo "Release Summary"
    echo "=========================================="
    echo "Version:         $version"
    echo "Release branch:  $release_branch"
    echo "Previous tag:    ${previous_tag:-none}"
    echo "=========================================="
    echo

    if ! confirm "Proceed with creating this release?"; then
        log_info "Aborted by user."
        exit 0
    fi
    echo

    # Step 7: Ask about cherry-picks.
    if ! [[ "$YES" == "true" ]]; then
        if confirm "Do you need to cherry-pick any commits before proceeding?" "n"; then
            log_info "Pausing for cherry-picks."
            log_info "Run your cherry-pick commands in the worktree directory:"
            log_info "  cd ${WORKTREE_DIR}"
            log_info "  git cherry-pick <commit-hash>"
            log_info ""
            log_info "Then re-run this script to continue."
            log_info ""
            log_info "To clean up the worktree if you decide not to proceed:"
            log_info "  cd ${ORIGINAL_REPO_ROOT}"
            log_info "  git worktree remove ${WORKTREE_DIR}"
            # Disable cleanup trap since user wants to cherry-pick manually.
            trap - EXIT
            WORKTREE_DIR=""
            exit 0
        fi
        echo
    fi

    # Step 8: Create release commit and tag.
    log_info "Creating release commit and tag..."
    if [[ "$DRY_RUN" == "true" ]]; then
        log_dry_run "git commit --allow-empty -m \"Release ${version}\""
        log_dry_run "git tag --no-sign ${version}"
    else
        git commit --allow-empty -m "Release ${version}"
        git tag --no-sign "${version}"
    fi
    echo

    # Step 9: Sanity checks.
    log_info "Running sanity checks..."
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "(Skipping tag verification in dry-run mode)"
    else
        local tags_on_head
        tags_on_head=$(git tag --contains HEAD 2>/dev/null || echo "")
        if ! echo "$tags_on_head" | grep -q "^${version}$"; then
            die "Sanity check failed: tag $version is not on HEAD"
        fi
        log_info "Tag $version is on HEAD"
    fi

    if [[ "$DRY_RUN" != "true" ]]; then
        log_info "Recent commits:"
        git log --oneline -5
        echo
    fi

    # Step 10: Push.
    if ! confirm "Push tag and commits to origin? (Requires bypass branch protection)" "y"; then
        log_info "Aborted by user."
        log_info "To push manually, run from the worktree directory:"
        log_info "  cd ${WORKTREE_DIR}"
        log_info "  git push origin ${version}"
        log_info "  git push --set-upstream origin ${release_branch}"
        log_info ""
        log_info "To clean up the worktree afterwards:"
        log_info "  cd ${ORIGINAL_REPO_ROOT}"
        log_info "  git worktree remove ${WORKTREE_DIR}"
        # Disable cleanup trap since user wants to push manually.
        trap - EXIT
        WORKTREE_DIR=""
        exit 0
    fi

    log_info "Pushing tag and commits..."
    if [[ "$DRY_RUN" == "true" ]]; then
        log_dry_run "git push origin ${version}"
        log_dry_run "git push --set-upstream origin ${release_branch}"
    else
        git push origin "${version}"
        git push --set-upstream origin "${release_branch}"
    fi
    echo

    # Step 11: Create GitHub release.
    log_info "Creating GitHub release..."

    local latest_flag=""
    if [[ "$DRY_RUN" != "true" ]]; then
        if ! is_latest_release "$version"; then
            latest_flag="--latest=false"
            log_info "This is not the highest semantic version; using --latest=false"
        fi
    fi

    # Build gh release create command as an array for safe argument handling
    gh_args=(release create "${version}" --title "${version}" --generate-notes)
    if [[ -n "$previous_tag" ]]; then
        gh_args+=(--notes-start-tag "${previous_tag}")
    fi
    if [[ -n "$latest_flag" ]]; then
        gh_args+=("$latest_flag")
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_dry_run "gh ${gh_args[*]}"
    else
        gh "${gh_args[@]}"
    fi
    echo

    # Step 12: Post-release tasks.
    log_info "Release $version created successfully!"
    echo
    echo "=========================================="
    echo "Remaining Manual Tasks"
    echo "=========================================="
    echo "1. Update SCANNER_VERSION in the stackrox repo"
    echo "2. Manual staging DB fix if needed"
    echo "=========================================="
}

main "$@"
