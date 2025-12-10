---
description: Create a patch release for scanner
allowed-tools: Bash, Read, Write, Edit, Glob, Grep, TodoWrite
argument-hint: <RELEASE> [PATCH_NUMBER]
---

# Patch Release Process

You are creating a patch release for scanner. The user has provided:
- RELEASE: $1 (e.g., 2.36)
- PATCH_NUMBER: $2 (optional - will auto-detect if not provided)

## Prerequisites

Before proceeding, verify:
1. The user's GitHub account must have "bypass branch protection" permissions on release branches.
2. The release branch `release-$1` must exist.

## Steps to Execute

Execute each step in order, documenting progress.

### Step 1: Determine the patch number

If PATCH_NUMBER ($2) was not provided, auto-detect the next patch number:
```bash
git fetch origin --tags
git tag --list "$1.*" | grep -E "^$1\.[0-9]+$" | sort -V | tail -1
```
Extract the patch number from the latest tag and increment by 1. For example, if the latest tag is `2.36.6`, the next patch number is `7`.

Set the variables:
- RELEASE = $1
- PATCH_NUMBER = (provided value or auto-detected next number)
- Full version = ${RELEASE}.${PATCH_NUMBER}

Create a release log at `/tmp/scanner-${RELEASE}.${PATCH_NUMBER}-release.md` as you go.

### Step 2: Verify branch state
```bash
git checkout release-${RELEASE}
git pull origin release-${RELEASE}
```
Ensure the branch is up-to-date with origin.

### Step 3: Check if release is necessary

**Check if HEAD is already a release commit:**
```bash
git log -1 --format='%s'
```
If the latest commit message matches the pattern `Release X.Y.Z`, then HEAD is already a release commit. In this case:
- Inform the user that the latest commit is already a release commit
- Show the commit message
- Ask the user what they want to do:
  - Abort (no new release needed)
  - Proceed anyway (create another release commit on top)

**Check if the patch number is sequential:**
Compare the auto-detected next patch number with the calculated expected next number.
- If the user provided a PATCH_NUMBER that is not the next sequential number (e.g., requesting 2.36.10 when 2.36.7 is the latest), warn the user:
  - Show the latest existing tag
  - Show the expected next patch number
  - Show the requested patch number
  - Ask the user what to do:
    - Use the expected next patch number instead
    - Proceed with the requested (non-sequential) patch number
    - Abort

### Step 4: Review commits since last tag
```bash
git log <previous-tag>..HEAD --oneline
```
Show the user what commits will be included in this release.

If there are no new commits since the last tag (other than possibly a release commit), warn the user that this release would contain no meaningful changes.

### Step 5: Confirm version with user
Display the determined version to the user and ask for confirmation before proceeding:
- Show RELEASE and PATCH_NUMBER values
- Show the full version that will be created
- Summarize the commits that will be included
- Ask user to confirm or provide a different patch number

### Step 6: Ask about cherry-picks
Ask the user if they need to cherry-pick any additional commits before proceeding.

### Step 7: Create release commit and tag
```bash
git commit --allow-empty -m "Release ${RELEASE}.${PATCH_NUMBER}"
git tag --no-sign ${RELEASE}.${PATCH_NUMBER}
```

### Step 8: Sanity checks
```bash
git tag --contains
git log --oneline -5
```
Verify:
- The tag is on the current commit
- The commit log shows expected commits

### Step 9: Push tag and commits
```bash
git push origin ${RELEASE}.${PATCH_NUMBER}
git push --set-upstream origin release-${RELEASE}
```
Note: This requires "bypass branch protection" permission. The push will bypass PR and status check requirements.

### Step 10: Create GitHub Release
First, determine if this should be marked as "Latest":
```bash
gh release list --limit 10
```

If a higher semantic version exists (e.g., 2.38.x when releasing 2.36.x), use `--latest=false`:
```bash
# If NOT the latest semantic version:
gh release create ${RELEASE}.${PATCH_NUMBER} --title "${RELEASE}.${PATCH_NUMBER}" --notes-start-tag <previous-tag> --generate-notes --latest=false

# If IS the latest semantic version:
gh release create ${RELEASE}.${PATCH_NUMBER} --title "${RELEASE}.${PATCH_NUMBER}" --notes-start-tag <previous-tag> --generate-notes
```

### Step 11: Post-release tasks
Inform the user of remaining manual tasks:
- Update SCANNER_VERSION in the stackrox repo
- Manual staging DB fix if needed

## Documentation

Update the release log at `/tmp/scanner-$1.$2-release.md` with the status of each step as you complete it.
