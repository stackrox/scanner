///////////////////////////////////////////////////
// Influenced by ClairCore under Apache 2.0 License
// https://github.com/quay/claircore
///////////////////////////////////////////////////

package rpm

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurens/osrelease"
	"github.com/stackrox/scanner/ext/featurens/redhatrelease"
	"github.com/stackrox/scanner/pkg/commonerr"
	"github.com/stackrox/scanner/pkg/features"
	"github.com/stackrox/scanner/pkg/repo2cpe"
	"github.com/stackrox/scanner/pkg/tarutil"
)

const (
	// This is the query format we're using to get data out of rpm.
	queryFmt = `%{name}\n` +
		`%{evr}\n` +
		`%{ARCH}\n` +
		`%{RPMTAG_MODULARITYLABEL}\n` +
		`.\n`
	queryFmtActiveVulnMgmt = `%{name}\n` +
		`%{evr}\n` +
		`%{ARCH}\n` +
		`%{RPMTAG_MODULARITYLABEL}\n` +
		`[%{FILENAMES}\n]` +
		`.\n`

	// Older versions of rpm do not have the `RPMTAG_MODULARITYLABEL` tag.
	// Ignore it for testing.
	queryFmtTest = `%{name}\n` +
		`%{evr}\n` +
		`%{ARCH}\n` +
		`.\n`
	queryFmtActiveVulnMgmtTest = `%{name}\n` +
		`%{evr}\n` +
		`%{ARCH}\n` +
		`[%{FILENAMES}\n]` +
		`.\n`

	dbPath           = `var/lib/rpm/Packages`
	contentManifests = `root/buildinfo/content_manifests`
)

var contentManifestPattern = regexp.MustCompile(`^root/buildinfo/content_manifests/.*\.json$`)

// AllRHELRequiredFiles lists all the names of the files required to identify RHEL-based releases.
var AllRHELRequiredFiles set.StringSet

func init() {
	AllRHELRequiredFiles.Add(dbPath)
	AllRHELRequiredFiles.AddAll(RequiredFilenames()...)
	AllRHELRequiredFiles.AddAll(redhatrelease.RequiredFilenames...)
	AllRHELRequiredFiles.AddAll(osrelease.RequiredFilenames...)
}

// ListFeatures returns the features found from the given files.
// returns a slice of packages found via rpm and a slice of CPEs found in
// /root/buildinfo/content_manifests.
func ListFeatures(files tarutil.FilesMap) ([]*database.RHELv2Package, []string, error) {
	if features.ActiveVulnMgmt.Enabled() {
		return listFeatures(files, queryFmtActiveVulnMgmt)
	}
	return listFeatures(files, queryFmt)
}

func listFeatures(files tarutil.FilesMap, queryFmt string) ([]*database.RHELv2Package, []string, error) {
	cpes, err := getCPEsUsingEmbeddedContentSets(files)
	if err != nil {
		return nil, nil, err
	}

	f, hasFile := files[dbPath]
	if !hasFile {
		return nil, cpes, nil
	}

	// Write the required "Packages" file to disk
	tmpDir, err := os.MkdirTemp("", "rpm")
	if err != nil {
		log.WithError(err).Error("could not create temporary folder for RPM detection")
		return nil, nil, commonerr.ErrFilesystem
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	err = os.WriteFile(tmpDir+"/Packages", f, 0700)
	if err != nil {
		log.WithError(err).Error("could not create temporary file for RPM detection")
		return nil, nil, commonerr.ErrFilesystem
	}

	cmd := exec.Command("rpm",
		`--dbpath`, tmpDir,
		`--query`, `--all`, `--queryformat`, queryFmt)
	r, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	defer utils.IgnoreError(r.Close)

	var errbuf bytes.Buffer
	cmd.Stderr = &errbuf

	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	pkgs, err := parsePackages(r, files)
	if err != nil {
		if errbuf.Len() != 0 {
			log.Warnf("Error executing RPM command: %s", errbuf.String())
		}
		return nil, nil, errors.Errorf("rpm: error reading rpm output: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		return nil, nil, err
	}

	return pkgs, cpes, nil
}

func parsePackages(r io.Reader, files tarutil.FilesMap) ([]*database.RHELv2Package, error) {
	var pkgs []*database.RHELv2Package

	p := &database.RHELv2Package{}
	// executablesSet ensures only unique executables are stored per package.
	executablesSet := set.NewStringSet()
	s := bufio.NewScanner(r)
	for i := 0; s.Scan(); i++ {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "(none)") {
			continue
		}
		if line == "." {
			// Reached package delimiter.

			// Ensure the current package is well-formed.
			// If it is, add it to the return slice.
			if p.Name != "" && p.Version != "" && p.Arch != "" {
				executables := make([]string, 0, executablesSet.Cardinality())
				for executable := range executablesSet {
					executables = append(executables, executable)
				}
				sort.Strings(executables)
				p.ProvidedExecutables = append(p.ProvidedExecutables, executables...)

				pkgs = append(pkgs, p)
			}

			// Start a new package definition and reset 'i'.
			p = &database.RHELv2Package{}
			executablesSet.Clear()
			i = -1
			continue
		}

		switch i {
		case 0:
			// This is not a real package. Skip it...
			if line == "gpg-pubkey" {
				continue
			}
			p.Name = line
		case 1:
			p.Version = line
		case 2:
			p.Arch = line
		case 3:
			moduleSplit := strings.Split(line, ":")
			if len(moduleSplit) < 2 {
				continue
			}
			moduleStream := fmt.Sprintf("%s:%s", moduleSplit[0], moduleSplit[1])
			p.Module = moduleStream
		default:
			// i >= 4 is reserved for provided filenames.

			// Rename to make it clear what the line represents.
			filename := line
			// The first character is always "/", which is removed when inserted into the files maps.
			// It is assumed if the listed file is tracked, it is an executable file.
			if _, exists := files[filename[1:]]; exists && !AllRHELRequiredFiles.Contains(filename[1:]) {
				p.ProvidedExecutables = append(p.ProvidedExecutables, filename)
			}
		}
	}

	return pkgs, s.Err()
}

func getCPEsUsingEmbeddedContentSets(files tarutil.FilesMap) ([]string, error) {
	// Get CPEs using embedded content-set files.
	// The files is be stored in /root/buildinfo/content_manifests/ and will need to
	// be translated using mapping file provided by Red Hat's PST team.
	contents := getContentManifestFileContents(files)
	if contents == nil {
		return nil, nil
	}

	var contentManifest database.ContentManifest
	if err := json.Unmarshal(contents, &contentManifest); err != nil {
		return nil, err
	}

	return repo2cpe.Singleton().Get(contentManifest.ContentSets)
}

func getContentManifestFileContents(files tarutil.FilesMap) []byte {
	for file, contents := range files {
		if !contentManifestPattern.MatchString(file) {
			continue
		}

		// Return the first one found, as there should only be one per layer.
		return contents
	}

	return nil
}

// RequiredFilenames lists the files required to be present for analysis to be run.
func RequiredFilenames() []string {
	return []string{dbPath, contentManifests}
}
