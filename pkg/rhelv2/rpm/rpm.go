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
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/featurens/osrelease"
	"github.com/stackrox/scanner/ext/featurens/redhatrelease"
	"github.com/stackrox/scanner/pkg/commonerr"
	"github.com/stackrox/scanner/pkg/features"
	"github.com/stackrox/scanner/pkg/metrics"
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

	contentManifests = `root/buildinfo/content_manifests`

	pkgFmt = `rpmv2`
)

var contentManifestPattern = regexp.MustCompile(`^root/buildinfo/content_manifests/.*\.json$`)

// rpmDatabaseDir is the directory where the RPM database is expected to be in
// the container filesystem.
var rpmDatabaseDir = "var/lib/rpm"

// rpmDatabaseFiles is a slice of all RPM database files for all known backends.
var rpmDatabaseFiles = []string{
	// bdb (rpm < 4.16)
	"Packages",
	// sqlite (rpm >= 4.16)
	"rpmdb.sqlite",
	"rpmdb.sqlite-shm",
	"rpmdb.sqlite-wal",
}

// AllRHELRequiredFiles lists all the names of the files required to identify RHEL-based releases.
var AllRHELRequiredFiles set.StringSet

func init() {
	AllRHELRequiredFiles.AddAll(RequiredFilenames()...)
	AllRHELRequiredFiles.AddAll(redhatrelease.RequiredFilenames...)
	AllRHELRequiredFiles.AddAll(osrelease.RequiredFilenames...)
}

// rpmDatabase represents an RPM database in the filesystem.
type rpmDatabase struct {
	// The path to the rpm database, can be used as --dbpath <dbPath> in rpm commands.
	dbPath string
}

// createRPMDatabaseFromImage creates an RPM database in a temporary directory
// from the RPM database found in the container image. All known RPM database
// backend is supported (i.e. bdb, sqlite). If no database is found in the image,
// returns nil.
func createRPMDatabaseFromImage(imageFiles tarutil.LayerFiles) (*rpmDatabase, error) {
	// Find all known RPM database files in the image archive.
	dbFiles := make(map[string]tarutil.FileData)
	for _, name := range rpmDatabaseFiles {
		data, exists := imageFiles.Get(path.Join(rpmDatabaseDir, name))
		if exists {
			dbFiles[name] = data
		}
	}
	if len(dbFiles) == 0 {
		// Not rpm database was found.
		return nil, nil
	}
	// Write the database files to the filesystem.
	dbDir, err := os.MkdirTemp("", "rpm")
	if err != nil {
		log.WithError(err).Error("could not create temporary folder for the rpm database")
		return nil, commonerr.ErrFilesystem
	}
	defer func() {
		// Remove temporary directory if returning on errors.
		if err != nil {
			_ = os.RemoveAll(dbDir)
		}
	}()
	for name, data := range dbFiles {
		path := filepath.Join(dbDir, name)
		err = os.WriteFile(path, data.Contents, 0700)
		if err != nil {
			log.WithError(err).Error("failed to create rpm database file")
			return nil, commonerr.ErrFilesystem
		}
	}
	return &rpmDatabase{
		dbPath: dbDir,
	}, nil
}

// delete removes all the RPM database files.
func (d *rpmDatabase) delete() error {
	return os.RemoveAll(d.dbPath)
}

// ListFeatures returns the features found from the given files.
// returns a slice of packages found via rpm          and a slice of CPEs found in
// /root/buildinfo/content_manifests.
func ListFeatures(files tarutil.LayerFiles) ([]*database.RHELv2Package, []string, error) {
	if features.ActiveVulnMgmt.Enabled() {
		return listFeatures(files, queryFmtActiveVulnMgmt)
	}
	return listFeatures(files, queryFmt)
}

func listFeatures(files tarutil.LayerFiles, queryFmt string) ([]*database.RHELv2Package, []string, error) {
	cpes, err := getCPEsUsingEmbeddedContentSets(files)
	if err != nil {
		return nil, nil, err
	}

	defer metrics.ObserveListFeaturesTime(pkgFmt, "all", time.Now())

	rpmDB, err := createRPMDatabaseFromImage(files)
	if err != nil {
		return nil, nil, err
	}
	if rpmDB == nil {
		return nil, cpes, nil
	}
	defer rpmDB.delete()

	defer metrics.ObserveListFeaturesTime(pkgFmt, "cli+parse", time.Now())

	cmd := exec.Command("rpm",
		`--dbpath`, rpmDB.dbPath,
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

func parsePackages(r io.Reader, files tarutil.LayerFiles) ([]*database.RHELv2Package, error) {
	var pkgs []*database.RHELv2Package

	p := &database.RHELv2Package{}
	// execToDeps and execToDeps ensures only unique executables or libraries are stored per package.
	execToDeps := make(database.StringToStringsMap)
	libToDeps := make(database.StringToStringsMap)
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
				if len(execToDeps) > 0 {
					p.ExecutableToDependencies = execToDeps
				}
				if len(libToDeps) > 0 {
					p.LibraryToDependencies = libToDeps
				}
				pkgs = append(pkgs, p)
			}

			// Start a new package definition and reset 'i'.
			p = &database.RHELv2Package{}
			execToDeps = make(database.StringToStringsMap)
			libToDeps = make(database.StringToStringsMap)
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
			// The first character is always "/", which is removed when inserted into the layer files.
			fileData, hasFile := files.Get(filename[1:])
			if hasFile {
				AddToDependencyMap(filename, fileData, execToDeps, libToDeps)
			}
		}
	}

	return pkgs, s.Err()
}

// AddToDependencyMap checks and adds files to executable and library dependency for RHEL package
func AddToDependencyMap(filename string, fileData tarutil.FileData, execToDeps, libToDeps database.StringToStringsMap) {
	// The first character is always "/", which is removed when inserted into the layer files.
	if fileData.Executable && !AllRHELRequiredFiles.Contains(filename[1:]) {
		deps := set.NewStringSet()
		if fileData.ELFMetadata != nil {
			deps.AddAll(fileData.ELFMetadata.ImportedLibraries...)
		}
		execToDeps[filename] = deps
	}
	if fileData.ELFMetadata != nil {
		for _, soname := range fileData.ELFMetadata.Sonames {
			deps, ok := libToDeps[soname]
			if !ok {
				deps = set.NewStringSet()
				libToDeps[soname] = deps
			}
			deps.AddAll(fileData.ELFMetadata.ImportedLibraries...)
		}
	}
}

func getCPEsUsingEmbeddedContentSets(files tarutil.LayerFiles) ([]string, error) {
	defer metrics.ObserveListFeaturesTime(pkgFmt, "cpes", time.Now())

	// Get CPEs using embedded content-set files.
	// The files are stored in /root/buildinfo/content_manifests/ and will need to
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

func getContentManifestFileContents(files tarutil.LayerFiles) []byte {
	for file, contents := range files.GetFilesMap() {
		if !contentManifestPattern.MatchString(file) {
			continue
		}

		// Return the first one found, as there should only be one per layer.
		return contents.Contents
	}

	return nil
}

// RequiredFilenames lists the files required to be present for analysis to be run.
func RequiredFilenames() []string {
	names := []string{contentManifests}
	for _, fn := range rpmDatabaseFiles {
		names = append(names, path.Join(rpmDatabaseDir, fn))
	}
	return names
}
