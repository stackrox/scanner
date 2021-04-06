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
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/commonerr"
	"github.com/stackrox/scanner/pkg/repo2cpe"
	"github.com/stackrox/scanner/pkg/tarutil"
)

// TODO: influenced by claircore

// This is the query format we're using to get data out of rpm.
const (
	queryFmt = `%{name}\n` +
		`%{evr}\n` +
		`%{RPMTAG_MODULARITYLABEL}\n` +
		`%{ARCH}\n` +
		`.\n`

	delim = "\n.\n"

	packages         = `var/lib/rpm/Packages`
	contentManifests = `root/buildinfo/content_manifests`
)

var (
	contentManifestPattern = regexp.MustCompile(`^root/buildinfo/content_manifests/.*\.json`)
)

// ListFeatures returns the features found from the given files.
// returns a slice of packages found via rpm and a slice of CPEs found in
// /root/buildinfo/content_manifests.
func ListFeatures(files tarutil.FilesMap) ([]*database.Package, []string, error) {
	cpes, err := getCPEsUsingEmbeddedContentSets(files)
	if err != nil {
		return nil, nil, err
	}

	f, hasFile := files[packages]
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

	var errbuf bytes.Buffer
	cmd.Stderr = &errbuf

	if err := cmd.Start(); err != nil {
		_ = r.Close()
		return nil, nil, err
	}

	var pkgs []*database.Package

	// Use a closure to defer the Close call.
	if err := func() error {
		defer utils.IgnoreError(r.Close)

		s := bufio.NewScanner(r)
		s.Split(querySplit)

		for s.Scan() {
			p, err := parsePackage(bytes.NewBuffer(s.Bytes()))
			if err != nil {
				return err
			}
			pkgs = append(pkgs, p)
		}

		return s.Err()
	}(); err != nil {
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

func querySplit(data []byte, atEOF bool) (advance int, token []byte, err error) {
	i := bytes.Index(data, []byte(delim))
	switch {
	case len(data) == 0 && atEOF:
		return 0, nil, io.EOF
	case i == -1 && atEOF:
		return 0, nil, errors.New("invalid format")
	case i == -1 && !atEOF:
		return 0, nil, nil
	default:
	}
	tok := data[:i]
	return len(tok) + len(delim), tok, nil
}

func parsePackage(buf *bytes.Buffer) (*database.Package, error) {
	var p database.Package
	var err error
	var line string

	for i := 0; ; i++ {
		// Look at the "queryFmt" string for the line numbers.
		line, err = buf.ReadString('\n')
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "(none)") {
			continue
		}
		if line == "" && err == nil {
			continue
		}
		switch i {
		case 0:
			p.Name = line
		case 1:
			p.Version = line
		case 2:
			moduleSplit := strings.Split(line, ":")
			if len(moduleSplit) < 2 {
				continue
			}
			moduleStream := fmt.Sprintf("%s:%s", moduleSplit[0], moduleSplit[1])
			p.Module = moduleStream
		case 3:
			p.Arch = line
		}
		switch err {
		case nil:
		case io.EOF:
			return &p, nil
		default:
			return nil, err
		}
	}
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

func RequiredFilenames() []string {
	return []string{packages, contentManifests}
}
