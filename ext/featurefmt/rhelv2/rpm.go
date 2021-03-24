package rhelv2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/tarutil"
)

// This is the query format we're using to get data out of rpm.
//
// There's XML output, but it's all jacked up.
const (
	queryFmt = `%{name}\n` +
	`%{evr}\n` +
	`%{sourcerpm}\n` +
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

func ListFeatures(files tarutil.FilesMap) ([]*database.Package, []string, error) {
	//CPEs, err := getCPEsUsingEmbeddedContentSets(files)
	//if err != nil {
	//	return nil, nil, err
	//}
	//
	//
	//
	//f, hasFile := files[packages]
	//if !hasFile {
	//	return nil, nil, nil
	//}
	//
	//// Write the required "Packages" file to disk
	//tmpDir, err := ioutil.TempDir(os.TempDir(), "rpm")
	//if err != nil {
	//	log.WithError(err).Error("could not create temporary folder for RPM detection")
	//	return nil, nil, commonerr.ErrFilesystem
	//}
	//defer func() {
	//	_ = os.RemoveAll(tmpDir)
	//}()
	//
	//err = ioutil.WriteFile(tmpDir+"/Packages", f, 0700)
	//if err != nil {
	//	log.WithError(err).Error("could not create temporary file for RPM detection")
	//	return nil, nil, commonerr.ErrFilesystem
	//}
	//
	//cmd := exec.Command("rpm",
	//	`--dbpath`, tmpDir,
	//	`--query`, `--all`, `--queryformat`, queryFmt)
	//r, err := cmd.StdoutPipe()
	//if err != nil {
	//	return nil, nil, err
	//}
	//
	//var errbuf bytes.Buffer
	//cmd.Stderr = &errbuf
	//
	//if err := cmd.Start(); err != nil {
	//	_ = r.Close()
	//	return nil, nil, err
	//}
	//
	//var pkgs []*database.Package
	//
	//// Use a closure to defer the Close call.
	//if err := func() error {
	//	defer utils.IgnoreError(r.Close)
	//
	//	srcs := make(map[string]*database.Package)
	//	s := bufio.NewScanner(r)
	//	s.Split(querySplit)
	//
	//	for s.Scan() {
	//		p, err := parsePackage(srcs, bytes.NewBuffer(s.Bytes()))
	//		if err != nil {
	//			return err
	//		}
	//		pkgs = append(pkgs, p)
	//	}
	//
	//	return s.Err()
	//}(); err != nil {
	//	if errbuf.Len() != 0 {
	//		log.Warnf("Error executing RPM command: %s", errbuf.String())
	//	}
	//	return nil, nil, errors.Errorf("rpm: error reading rpm output: %v", err)
	//}
	//
	//if err := cmd.Wait(); err != nil {
	//	return nil, nil, err
	//}
	//
	//// TODO:
	//return pkgs, nil, nil
	return nil, nil, nil
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

func parsePackage(src map[string]*database.Package, buf *bytes.Buffer) (*database.Package, error) {
	p := database.Package{
		Kind: database.BINARY,
	}
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
			line = strings.TrimSuffix(line, ".src.rpm")
			sp := strings.Split(line, "-")
			name := strings.Join(sp[:len(sp)-2], "-")
			if s, ok := src[name]; ok {
				p.Source = s
				break
			}
			p.Source = &database.Package{
				Name:    name,
				Version: sp[len(sp)-2] + "-" + sp[len(sp)-1],
				Kind:    database.SOURCE,
			}
			src[name] = p.Source
		case 3:
			moduleSplit := strings.Split(line, ":")
			if len(moduleSplit) < 2 {
				continue
			}
			moduleStream := fmt.Sprintf("%s:%s", moduleSplit[0], moduleSplit[1])
			p.Module = moduleStream
			if p.Source != nil {
				p.Source.Module = moduleStream
			}
		case 4:
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
	contents := findContentManifestFile(files)
	if contents == nil {
		return nil, nil
	}

	var contentManifest database.ContentManifest
	if err := json.Unmarshal(contents, &contentManifest); err != nil {
		return nil, err
	}



	// TODO: Read repository-to-cpe.json file upon update, and create a global in-memory object representing it.
	// Use that object to atomically get

	return nil, nil
}

func findContentManifestFile(files tarutil.FilesMap) []byte {
	for file, contents := range files {
		if !contentManifestPattern.MatchString(file) {
			continue
		}

		return contents
	}

	return nil
}

func RequiredFilenames() []string {
	return []string{packages, contentManifests}
}
