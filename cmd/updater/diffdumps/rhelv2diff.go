package diffdumps

import (
	"archive/zip"
	"bytes"
	"crypto/md5"
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/pkg/vulndump"
)

func generateRHELv2Diff(outputDir string, baseLastModifiedTime time.Time, baseF, headF *zip.File) error {
	reader, err := headF.Open()
	if err != nil {
		return errors.Wrap(err, "opening file")
	}
	defer utils.IgnoreError(reader.Close)

	var rhelv2 vulndump.RHELv2
	if err := json.NewDecoder(reader).Decode(&rhelv2); err != nil {
		return errors.Wrap(err, "reading file")
	}

	// If the head file is not newer than the base dump, then skip.
	if !baseLastModifiedTime.Before(rhelv2.LastModified) {
		log.Infof("RHELv2 feed %q not updated since base dump", headF.Name)
		return nil
	}

	var baseRHELv2 vulndump.RHELv2
	if baseF != nil {
		reader, err := baseF.Open()
		if err != nil {
			return errors.Wrap(err, "opening base file")
		}
		defer utils.IgnoreError(reader.Close)

		if err := json.NewDecoder(reader).Decode(&baseRHELv2); err != nil {
			return errors.Wrap(err, "reading base file")
		}
	}

	// If the head file is not newer than the base file, then skip.
	// Not exactly possible since the base file must be older than the base dump as a whole,
	// but doesn't hurt to sanity check.
	if !rhelv2.LastModified.After(baseRHELv2.LastModified) {
		log.Infof("RHELv2 feed %q not updated since base file", headF.Name)
		return nil
	}

	baseVulnsMap := make(map[string]*database.RHELv2Vulnerability, len(baseRHELv2.Vulns))
	for _, vuln := range baseRHELv2.Vulns {
		if _, ok := baseVulnsMap[vuln.Name]; ok {
			// Should really never happen, but being defensive.
			return errors.Errorf("UNEXPECTED: got multiple vulns for key: %s", vuln.Name)
		}
		baseVulnsMap[vuln.Name] = vuln
	}

	var filtered []*database.RHELv2Vulnerability
	for _, headVuln := range rhelv2.Vulns {
		matchingBaseVuln, found := baseVulnsMap[headVuln.Name]
		// If the vuln was not in the base, or not equal to what was in the base,
		// add it. Else, skip.
		if !found || !bytes.Equal(md5Vuln(matchingBaseVuln), md5Vuln(headVuln)) {
			filtered = append(filtered, headVuln)
		}
	}

	log.Infof("Diffed RHELv2 file %s; after filtering, %d/%d vulns are in the diff", headF.Name, len(filtered), len(baseRHELv2.Vulns))

	outF, err := os.Create(filepath.Join(outputDir, filepath.Base(headF.Name)))
	if err != nil {
		return errors.Wrap(err, "creating output file")
	}
	defer utils.IgnoreError(outF.Close)

	if err := json.NewEncoder(outF).Encode(&vulndump.RHELv2{
		LastModified: rhelv2.LastModified,
		Vulns:        filtered,
	}); err != nil {
		return errors.Wrap(err, "writing filtered RHELv2 dump to writer")
	}

	return nil
}

func generateRHELv2VulnsDiff(outputDir string, baseLastModifiedTime time.Time, baseZipR, headZipR *zip.ReadCloser) error {
	rhelv2SubDir := filepath.Join(outputDir, vulndump.RHELv2DirName)
	if err := os.MkdirAll(rhelv2SubDir, 0755); err != nil {
		return errors.Wrap(err, "creating subdir for RHEL v2")
	}

	baseFiles := make(map[string]*zip.File)
	for _, baseF := range baseZipR.File {
		name := baseF.Name
		if filepath.Dir(name) == vulndump.RHELv2DirName && filepath.Ext(name) == ".json" {
			baseFiles[name] = baseF
		}
	}

	for _, headF := range headZipR.File {
		name := headF.Name
		// Only look at JSON files in the nvd/ folder.
		if filepath.Dir(name) != vulndump.RHELv2DirName || filepath.Ext(name) != ".json" {
			continue
		}

		if err := generateRHELv2Diff(rhelv2SubDir, baseLastModifiedTime, baseFiles[name], headF); err != nil {
			return errors.Wrapf(err, "generating RHELv2 diff for file %q", headF.Name)
		}
	}

	return nil
}

// md5Vuln creates an md5 hash from the members of the passed-in Vulnerability,
// giving us a stable, context-free identifier for this revision of the
// Vulnerability.
func md5Vuln(v *database.RHELv2Vulnerability) []byte {
	var b bytes.Buffer
	b.WriteString(v.Name)
	b.WriteString(v.Description)
	b.WriteString(v.Issued.String())
	b.WriteString(v.Links)
	b.WriteString(v.Severity)
	if v.Package != nil {
		b.WriteString(v.Package.Name)
		b.WriteString(v.Package.Version)
		b.WriteString(v.Package.Module)
		b.WriteString(v.Package.Arch)
		b.WriteString(v.Package.Kind)
	}
	if v.Distribution != nil {
		b.WriteString(v.Distribution.DID)
		b.WriteString(v.Distribution.Name)
		b.WriteString(v.Distribution.Version)
		b.WriteString(v.Distribution.VersionID)
		b.WriteString(v.Distribution.CPE.BindFS())
		b.WriteString(v.Distribution.PrettyName)
	}
	b.WriteString(v.ArchOperation.String())
	b.WriteString(v.FixedInVersion)
	s := md5.Sum(b.Bytes())
	return s[:]
}
