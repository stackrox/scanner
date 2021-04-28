package diffdumps

import (
	"archive/zip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/mitchellh/hashstructure"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/repo2cpe"
	"github.com/stackrox/scanner/pkg/vulndump"
)

func generateRHELv2Diff(outputDir string, baseLastModifiedTime time.Time, baseF, headF *zip.File, rhelExists bool) error {
	reader, err := headF.Open()
	if err != nil {
		return errors.Wrap(err, "opening file")
	}
	defer utils.IgnoreError(reader.Close)

	var rhel vulndump.RHELv2
	if err := json.NewDecoder(reader).Decode(&rhel); err != nil {
		return errors.Wrap(err, "reading file")
	}

	// If the head file is not newer than the base dump, then skip.
	// Skip this check if the base dump does not even contain RHELv2 files.
	if rhelExists && !baseLastModifiedTime.Before(rhel.LastModified) {
		log.Infof("RHELv2 feed %q not updated since base dump", headF.Name)
		return nil
	}

	var baseRHEL vulndump.RHELv2
	if baseF != nil {
		reader, err := baseF.Open()
		if err != nil {
			return errors.Wrap(err, "opening base file")
		}
		defer utils.IgnoreError(reader.Close)

		if err := json.NewDecoder(reader).Decode(&baseRHEL); err != nil {
			return errors.Wrap(err, "reading base file")
		}
	}

	// If the head file is not newer than the base file, then skip.
	// Not exactly possible since the base file must be older than the base dump as a whole,
	// but doesn't hurt to sanity check.
	// Skip this check if the base dump does not even contain RHELv2 files.
	if rhelExists && !rhel.LastModified.After(baseRHEL.LastModified) {
		log.Infof("RHELv2 feed %q not updated since base file", headF.Name)
		return nil
	}

	baseVulnsMap := make(map[string]*database.RHELv2Vulnerability, len(baseRHEL.Vulns))
	for _, vuln := range baseRHEL.Vulns {
		if _, ok := baseVulnsMap[vuln.Name]; ok {
			// Should really never happen, but being defensive.
			return errors.Errorf("UNEXPECTED (base dump): got multiple vulns for key: %s", vuln.Name)
		}
		baseVulnsMap[vuln.Name] = vuln
	}

	// Keep track of all fixed CVEs so we know which unfixed CVEs have since been fixed.
	// We only want to display the relevant RHBA/RHEA/RHSA when a CVE is fixed.
	fixedCVEs := set.NewStringSet()
	for _, vuln := range rhel.Vulns {
		fixedCVEs.AddAll(vuln.SubCVEs...)
	}

	var filtered []*database.RHELv2Vulnerability
	var vulnsToDelete []string
	for _, headVuln := range rhel.Vulns {
		matchingBaseVuln, found := baseVulnsMap[headVuln.Name]
		// If the vuln was not in the base, add it.
		if !found {
			filtered = append(filtered, headVuln)
			continue
		}

		if fixedCVEs.Contains(matchingBaseVuln.Name) {
			// The base dump contains an unfixed CVE that has since been fixed.
			// Mark it for deletion.
			vulnsToDelete = append(vulnsToDelete, matchingBaseVuln.Name)
		}

		matchingHash, err := vulnHash(matchingBaseVuln)
		if err != nil {
			log.Warnf("Unable to hash existing vuln %s. Adding from head...", matchingBaseVuln.Name)
			filtered = append(filtered, headVuln)
			continue
		}

		headHash, err := vulnHash(headVuln)
		if err != nil {
			log.Warnf("Unable to hash new vuln %s. Skipping head vuln...", headVuln.Name)
			continue
		}

		// If the vuln is not equal to what was in the base, add it. Else, skip.
		if matchingHash != headHash {
			filtered = append(filtered, headVuln)
		}
	}

	log.Infof("Diffed RHELv2 file %s; after filtering, %d/%d vulns are in the diff and %d unfixed vulns have since been fixed", headF.Name, len(filtered), len(rhel.Vulns), len(vulnsToDelete))

	outF, err := os.Create(filepath.Join(outputDir, filepath.Base(headF.Name)))
	if err != nil {
		return errors.Wrap(err, "creating output file")
	}
	defer utils.IgnoreError(outF.Close)

	if err := json.NewEncoder(outF).Encode(&vulndump.RHELv2{
		LastModified:  rhel.LastModified,
		Vulns:         filtered,
		VulnsToDelete: vulnsToDelete,
	}); err != nil {
		return errors.Wrap(err, "writing filtered RHELv2 dump to writer")
	}

	return nil
}

func generateRHELv2VulnsDiff(outputDir string, baseLastModifiedTime time.Time, baseZipR, headZipR *zip.ReadCloser) error {
	rhelv2VulnsSubDir := filepath.Join(outputDir, vulndump.RHELv2DirName, vulndump.RHELv2VulnsSubDirName)
	if err := os.MkdirAll(rhelv2VulnsSubDir, 0755); err != nil {
		return errors.Wrap(err, "creating subdir for RHELv2")
	}

	vulnsDir := filepath.Join(vulndump.RHELv2DirName, vulndump.RHELv2VulnsSubDirName)
	baseFiles := make(map[string]*zip.File)
	for _, baseF := range baseZipR.File {
		name := baseF.Name
		if filepath.Dir(name) == vulnsDir && filepath.Ext(name) == ".json" {
			baseFiles[name] = baseF
		}
	}

	// Let's us know if the base dump had RHELv2 data.
	rhelExists := len(baseFiles) > 0

	repoToCPEFile := filepath.Join(vulndump.RHELv2DirName, repo2cpe.RHELv2CPERepoName)
	for _, headF := range headZipR.File {
		name := headF.Name

		// repo to cpe JSON
		if name == repoToCPEFile {
			if err := generateRHELv2RepoToCPE(filepath.Join(outputDir, repoToCPEFile), headF); err != nil {
				return errors.Wrapf(err, "generating %s", repo2cpe.RHELv2CPERepoName)
			}
		}

		// Only look at JSON files in the vulns/ folder.
		if filepath.Dir(name) != vulnsDir || filepath.Ext(name) != ".json" {
			continue
		}

		if err := generateRHELv2Diff(rhelv2VulnsSubDir, baseLastModifiedTime, baseFiles[name], headF, rhelExists); err != nil {
			return errors.Wrapf(err, "generating RHELv2 diff for file %q", headF.Name)
		}
	}

	return nil
}

func generateRHELv2RepoToCPE(fileName string, file *zip.File) error {
	reader, err := file.Open()
	if err != nil {
		return errors.Wrap(err, "opening file")
	}
	defer utils.IgnoreError(reader.Close)

	outF, err := os.Create(fileName)
	if err != nil {
		return errors.Wrap(err, "creating output file")
	}
	defer utils.IgnoreError(outF.Close)

	if _, err := io.Copy(outF, reader); err != nil {
		return errors.Wrap(err, "copying file contents")
	}

	return nil
}

// vulnHash creates a hash from the members of the passed-in Vulnerability.
func vulnHash(v *database.RHELv2Vulnerability) (uint64, error) {
	return hashstructure.Hash(v, nil)
}
