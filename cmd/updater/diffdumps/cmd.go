package diffdumps

import (
	"archive/zip"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/facebookincubator/nvdtools/vulndb"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/nvdloader"
	"github.com/stackrox/scanner/pkg/vulndump"
)

func validateAndOpenDump(zipPath string) (*zip.Reader, error) {
	if filepath.Ext(zipPath) != ".zip" {
		return nil, errors.Errorf("invalid dump %q; expected zip file", zipPath)
	}
	zipFile, err := os.Open(zipPath)
	if err != nil {
		return nil, errors.Wrapf(err, "error opening zip path: %q", zipPath)
	}
	fi, err := zipFile.Stat()
	if err != nil {
		return nil, errors.Wrapf(err, "error stating file: %q", zipPath)
	}

	zipR, err := zip.NewReader(zipFile, fi.Size())
	if err != nil {
		return nil, errors.Wrap(err, "opening ZIP")
	}
	return zipR, nil
}

func validateAndGetManifest(zipR *zip.Reader) (*vulndump.Manifest, error) {
	manifest, err := vulndump.LoadManifestFromDump(zipR)
	if err != nil {
		return nil, err
	}
	if !manifest.Since.IsZero() {
		return nil, errors.New("invalid dump: only diff genesis dumps, NOT diff-ed dumps!")
	}
	return manifest, nil
}

func generateNVDDiff(outputDir string, baseLastModifiedTime time.Time, headF *zip.File) error {
	reader, err := headF.Open()
	if err != nil {
		return errors.Wrap(err, "opening file")
	}
	defer utils.IgnoreError(reader.Close)
	nvdDump, err := nvdloader.LoadJSONFileFromReader(reader)
	if err != nil {
		return errors.Wrap(err, "reading NVD dump")
	}
	// Mutate the dump in place.
	filtered := nvdDump.CVEItems[:0]
	for _, item := range nvdDump.CVEItems {
		modifiedDate, err := vulndb.ParseTime(item.LastModifiedDate)
		if err != nil {
			// Should basically never happen.
			return errors.Wrapf(err, "invalid item %+v; couldn't parse modifiedDate", item)
		}
		if modifiedDate.After(baseLastModifiedTime) {
			filtered = append(filtered, item)
		}
	}
	log.Infof("Diffed NVD file %s; after filtering, %d/%d vulns are in the diff", headF.Name, len(filtered), len(nvdDump.CVEItems))
	nvdDump.CVEItems = filtered

	outF, err := os.Create(filepath.Join(outputDir, filepath.Base(headF.Name)))
	if err != nil {
		return errors.Wrap(err, "creating output file")
	}
	defer utils.IgnoreError(outF.Close)

	if err := nvdloader.WriteJSONFileToWriter(nvdDump, outF); err != nil {
		return errors.Wrap(err, "writing filtered dump to writer")
	}
	return nil
}

func generateNVDDiffs(outputDir string, baseLastModifiedTime time.Time, headZipR *zip.Reader) error {
	nvdSubDir := filepath.Join(outputDir, vulndump.NVDDirName)
	if err := os.MkdirAll(nvdSubDir, 0755); err != nil {
		return errors.Wrap(err, "creating subdir for NVD")
	}

	for _, headF := range headZipR.File {
		name := headF.Name
		// Only look at JSON files in the nvd/ folder.
		if filepath.Dir(name) != vulndump.NVDDirName || filepath.Ext(name) != ".json" {
			continue
		}
		if err := generateNVDDiff(nvdSubDir, baseLastModifiedTime, headF); err != nil {
			return errors.Wrapf(err, "generating NVD diff for file %q", headF.Name)
		}
	}
	return nil
}

type clairVulnUniqueKey struct {
	name      string
	namespace string
}

func keyFromVuln(v *database.Vulnerability) clairVulnUniqueKey {
	return clairVulnUniqueKey{
		name:      v.Name,
		namespace: v.Namespace.Name,
	}
}

type stringPair struct {
	first  string
	second string
}

func lessThanLexicographically(pairs []stringPair) bool {
	for _, pair := range pairs {
		cmp := strings.Compare(pair.first, pair.second)
		if cmp != 0 {
			return cmp < 0
		}
	}
	return false
}

func sortFeatureVersionSlice(slice []database.FeatureVersion) {
	sort.Slice(slice, func(i, j int) bool {
		return lessThanLexicographically([]stringPair{
			{slice[i].Feature.Name, slice[j].Feature.Name},
			{slice[i].Feature.Namespace.Name, slice[j].Feature.Namespace.Name},
			{slice[i].Version, slice[j].Version},
		},
		)
	})
}

func vulnsAreEqual(v1, v2 database.Vulnerability) bool {
	sortFeatureVersionSlice(v1.FixedIn)
	sortFeatureVersionSlice(v2.FixedIn)
	return reflect.DeepEqual(v1, v2)
}

func generateOSVulnsDiff(outputDir string, baseZipR *zip.Reader, headZipR *zip.Reader) error {
	baseVulns, err := vulndump.LoadOSVulnsFromDump(baseZipR)
	if err != nil {
		return errors.Wrap(err, "loading OS vulns from base dump")
	}
	headVulns, err := vulndump.LoadOSVulnsFromDump(headZipR)
	if err != nil {
		return errors.Wrap(err, "loading OS vulns from head dump")
	}

	baseVulnsMap := make(map[clairVulnUniqueKey]database.Vulnerability, len(baseVulns))
	for _, vuln := range baseVulns {
		key := keyFromVuln(&vuln)
		if _, ok := baseVulnsMap[key]; ok {
			// Should really never happen, but being defensive.
			return errors.Errorf("UNEXPECTED: got multiple vulns for key: %v", key)
		}
		baseVulnsMap[key] = vuln
	}

	var filtered []database.Vulnerability
	for _, headVuln := range headVulns {
		key := keyFromVuln(&headVuln)
		matchingBaseVuln, found := baseVulnsMap[key]
		// If the vuln was in the base, and equal to what was in the base,
		// skip it. Else, add.
		if !(found && vulnsAreEqual(matchingBaseVuln, headVuln)) {
			filtered = append(filtered, headVuln)
		}
	}
	log.Infof("Diffed OS vulns; base had %d, head had %d, and the diff has %d", len(baseVulns), len(headVulns), len(filtered))
	if err := vulndump.WriteOSVulns(outputDir, filtered); err != nil {
		return err
	}
	return nil
}

func Command() *cobra.Command {
	c := &cobra.Command{
		Use: "diff-dumps",
	}

	var (
		baseDumpFile string
		headDumpFile string
		outFile      string
	)

	c.RunE = func(_ *cobra.Command, _ []string) error {
		baseZipR, err := validateAndOpenDump(baseDumpFile)
		if err != nil {
			return errors.Wrap(err, "loading base dump")
		}
		headZipR, err := validateAndOpenDump(headDumpFile)
		if err != nil {
			return errors.Wrap(err, "loading head dump")
		}
		baseManifest, err := validateAndGetManifest(baseZipR)
		if err != nil {
			return errors.Wrap(err, "loading manifest from base dump")
		}
		headManifest, err := validateAndGetManifest(headZipR)
		if err != nil {
			return errors.Wrap(err, "loading manifest from head dump")
		}

		// Intentionally return an error even in the equal case, they are only going to be equal if two dumps are literally
		// exactly the same, and that's probably a mistake by the invoker of the program.
		if !baseManifest.Until.Before(headManifest.Until) {
			return errors.Errorf("base manifest is at least as current (%s) as head manifest (%s). Wrong order of arguments?", baseManifest.Until, headManifest.Until)
		}
		log.Info("Validated dump files. Proceeding with the diffing...")

		stagingDir, err := ioutil.TempDir("", "vuln-dump-diff")
		if err != nil {
			return errors.Wrap(err, "creating temp dir for output")
		}
		defer func() {
			_ = os.RemoveAll(stagingDir)
		}()
		log.Info("Generating NVD diff...")
		if err := generateNVDDiffs(stagingDir, baseManifest.Until, headZipR); err != nil {
			return errors.Wrap(err, "creating NVD diff")
		}
		log.Info("Done generating NVD diff.")

		log.Info("Generating OS vulns diff...")
		if err := generateOSVulnsDiff(stagingDir, baseZipR, headZipR); err != nil {
			return errors.Wrap(err, "creating OS vulns diff")
		}
		log.Info("Generated OS vulns diff")

		err = vulndump.WriteManifestFile(stagingDir, vulndump.Manifest{
			Since: baseManifest.Until,
			Until: headManifest.Until,
		})
		if err != nil {
			return errors.Wrap(err, "writing manifest file")
		}

		log.Info("Zipping up the dump...")
		err = vulndump.WriteZip(stagingDir, outFile)
		if err != nil {
			return errors.Wrap(err, "writing final zip")
		}
		log.Info("All done!")
		return nil
	}

	c.Flags().StringVar(&baseDumpFile, "base-dump", "", "path to base dump")
	c.Flags().StringVar(&headDumpFile, "head-dump", "", `path to "head" (updated) dump`)
	c.Flags().StringVar(&outFile, "out-file", "", "path to write the diff-ed dump to")
	utils.Must(
		c.MarkFlagRequired("base-dump"),
		c.MarkFlagRequired("head-dump"),
		c.MarkFlagRequired("out-file"),
	)

	return c
}
