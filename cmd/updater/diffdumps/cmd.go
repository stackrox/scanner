package diffdumps

import (
	"archive/zip"
	"encoding/json"
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
	"github.com/stackrox/scanner/cmd/updater/common"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt"
	"github.com/stackrox/scanner/pkg/vulndump"
	"github.com/stackrox/scanner/pkg/vulnloader/nvdloader"
)

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

func generateNVDDiffs(outputDir string, baseLastModifiedTime time.Time, headZipR *zip.ReadCloser) error {
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

func vulnsAreEqual(v1, v2 *database.Vulnerability) bool {
	sortFeatureVersionSlice(v1.FixedIn)
	sortFeatureVersionSlice(v2.FixedIn)
	return reflect.DeepEqual(v1, v2)
}

func filterFixableCentOSVulns(vulns []*database.Vulnerability) []*database.Vulnerability {
	var filtered []*database.Vulnerability
	for _, vuln := range vulns {
		if !strings.HasPrefix(vuln.Namespace.Name, "centos") {
			filtered = append(filtered, vuln)
			continue
		}
		var newFixedIn []database.FeatureVersion
		for _, fixedIn := range vuln.FixedIn {
			if fixedIn.Version != versionfmt.MaxVersion {
				newFixedIn = append(newFixedIn, fixedIn)
			}
		}
		if len(newFixedIn) > 0 {
			vuln.FixedIn = newFixedIn
			filtered = append(filtered, vuln)
		}
	}
	return filtered
}

func generateOSVulnsDiff(outputDir string, baseZipR *zip.ReadCloser, baseManifest *vulndump.Manifest, headZipR *zip.ReadCloser, cfg config) error {
	baseVulns, err := vulndump.LoadOSVulnsFromDump(baseZipR)
	if err != nil {
		return errors.Wrap(err, "loading OS vulns from base dump")
	}
	headVulns, err := vulndump.LoadOSVulnsFromDump(headZipR)
	if err != nil {
		return errors.Wrap(err, "loading OS vulns from head dump")
	}

	baseVulnsMap := make(map[clairVulnUniqueKey]*database.Vulnerability, len(baseVulns))
	for i := range baseVulns {
		vuln := &baseVulns[i]
		key := keyFromVuln(vuln)
		if _, ok := baseVulnsMap[key]; ok {
			// Should really never happen, but being defensive.
			return errors.Errorf("UNEXPECTED: got multiple vulns for key: %v", key)
		}
		baseVulnsMap[key] = vuln
	}

	d := time.Date(2020, 9, 29, 0, 0, 0, 0, time.UTC)

	// This commit https://github.com/stackrox/scanner/commit/fe393b26f092d9b295820dc6283e4c3d784c872b
	// broke backwards compatibility between RHEL format and Central so we need to rewrite the Red Hat metadata
	// into the NVD key
	rewriteMetadata := baseManifest.Until.Before(d)
	if rewriteMetadata {
		log.Infof("Found base manifest: %+v to be before rhel cutoff", baseManifest)
	}

	var filtered []*database.Vulnerability
	for i := range headVulns {
		headVuln := &headVulns[i]
		// Rewrite base if needed
		if rewriteMetadata && strings.HasPrefix(headVuln.Namespace.Name, "centos") {
			if val, ok := headVuln.Metadata["Red Hat"]; ok {
				headVuln.Metadata["NVD"] = val
			}
			log.Infof("Rewriting vuln to include NVD data: %v", headVuln.Name)
		}

		key := keyFromVuln(headVuln)
		matchingBaseVuln, found := baseVulnsMap[key]
		// If the vuln was in the base, and equal to what was in the base,
		// skip it. Else, add.
		if !found || !vulnsAreEqual(matchingBaseVuln, headVuln) {
			filtered = append(filtered, headVuln)
		}
	}

	if cfg.SkipFixableCentOSVulns {
		countBefore := len(filtered)
		filtered = filterFixableCentOSVulns(filtered)
		log.Infof("Skipping fixable centOS vulns: filtered out %d", countBefore-len(filtered))
	}
	log.Infof("Diffed OS vulns; base had %d, head had %d, and the diff has %d", len(baseVulns), len(headVulns), len(filtered))
	if err := vulndump.WriteOSVulns(outputDir, filtered); err != nil {
		return err
	}
	return nil
}

type config struct {
	SkipFixableCentOSVulns bool `json:"skipFixableCentOSVulns"`
}

func Command() *cobra.Command {
	c := &cobra.Command{
		Use: "diff-dumps",
	}

	var (
		baseDumpFile      string
		headDumpFile      string
		outFile           string
		configStringified string
	)

	c.RunE = func(_ *cobra.Command, _ []string) error {
		var cfg config
		if configStringified != "" {
			if err := json.Unmarshal([]byte(configStringified), &cfg); err != nil {
				return errors.Wrap(err, "parsing passed config")
			}
		}
		baseZipR, baseManifest, err := common.OpenGenesisDumpAndExtractManifest(baseDumpFile)
		if err != nil {
			return errors.Wrap(err, "loading base dump")
		}
		defer utils.IgnoreError(baseZipR.Close)
		headZipR, headManifest, err := common.OpenGenesisDumpAndExtractManifest(headDumpFile)
		if err != nil {
			return errors.Wrap(err, "loading head dump")
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
		if err := generateOSVulnsDiff(stagingDir, baseZipR, baseManifest, headZipR, cfg); err != nil {
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
	c.Flags().StringVar(&configStringified, "config", "", "config for the given dump (should be serialized JSON)")
	utils.Must(
		c.MarkFlagRequired("base-dump"),
		c.MarkFlagRequired("head-dump"),
		c.MarkFlagRequired("out-file"),
	)

	return c
}
