package diffdumps

import (
	"archive/zip"
	"encoding/json"
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
	"github.com/stackrox/k8s-cves/pkg/validation"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/cmd/updater/common"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt"
	"github.com/stackrox/scanner/ext/versionfmt/dpkg"
	"github.com/stackrox/scanner/ext/vulnsrc/ubuntu"
	"github.com/stackrox/scanner/pkg/vulndump"
	"github.com/stackrox/scanner/pkg/vulnloader/k8sloader"
	"github.com/stackrox/scanner/pkg/vulnloader/nvdloader"
	namespaces "github.com/stackrox/scanner/pkg/wellknownnamespaces"
)

func generateK8sDiff(outputDir string, baseF, headF *zip.File) error {
	reader, err := headF.Open()
	if err != nil {
		return errors.Wrap(err, "opening file")
	}
	defer utils.IgnoreError(reader.Close)
	k8sDump, err := k8sloader.LoadYAMLFileFromReader(reader)
	if err != nil {
		return errors.Wrap(err, "reading Kubernetes dump")
	}

	var baseK8sDump *validation.CVESchema
	if baseF != nil {
		reader, err := baseF.Open()
		if err != nil {
			return errors.Wrap(err, "opening file")
		}
		defer utils.IgnoreError(reader.Close)
		baseK8sDump, err = k8sloader.LoadYAMLFileFromReader(reader)
		if err != nil {
			return errors.Wrap(err, "reading base Kubernetes dump")
		}
	}

	var k8sDiff validation.CVESchema
	if !reflect.DeepEqual(baseK8sDump, k8sDump) {
		log.Infof("Kubernetes CVE file %q is in the diff", headF.Name)
		k8sDiff = *k8sDump
	}

	outF, err := os.Create(filepath.Join(outputDir, filepath.Base(headF.Name)))
	if err != nil {
		return errors.Wrap(err, "creating output file")
	}
	defer utils.IgnoreError(outF.Close)

	if err := k8sloader.WriteYAMLFileToWriter(&k8sDiff, outF); err != nil {
		return errors.Wrap(err, "writing dump to writer")
	}
	return nil
}

func generateK8sDiffs(outputDir string, baseZipR *zip.ReadCloser, headZipR *zip.ReadCloser) error {
	k8sSubDir := filepath.Join(outputDir, vulndump.K8sDirName)
	if err := os.MkdirAll(k8sSubDir, 0755); err != nil {
		return errors.Wrap(err, "creating subdir for Kubernetes")
	}

	baseFiles := make(map[string]*zip.File)
	for _, baseF := range baseZipR.File {
		name := baseF.Name

		if strings.Contains(name, "../") {
			log.Warnf("Illegal file name in ZIP: %s", name)
			continue
		}

		if filepath.Dir(name) == vulndump.K8sDirName && filepath.Ext(name) == ".yaml" {
			baseFiles[name] = baseF
		}
	}

	for _, headF := range headZipR.File {
		name := headF.Name

		// Protect from "zip slip".
		if strings.Contains(name, "../") {
			log.Warnf("Illegal file name in ZIP: %s", name)
			continue
		}

		// Only look at YAML files in the k8s/ folder.
		if filepath.Dir(name) != vulndump.K8sDirName || filepath.Ext(name) != ".yaml" {
			continue
		}
		if err := generateK8sDiff(k8sSubDir, baseFiles[name], headF); err != nil {
			return errors.Wrapf(err, "generating Kubernetes diff for file %q", headF.Name)
		}
	}
	return nil
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

func generateNVDDiffs(outputDir string, baseLastModifiedTime time.Time, headZipR *zip.ReadCloser) error {
	nvdSubDir := filepath.Join(outputDir, vulndump.NVDDirName)
	if err := os.MkdirAll(nvdSubDir, 0755); err != nil {
		return errors.Wrap(err, "creating subdir for NVD")
	}

	for _, headF := range headZipR.File {
		name := headF.Name

		// Protect from "zip slip".
		if strings.Contains(name, "../") {
			log.Warnf("Illegal file name in ZIP: %s", name)
			continue
		}

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

func vulnsAreEqual(v1, v2 database.Vulnerability, skipSeverityComparison bool) bool {
	sortFeatureVersionSlice(v1.FixedIn)
	sortFeatureVersionSlice(v2.FixedIn)

	if skipSeverityComparison {
		// It is fine to set this to unknown w/o side effects because the vulns are passed by value and not reference
		v1.Severity = database.UnknownSeverity
		v2.Severity = database.UnknownSeverity
	}
	return reflect.DeepEqual(v1, v2)
}

func filterUbuntuLinuxKernelFeatures(vuln *database.Vulnerability) {
	if !strings.HasPrefix(vuln.Namespace.Name, "ubuntu") {
		return
	}
	var newFixedIn []database.FeatureVersion
	for _, fixedIn := range vuln.FixedIn {
		if strings.HasPrefix(fixedIn.Feature.Name, "linux") {
			continue
		}
		newFixedIn = append(newFixedIn, fixedIn)
	}
	vuln.FixedIn = newFixedIn
}

func filterFixableCentOSVulns(vulns []database.Vulnerability) []database.Vulnerability {
	var filtered []database.Vulnerability
	for _, vuln := range vulns {
		if !namespaces.IsCentOSNamespace(vuln.Namespace.Name) {
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

func updateUbuntuLink(cfg config, vuln *database.Vulnerability) {
	if cfg.UseLegacyUbuntuCVEURLPrefix && namespaces.IsUbuntuNamespace(vuln.Namespace.Name) {
		vuln.Link = ubuntu.LegacyCVEURLPrefix + vuln.Link[len(ubuntu.CVEURLPrefix):]
	}
}

func generateOSVulnsDiff(outputDir string, baseZipR, headZipR *zip.ReadCloser, cfg config) error {
	baseVulns, err := vulndump.LoadOSVulnsFromDump(baseZipR)
	if err != nil {
		return errors.Wrap(err, "loading OS vulns from base dump")
	}
	headVulns, err := vulndump.LoadOSVulnsFromDump(headZipR)
	if err != nil {
		return errors.Wrap(err, "loading OS vulns from head dump")
	}

	baseVulnsMap := make(map[clairVulnUniqueKey]database.Vulnerability, len(baseVulns))
	for i := range baseVulns {
		// This removes the possibility of memory aliasing.
		vuln := baseVulns[i]
		key := keyFromVuln(&vuln)
		if _, ok := baseVulnsMap[key]; ok {
			// Should really never happen, but being defensive.
			return errors.Errorf("UNEXPECTED: got multiple vulns for key: %v", key)
		}
		baseVulnsMap[key] = vuln
	}

	var filtered []database.Vulnerability
	var linuxKernelVulnsFiltered int
	for i := range headVulns {
		// This removes the possibility of memory aliasing.
		headVuln := headVulns[i]
		if cfg.SkipUbuntuLinuxKernelVulns {
			filterUbuntuLinuxKernelFeatures(&headVuln)
			if len(headVuln.FixedIn) == 0 {
				linuxKernelVulnsFiltered++
				continue
			}
		}

		if cfg.UseDPKGParserForAlpine && namespaces.IsAlpineNamespace(headVuln.Namespace.Name) {
			headVuln.Namespace.VersionFormat = dpkg.ParserName

			for i := range headVuln.FixedIn {
				headVuln.FixedIn[i].Feature.Namespace.VersionFormat = dpkg.ParserName
			}
		}

		updateUbuntuLink(cfg, &headVuln)

		key := keyFromVuln(&headVuln)
		matchingBaseVuln, found := baseVulnsMap[key]
		// If the vuln was in the base, and equal to what was in the base,
		// skip it. Else, add.
		if !(found && vulnsAreEqual(matchingBaseVuln, headVuln, cfg.SkipSeverityComparison)) {
			filtered = append(filtered, headVuln)
		}
	}
	if cfg.SkipUbuntuLinuxKernelVulns {
		log.Infof("Skipped %d Ubuntu linux kernel vulns", linuxKernelVulnsFiltered)
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
	SkipFixableCentOSVulns     bool `json:"skipFixableCentOSVulns"`
	IgnoreKubernetesVulns      bool `json:"ignoreKubernetesVulns"`
	SkipUbuntuLinuxKernelVulns bool `json:"skipUbuntuLinuxKernelVulns"`
	SkipSeverityComparison     bool `json:"skipSeverityComparison"`
	SkipRHELv2Vulns            bool `json:"skipRHELv2Vulns"`
	UseDPKGParserForAlpine     bool `json:"useDPKGParserForAlpine"`
	// SkipRHELv2TitleComparison needed only be set for one specific release.
	SkipRHELv2TitleComparison   bool `json:"skipRHELv2TitleComparison"`
	KeepUnusedRHELv2CPEs        bool `json:"keepUnusedRHELv2CPEs"`
	UseLegacyUbuntuCVEURLPrefix bool `json:"useLegacyUbuntuCVEURLPrefix"`
}

// Command defines the diff-dumps command.
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

		stagingDir, err := os.MkdirTemp("", "vuln-dump-diff")
		if err != nil {
			return errors.Wrap(err, "creating temp dir for output")
		}
		defer func() {
			_ = os.RemoveAll(stagingDir)
		}()

		if cfg.IgnoreKubernetesVulns {
			log.Info("Skipping Kubernetes diff")
		} else {
			log.Info("Generating Kubernetes diff...")
			if err := generateK8sDiffs(stagingDir, baseZipR, headZipR); err != nil {
				return errors.Wrap(err, "creating Kubernetes diff")
			}
			log.Info("Done generating Kubernetes diff")
		}

		log.Info("Generating NVD diff...")
		if err := generateNVDDiffs(stagingDir, baseManifest.Until, headZipR); err != nil {
			return errors.Wrap(err, "creating NVD diff")
		}
		log.Info("Done generating NVD diff")

		log.Info("Generating OS vulns diff...")
		if err := generateOSVulnsDiff(stagingDir, baseZipR, headZipR, cfg); err != nil {
			return errors.Wrap(err, "creating OS vulns diff")
		}
		log.Info("Generated OS vulns diff")

		if cfg.SkipRHELv2Vulns {
			log.Info("Skipping RHELv2 diff")
		} else {
			log.Info("Generating RHELv2 vulns diff")
			if err := generateRHELv2VulnsDiff(cfg, stagingDir, baseManifest.Until, baseZipR, headZipR); err != nil {
				return errors.Wrap(err, "creating RHELv2 vulns diff")
			}
			log.Info("Generated RHELv2 vulns diff")
		}

		err = vulndump.WriteManifestFile(stagingDir, vulndump.Manifest{
			Since: baseManifest.Until,
			Until: headManifest.Until,
		})
		if err != nil {
			return errors.Wrap(err, "writing manifest file")
		}

		log.Info("Zipping up the dump...")
		err = vulndump.WriteZip(stagingDir, outFile, cfg.IgnoreKubernetesVulns, cfg.SkipRHELv2Vulns)
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
