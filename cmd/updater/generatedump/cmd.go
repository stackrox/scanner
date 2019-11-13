package generatedump

import (
	"compress/gzip"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mholt/archiver"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/vulnmdsrc/nvd"
	"github.com/stackrox/scanner/ext/vulnsrc"
	"github.com/stackrox/scanner/pkg/nvdloader"
	"github.com/stackrox/scanner/pkg/vulndump"
)

// An empty datastore makes all the updaters assume they're starting from scratch.
type emptyDataStore struct {
}

func (e emptyDataStore) GetKeyValue(key string) (string, error) {
	return "", nil
}

func wrapVulns(startTime time.Time, fetchedVulns []database.Vulnerability) []vulndump.WrappedVulnerability {
	wrappedVulns := make([]vulndump.WrappedVulnerability, 0, len(fetchedVulns))
	for _, v := range fetchedVulns {
		wrappedVulns = append(wrappedVulns, vulndump.WrappedVulnerability{
			LastUpdatedTime: startTime,
			Vulnerability:   v,
		})
	}
	return wrappedVulns
}

func Command() *cobra.Command {
	c := &cobra.Command{
		Use: "generate-dump",
	}
	outFile := c.Flags().String("out-file", "./dump.tar.gz", "file to write the dump to")

	c.RunE = func(_ *cobra.Command, _ []string) error {
		if !strings.HasSuffix(*outFile, ".tar.gz") {
			return errors.Errorf("invalid outfile %q; must end in .tar.gz", *outFile)
		}
		startTime := time.Now()

		dumpDir, err := ioutil.TempDir("", "vuln-updater")
		if err != nil {
			return errors.Wrap(err, "failed to create temp dir")
		}
		log.Infof("Writing to dump dir %q", dumpDir)
		defer func() {
			_ = os.RemoveAll(dumpDir)
		}()
		nvdSubDir := filepath.Join(dumpDir, vulndump.NVDSubDirName)
		if err := os.MkdirAll(nvdSubDir, 0755); err != nil {
			return errors.Wrap(err, "creating subdir for NVD")
		}

		log.Info("Downloading NVD...")
		if err := nvdloader.DownloadFeedsToPath(nvdSubDir); err != nil {
			return errors.Wrap(err, "downloading NVD")
		}
		log.Info("Fetching vulns...")
		fetchedVulns, err := fetchVulns(emptyDataStore{}, nvdSubDir)
		if err != nil {
			return errors.Wrap(err, "fetching vulns")
		}
		log.Infof("Finished fetching vulns (total: %d)", len(fetchedVulns))
		log.Info("Writing JSON file for updated vulns...")
		f, err := os.Create(filepath.Join(dumpDir, vulndump.FeedVulnsFileName))
		if err != nil {
			return errors.Wrap(err, "creating JSON file for updated vulns")
		}
		if err := json.NewEncoder(f).Encode(wrapVulns(startTime, fetchedVulns)); err != nil {
			return errors.Wrap(err, "writing JSON for vulns to file")
		}
		log.Info("Writing TIMESTAMP file...")
		marshaledStartTime, err := startTime.MarshalText()
		utils.Must(err) // Never happens.
		if err := ioutil.WriteFile(filepath.Join(dumpDir, vulndump.TimestampFileName), marshaledStartTime, 0644); err != nil {
			return errors.Wrap(err, "writing timestamp file")
		}

		log.Info("Creating a tar archive...")
		tarArchiver := archiver.NewTarGz()
		tarArchiver.CompressionLevel = gzip.BestCompression
		if err := tarArchiver.Archive([]string{
			filepath.Join(dumpDir, vulndump.TimestampFileName),
			filepath.Join(dumpDir, vulndump.NVDSubDirName),
			filepath.Join(dumpDir, vulndump.FeedVulnsFileName),
		}, *outFile); err != nil {
			return errors.Wrap(err, "writing out tar")
		}
		return nil
	}

	return c
}

// fetch get data from the registered fetchers, in parallel.
func fetchVulns(datastore vulnsrc.DataStore, nvdDumpDir string) (vulns []database.Vulnerability, err error) {
	errSig := concurrency.NewErrorSignal()

	// Fetch updates in parallel.
	log.Info("fetching vulnerability updates")
	responseC := make(chan *vulnsrc.UpdateResponse)
	for n, u := range vulnsrc.Updaters() {
		go func(name string, u vulnsrc.Updater) {
			response, err := u.Update(datastore)
			if err != nil {
				log.WithError(err).WithField("updater name", name).Error("an error occurred when fetching update")
				errSig.SignalWithError(err)
				return
			}

			responseC <- &response
			log.WithField("updater name", name).Info("finished fetching")
		}(n, u)
	}

	// Collect results of updates.
	for i := 0; i < len(vulnsrc.Updaters()); i++ {
		select {
		case resp := <-responseC:
			vulns = append(vulns, doVulnerabilitiesNamespacing(resp.Vulnerabilities)...)
			for _, note := range resp.Notes {
				log.WithField("note", note).Warn("There was a warning when running the updaters")
			}
		case <-errSig.Done():
			return nil, errSig.Err()
		}
	}

	close(responseC)
	vulnsWithMetadata, err := addMetadata(vulns, nvdDumpDir)
	if err != nil {
		return nil, errors.Wrap(err, "adding metadata to vulns")
	}
	return vulnsWithMetadata, nil
}

// Add metadata to the specified vulnerabilities using the NVD metadata fetcher.
func addMetadata(vulnerabilities []database.Vulnerability, nvdDumpDir string) ([]database.Vulnerability, error) {
	log.Info("adding metadata to vulnerabilities")

	nvdAppender := nvd.SingletonAppender()
	if err := nvdAppender.BuildCache(nvdDumpDir); err != nil {
		return nil, errors.Wrap(err, "failed to build cache from the NVD feed dump")
	}
	defer nvdAppender.PurgeCache()
	for i := range vulnerabilities {
		vuln := &vulnerabilities[i]
		if err := nvdAppender.Append(vuln.Name, vuln.SubCVEs, appendFuncForVuln(vuln)); err != nil {
			return nil, errors.Wrapf(err, "Failed to append metadata for vuln %s", vuln.Name)
		}
	}

	return vulnerabilities, nil
}

func appendFuncForVuln(v *database.Vulnerability) nvd.AppendFunc {
	return func(metadataKey string, enricher nvd.MetadataEnricher, severity database.Severity) {
		// If necessary, initialize the metadata map for the vulnerability.
		if v.Metadata == nil {
			v.Metadata = make(map[string]interface{})
		}

		// Append the metadata.
		v.Metadata[metadataKey] = enricher.Metadata()
		if v.Description == "" {
			v.Description = enricher.Summary()
		}

		// If necessary, provide a severity for the vulnerability.
		if v.Severity == database.UnknownSeverity {
			v.Severity = severity
		}
	}
}

// doVulnerabilitiesNamespacing takes Vulnerabilities that don't have a
// Namespace and split them into multiple vulnerabilities that have a Namespace
// and only contains the FixedIn FeatureVersions corresponding to their
// Namespace.
//
// It helps simplifying the fetchers that share the same metadata about a
// Vulnerability regardless of their actual namespace (ie. same vulnerability
// information for every version of a distro).
func doVulnerabilitiesNamespacing(vulnerabilities []database.Vulnerability) []database.Vulnerability {
	vulnerabilitiesMap := make(map[string]*database.Vulnerability)

	for _, v := range vulnerabilities {
		featureVersions := v.FixedIn
		v.FixedIn = []database.FeatureVersion{}

		for _, fv := range featureVersions {
			index := fv.Feature.Namespace.Name + ":" + v.Name

			if vulnerability, ok := vulnerabilitiesMap[index]; !ok {
				newVulnerability := v
				newVulnerability.Namespace = fv.Feature.Namespace
				newVulnerability.FixedIn = []database.FeatureVersion{fv}

				vulnerabilitiesMap[index] = &newVulnerability
			} else {
				vulnerability.FixedIn = append(vulnerability.FixedIn, fv)
			}
		}
	}

	// Convert map into a slice.
	var response []database.Vulnerability
	for _, vulnerability := range vulnerabilitiesMap {
		response = append(response, *vulnerability)
	}

	return response
}
