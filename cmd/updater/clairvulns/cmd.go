package clairvulns

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/vulnmdsrc/nvd"
	"github.com/stackrox/scanner/ext/vulnsrc"
	"github.com/stackrox/scanner/pkg/nvdloader"
)

// An empty datastore makes all the updaters assume they're starting from scratch.
type emptyDataStore struct {
}

func (e emptyDataStore) GetKeyValue(key string) (string, error) {
	return "", nil
}

type wrappedVuln struct {
	LastUpdatedTime time.Time              `json:"lastUpdatedTime"`
	Vulnerability   database.Vulnerability `json:"vulnerability"`
}

func wrapVulns(startTime time.Time, fetchedVulns []database.Vulnerability) []wrappedVuln {
	wrappedVulns := make([]wrappedVuln, 0, len(fetchedVulns))
	for _, v := range fetchedVulns {
		wrappedVulns = append(wrappedVulns, wrappedVuln{
			LastUpdatedTime: startTime,
			Vulnerability:   v,
		})
	}
	return wrappedVulns
}

func Command() *cobra.Command {
	c := &cobra.Command{
		Use: "fetch clair vulnerabilities",
	}
	outFile := c.Flags().String("out-file", "", "path to write updated vulnerabilities to")
	utils.Must(c.MarkFlagRequired("out-file"))

	c.RunE = func(_ *cobra.Command, _ []string) error {
		startTime := time.Now()
		fetchedVulns, err := fetchVulns(emptyDataStore{})
		if err != nil {
			return err
		}
		log.Infof("Finished fetching vulns (total: %d)", len(fetchedVulns))
		f, err := os.Create(*outFile)
		if err != nil {
			return err
		}
		if err := json.NewEncoder(f).Encode(wrapVulns(startTime, fetchedVulns)); err != nil {
			return err
		}
		return nil
	}

	return c
}

// fetch get data from the registered fetchers, in parallel.
func fetchVulns(datastore vulnsrc.DataStore) (vulns []database.Vulnerability, err error) {
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
	vulnsWithMetadata, err := addMetadata(vulns)
	if err != nil {
		return nil, errors.Wrap(err, "adding metadata to vulns")
	}
	return vulnsWithMetadata, nil
}

// Add metadata to the specified vulnerabilities using the NVD metadata fetcher.
func addMetadata(vulnerabilities []database.Vulnerability) ([]database.Vulnerability, error) {
	log.Info("adding metadata to vulnerabilities")

	dumpDir, err := ioutil.TempDir("", "nvd-dump")
	if err != nil {
		return nil, errors.Wrap(err, "creating temp dir")
	}
	defer func() {
		_ = os.RemoveAll(dumpDir)
	}()

	if err := nvdloader.DownloadFeedsToPath(dumpDir); err != nil {
		return nil, errors.Wrap(err, "downloading NVD feeds")
	}

	nvdAppender := nvd.SingletonAppender()
	if err := nvdAppender.BuildCache(dumpDir); err != nil {
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
