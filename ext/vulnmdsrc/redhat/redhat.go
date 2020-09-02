package redhat

import (
	"bufio"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/ext/vulnmdsrc"
	"github.com/stackrox/scanner/pkg/commonerr"
)

const (
	appenderName string = "Red Hat"
)

type appender struct {
	metadata map[string]*metadataEnricher
}

type metadataEnricher struct {
	metadata *vulnmdsrc.Metadata
	summary  string
}

func (m *metadataEnricher) Metadata() interface{} {
	return m.metadata
}

func (m *metadataEnricher) Summary() string {
	return m.summary
}

func newMetadataEnricher(redhat *redhatEntry) *metadataEnricher {
	return &metadataEnricher{
		metadata: redhat.Metadata(),
		summary:  redhat.Summary(),
	}
}

func (a *appender) BuildCache(dumpDir string) error {
	a.metadata = make(map[string]*metadataEnricher)

	fileInfos, err := ioutil.ReadDir(dumpDir)
	if err != nil {
		return errors.Wrap(err, "failed to read dir")
	}

	for _, fileInfo := range fileInfos {
		fileName := fileInfo.Name()
		if filepath.Ext(fileName) != ".json" {
			continue
		}
		f, err := os.Open(filepath.Join(dumpDir, fileName))
		if err != nil {
			return errors.Wrapf(err, "could not open Red Hat data file %s", fileName)
		}

		if err := a.parseDataFeed(bufio.NewReader(f)); err != nil {
			return errors.Wrapf(err, "could not parse Red Hat data file %s", fileName)
		}
		_ = f.Close()
	}
	log.Infof("Obtained metadata for %d vulns", len(a.metadata))

	return nil
}

func (a *appender) parseDataFeed(r io.Reader) error {
	var redhat redhat
	if err := json.NewDecoder(r).Decode(&redhat); err != nil {
		return commonerr.ErrCouldNotParse
	}

	for _, redhatEntry := range redhat.Entries {
		// Create metadata entry.
		enricher := newMetadataEnricher(&redhatEntry)
		if enricher.metadata != nil {
			a.metadata[redhatEntry.Name()] = enricher
		}
	}

	return nil
}

func (a *appender) Append(name string, subCVEs []string, callback vulnmdsrc.AppendFunc) error {
	return nil
}

func (a *appender) PurgeCache() {
	a.metadata = nil
}
