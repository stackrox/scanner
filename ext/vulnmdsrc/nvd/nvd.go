// Copyright 2017 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package nvd implements a vulnerability metadata appender using the NIST NVD
// database.
package nvd

import (
	"bufio"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/vulnmdsrc"
	"github.com/stackrox/scanner/pkg/commonerr"
)

const (
	appenderName string = "NVD"
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

func newMetadataEnricher(nvd *nvdEntry) *metadataEnricher {
	return &metadataEnricher{
		metadata: nvd.Metadata(),
		summary:  nvd.Summary(),
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
			return errors.Wrapf(err, "could not open NVD data file %s", fileName)
		}

		if err := a.parseDataFeed(bufio.NewReader(f)); err != nil {
			return errors.Wrapf(err, "could not parse NVD data file %s", fileName)
		}
		_ = f.Close()
	}
	log.Infof("Obtained metadata for %d vulns", len(a.metadata))

	return nil
}

func (a *appender) parseDataFeed(r io.Reader) error {
	var nvd nvd

	if err := json.NewDecoder(r).Decode(&nvd); err != nil {
		return commonerr.ErrCouldNotParse
	}

	for _, nvdEntry := range nvd.Entries {
		// Create metadata entry.
		enricher := newMetadataEnricher(&nvdEntry)
		if enricher.metadata != nil {
			a.metadata[nvdEntry.Name()] = enricher
		}
	}

	return nil
}

func (a *appender) Append(name string, _ []string, appendFunc vulnmdsrc.AppendFunc) error {
	if enricher, ok := a.metadata[name]; ok {
		appendFunc(appenderName, enricher, SeverityFromCVSS(enricher.metadata))
		return nil
	}
	return nil
}

func (a *appender) PurgeCache() {
	a.metadata = nil
}

// SeverityFromCVSS converts the CVSS Score (0.0 - 10.0) into a
// database.Severity following the qualitative rating scale available in the
// CVSS v3.0 specification (https://www.first.org/cvss/specification-document),
// Table 14.
//
// The Negligible level is set for CVSS scores between [0, 1), replacing the
// specified None level, originally used for a score of 0.
func SeverityFromCVSS(meta *vulnmdsrc.Metadata) database.Severity {
	score := meta.CVSSv3.Score
	if score == 0 {
		score = meta.CVSSv2.Score
	}
	switch {
	case score < 1.0:
		return database.NegligibleSeverity
	case score < 4.0:
		return database.LowSeverity
	case score < 7.0:
		return database.MediumSeverity
	case score < 9.0:
		return database.HighSeverity
	case score <= 10.0:
		return database.CriticalSeverity
	}
	return database.UnknownSeverity
}
