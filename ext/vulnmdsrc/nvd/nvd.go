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
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/commonerr"
)

const (
	appenderName string = "NVD"
)

type appender struct {
	metadata map[string]*metadataEnricher
}

type metadataEnricher struct {
	metadata *Metadata
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

type Metadata struct {
	PublishedDateTime    string
	LastModifiedDateTime string
	CVSSv2               NVDmetadataCVSSv2
	CVSSv3               NVDmetadataCVSSv3
}

type NVDmetadataCVSSv2 struct {
	Vectors             string
	Score               float64
	ExploitabilityScore float64
	ImpactScore         float64
}

type NVDmetadataCVSSv3 struct {
	Vectors             string
	Score               float64
	ExploitabilityScore float64
	ImpactScore         float64
}

func (a *appender) BuildCache(nvdDumpDir string) error {
	a.metadata = make(map[string]*metadataEnricher)

	fileInfos, err := ioutil.ReadDir(nvdDumpDir)
	if err != nil {
		return errors.Wrap(err, "failed to read dir")
	}

	for _, fileInfo := range fileInfos {
		fileName := fileInfo.Name()
		if filepath.Ext(fileName) != ".json" {
			continue
		}
		f, err := os.Open(fileName)
		if err != nil {
			return errors.Wrapf(err, "could not open NVD data file %s", fileName)
		}

		if err := a.parseDataFeed(bufio.NewReader(f)); err != nil {
			return errors.Wrapf(err, "could not parse NVD data file %s", fileName)
		}
		_ = f.Close()
	}

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

func (a *appender) getHighestCVSSMetadata(cves []string) *Metadata {
	var maxScore float64
	var maxMetadata *Metadata
	for _, cve := range cves {
		if enricher, ok := a.metadata[cve]; ok {
			nvdMetadata := enricher.metadata
			if nvdMetadata.CVSSv3.Score != 0 && nvdMetadata.CVSSv3.Score > maxScore {
				maxScore = nvdMetadata.CVSSv3.Score
				maxMetadata = nvdMetadata
			} else if nvdMetadata.CVSSv2.Score > maxScore {
				maxScore = nvdMetadata.CVSSv2.Score
				maxMetadata = nvdMetadata
			}
		}
	}

	return maxMetadata
}

func (a *appender) Append(name string, subCVEs []string, appendFunc AppendFunc) error {
	if enricher, ok := a.metadata[name]; ok {
		appendFunc(appenderName, enricher, SeverityFromCVSS(enricher.metadata))
		return nil
	}
	if nvdMetadata := a.getHighestCVSSMetadata(subCVEs); nvdMetadata != nil {
		appendFunc(appenderName, &metadataEnricher{metadata: nvdMetadata}, SeverityFromCVSS(nvdMetadata))
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
func SeverityFromCVSS(meta *Metadata) database.Severity {
	score := meta.CVSSv3.Score
	if score == 0 {
		score = meta.CVSSv2.Score
	}
	switch {
	case score < 1.0:
		return database.NegligibleSeverity
	case score < 3.9:
		return database.LowSeverity
	case score < 6.9:
		return database.MediumSeverity
	case score < 8.9:
		return database.HighSeverity
	case score <= 10:
		return database.CriticalSeverity
	}
	return database.UnknownSeverity
}
