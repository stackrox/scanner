package nodeinventory

import (
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/compliance/collection/metrics"
	"github.com/stackrox/scanner/database"
	scannerV1 "github.com/stackrox/scanner/generated/scanner/api/v1"
	"github.com/stackrox/scanner/pkg/analyzer/nodes"
	"golang.org/x/exp/maps"
)

// Scanner is an implementation of NodeInventorizer
type Scanner struct {
}

// ScanResult wraps scanned node components, scanner notes and the node name in a result message.
type ScanResult struct {
	NodeName   string
	Components *scannerV1.Components
	Notes      []scannerV1.Note
}

// Scan scans the current node and returns the results as ScanResult object
func (n *Scanner) Scan(nodeName string) (*ScanResult, error) {
	metrics.ObserveScansTotal(nodeName)
	startTime := time.Now()

	// uncertifiedRHEL is set to false, as scans are only supported on RHCOS for now,
	// which only exists in certified versions
	componentsHost, err := nodes.Analyze(nodeName, "/host/", nodes.AnalyzeOpts{UncertifiedRHEL: false, IsRHCOSRequired: true})

	scanDuration := time.Since(startTime)
	metrics.ObserveScanDuration(scanDuration, nodeName, err)
	log.Debugf("Collecting Node Inventory took %f seconds", scanDuration.Seconds())

	if err != nil {
		log.Errorf("Error scanning node /host inventory: %v", err)
		return nil, err
	}
	log.Debugf("Components found under /host: %v", componentsHost)

	protoComponents := protoComponentsFromScanComponents(componentsHost)

	return &ScanResult{
		NodeName:   nodeName,
		Components: protoComponents,
		Notes:      []scannerV1.Note{scannerV1.Note_LANGUAGE_CVES_UNAVAILABLE},
	}, nil
}

func protoComponentsFromScanComponents(c *nodes.Components) *scannerV1.Components {
	if c == nil {
		return nil
	}

	var namespace string
	if c.OSNamespace == nil {
		namespace = "unknown"
		// TODO(ROX-14186): Also set a note here that this is an uncertified scan
	} else {
		namespace = c.OSNamespace.Name
	}

	// For now, we only care about RHEL components, but this must be extended once we support non-RHCOS
	var rhelComponents []*scannerV1.RHELComponent
	var contentSets []string
	if c.CertifiedRHELComponents != nil {
		rhelComponents = convertAndDedupRHELComponents(c.CertifiedRHELComponents)
		contentSets = c.CertifiedRHELComponents.ContentSets
	}

	protoComponents := &scannerV1.Components{
		Namespace:       namespace,
		RhelComponents:  rhelComponents,
		RhelContentSets: contentSets,
	}
	return protoComponents
}

func convertAndDedupRHELComponents(rc *database.RHELv2Components) []*scannerV1.RHELComponent {
	if rc == nil || rc.Packages == nil {
		log.Warn("No RHEL packages found in scan result")
		return nil
	}

	convertedComponents := make(map[string]*scannerV1.RHELComponent, 0)
	for i, rhelc := range rc.Packages {
		if rhelc == nil {
			continue
		}
		comp := &scannerV1.RHELComponent{
			// The loop index is used as ID, as this field only needs to be unique for each NodeInventory result slice
			Id:          int64(i),
			Name:        rhelc.Name,
			Namespace:   rc.Dist,
			Version:     rhelc.Version,
			Arch:        rhelc.Arch,
			Module:      rhelc.Module,
			Executables: nil,
		}
		if rhelc.Executables != nil {
			comp.Executables = convertExecutables(rhelc.Executables)
		}
		compKey := makeComponentKey(comp)
		if compKey != "" {
			if _, contains := convertedComponents[compKey]; !contains {
				log.Debugf("Adding component %v to convertedComponents", comp.Name)
				convertedComponents[compKey] = comp
			} else {
				log.Warnf("Detected package collision in Node Inventory scan. Skipping package %s at index %d", compKey, i)
			}
		}

	}
	return maps.Values(convertedComponents)
}

func convertExecutables(exe []*scannerV1.Executable) []*scannerV1.Executable {
	arr := make([]*scannerV1.Executable, len(exe))
	for i, executable := range exe {
		arr[i] = &scannerV1.Executable{
			Path:             executable.GetPath(),
			RequiredFeatures: nil,
		}
		if executable.GetRequiredFeatures() != nil {
			arr[i].RequiredFeatures = make([]*scannerV1.FeatureNameVersion, len(executable.GetRequiredFeatures()))
			for i2, fnv := range executable.GetRequiredFeatures() {
				arr[i].RequiredFeatures[i2] = &scannerV1.FeatureNameVersion{
					Name:    fnv.GetName(),
					Version: fnv.GetVersion(),
				}
			}
		}
	}
	return arr
}

func makeComponentKey(component *scannerV1.RHELComponent) string {
	return component.Name + ":" + component.Version + ":" + component.Arch + ":" + component.Module
}
