package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/pkg/analyzer/nodes"
)

func main() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fPath := flag.String("fspath", "/host", "Path to the root folder of a filesystem")
	fRHCOSrequired := flag.Bool("rhcosRequired", true, "Fails scan if filesystem is not RHCOS. Node Scanning only works on RHCOS.")
	fUncertifiedRHEL := flag.Bool("uncertifiedRhel", false, "Set true for CentOS and false for RHEL.")
	fVerbose := flag.Bool("verbose", false, "Print verbose output if set")
	flag.Parse()

	setupLog(*fVerbose)

	fspath, err := filepath.Abs(*fPath)
	if err != nil {
		log.Fatalf("Encountered error while formatting path: %v", err)
	}

	log.Infof("Analyzing rootfs in %v", fspath)
	components, err := nodes.Analyze(context.Background(), "nodename", fspath, nodes.AnalyzeOpts{UncertifiedRHEL: *fUncertifiedRHEL, IsRHCOSRequired: *fRHCOSrequired})
	if err != nil {
		log.Errorf("Encountered error while scanning: %v", err)
	}

	printResultsToTTY(components)
}

func setupLog(verbose bool) {
	log.SetFormatter(&log.TextFormatter{
		DisableLevelTruncation: true,
		PadLevelText:           true,
		FullTimestamp:          true,
		TimestampFormat:        "2006-01-02 15:04:05",
	})

	if verbose {
		log.SetLevel(log.DebugLevel)
	}
}

func printResultsToTTY(components *nodes.Components) {
	if components == nil || components.CertifiedRHELComponents == nil {
		log.Info("No Components discovered")
		return
	}
	log.Infof("Determined OS: %v", components.CertifiedRHELComponents.Dist)
	if components.CertifiedRHELComponents.Packages != nil {
		log.Infof("Number of installed RPM packages: %v", len(components.CertifiedRHELComponents.Packages))
		for _, c := range components.CertifiedRHELComponents.Packages {
			log.Debugf("Component: %v", c)
		}
	}

	if components.CertifiedRHELComponents.ContentSets != nil {
		log.Infof("Number of discovered ContentSets: %v", len(components.CertifiedRHELComponents.ContentSets))
		for _, cs := range components.CertifiedRHELComponents.ContentSets {
			log.Debugf("CPE: %v", cs)
		}
	}

}
