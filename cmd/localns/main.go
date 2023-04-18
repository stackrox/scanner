package main

import (
	"context"
	"flag"
	"os"

	"github.com/cloudflare/cfssl/log"
	"github.com/stackrox/scanner/pkg/analyzer/nodes"
)

func main() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagPath := flag.String("rootpath", "/host", "Path to the root folder of an RHCOS filesystem")
	flag.Parse()

	log.Infof("Analyzing rootfs in %v", *flagPath)

	components, err := nodes.Analyze(context.Background(), "nodename", *flagPath /*"/tmp/rpm-rhel86"*/, nodes.AnalyzeOpts{UncertifiedRHEL: false, IsRHCOSRequired: true})
	if err != nil {
		log.Errorf("Encountered error while scanning: %v", err)
	}
	if components == nil || components.CertifiedRHELComponents == nil {
		log.Info("No Components discovered")
		return
	}
	log.Info("Number of discovered packages: %v", len(components.CertifiedRHELComponents.Packages))
	for _, c := range components.CertifiedRHELComponents.Packages {
		log.Info("Component: %v", c)
	}
}
