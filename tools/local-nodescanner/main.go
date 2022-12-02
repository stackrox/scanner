package main

import (
	"flag"

	"github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/pkg/analyzer/nodes"
)

// local nodescanner is an application that allows you to run the node scan / inventory code locally on you machine.

// Required:
// Extracted filesystem from an RHCOS live .ISO (https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/latest/)
// installed RPM v 4.13.3 (precisely: have rpmdb in path) - newer versions, e.g. 4.17, WILL NOT WORK and produce empty components.
//        alternatively:
//        run this binary with mounted unpacked folder in registry.access.redhat.com/ubi8/ubi:8.7

// Howto:
// Download the ISO, extract with 7z x <iso-name>, then extract images/pxeboot/root.squashfs with 7z as well
// The root fs will be in ostree/deploy/rhcos/deploy/
// Caveat: The image doesn't contain a populated rpm Package DB. You still need to get that from a running system, e.g. a node.

func main() {
	var uncertifiedRHEL bool
	var path string

	flag.StringVar(&path, "path", "", "Path to an extracted RHCOS rootFS folder")
	flag.BoolVar(&uncertifiedRHEL, "uncertifiedRHEL", false, "Whether to treat this run as uncertified RHEL FS")
	flag.Parse()

	logrus.Infof("%v", path)
	if path == "" {
		logrus.Fatal("A valid path is required")
	}

	components, err := nodes.Analyze("localnode", path, uncertifiedRHEL)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Infof("Nodescan finished. Returned components: %v", components)
}
