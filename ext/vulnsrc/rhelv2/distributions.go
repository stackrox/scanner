package rhelv2

import (
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/cpe"
)

// RHEL has minor releases however their security database files are bundled together
// by major version. for example `com.redhat.rhsa-RHEL7.xml`
// we choose to normalize detected distributions into major releases and parse vulnerabilities by major release versions.

type Release int

const (
	// RHEL3 Red Hat Enterprise Linux 3
	RHEL3 Release = 3
	// RHEL4 Red Hat Enterprise Linux 4
	RHEL4 Release = 4
	// RHEL5 Red Hat Enterprise Linux 5
	RHEL5 Release = 5
	// RHEL6 Red Hat Enterprise Linux 6
	RHEL6 Release = 6
	// RHEL7 Red Hat Enterprise Linux 7
	RHEL7 Release = 7
	// RHEL8 Red Hat Enterprise Linux 8
	RHEL8 Release = 8
)

var rhel6Dist = &database.Distribution{
	VersionID:  "6",
	DID:        "rhel",
	CPE:        cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:6"),
}
var rhel7Dist = &database.Distribution{
	VersionID:  "7",
	DID:        "rhel",
	CPE:        cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:7"),
}
var rhel8Dist = &database.Distribution{
	VersionID:  "8",
	DID:        "rhel",
	CPE:        cpe.MustUnbind("cpe:/o:redhat:enterprise_linux:8"),
}

func releaseToDist(r Release) *database.Distribution {
	switch r {
	case RHEL6:
		return rhel6Dist
	case RHEL7:
		return rhel7Dist
	case RHEL8:
		return rhel8Dist
	default:
		// return empty dist
		return &database.Distribution{}
	}
}
