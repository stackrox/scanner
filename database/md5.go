package database

import (
	"bytes"
	"crypto/md5"
)

// MD5Vuln creates an md5 hash from the members of the passed-in Vulnerability,
// giving us a stable, context-free identifier for this revision of the
// Vulnerability.
func MD5Vuln(v *RHELv2Vulnerability) []byte {
	var b bytes.Buffer
	b.WriteString(v.Name)
	// Ignore description, as it is stored separately.
	b.WriteString(v.Issued.String())
	b.WriteString(v.Updated.String())
	b.WriteString(v.Link)
	b.WriteString(v.Severity)
	b.WriteString(v.CVSSv3)
	b.WriteString(v.CVSSv2)
	s := md5.Sum(b.Bytes())
	return s[:]
}

// MD5VulnPackage creates an md5 hash from the members of the given
// arguments to represent a unique identifier for a vulnerable package.
func MD5VulnPackage(vulnName string, p *RHELv2Package, cpe string, pkgInfo *RHELv2PackageInfo) []byte {
	var b bytes.Buffer
	b.WriteString(vulnName)
	b.WriteString(p.Name)
	b.WriteString(p.Module)
	b.WriteString(p.Arch)
	b.WriteString(cpe)
	b.WriteString(pkgInfo.ArchOperation.String())
	b.WriteString(pkgInfo.FixedInVersion)
	s := md5.Sum(b.Bytes())
	return s[:]
}
