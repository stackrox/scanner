package ghsa

import "time"

// PackageInfo describes the Go package affected by a vulnerability.
type PackageInfo struct {
	Name string `json:"name,omitempty"`
}

// AdvisoryIdentifier is an identifier referencing an advisory (GHSA or CVE).
type AdvisoryIdentifier struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

// AdvisoryReference contains links to further information about the advisory.
type AdvisoryReference struct {
	URL string `json:"url,omitempty"`
}

// VersionSpec specifies a version of an affected package.
type VersionSpec struct {
	Identifier string `json:"identifier,omitempty"`
}

// Advisory describes a GHSA advisory.
type Advisory struct {
	ID          string               `json:"ghsaId,omitempty"`
	Summary     string               `json:"summary,omitempty"`
	Description string               `json:"description,omitempty"`
	Identifiers []AdvisoryIdentifier `json:"identifiers,omitempty"`
	Permalink   string               `json:"permalink,omitempty"`
	References  []AdvisoryReference  `json:"references,omitempty"`

	PublishedAt time.Time  `json:"publishedAt,omitempty"`
	UpdatedAt   time.Time  `json:"updatedAt,omitempty"`
	WithdrawnAt *time.Time `json:"withdrawnAt,omitempty"`
}

// SecurityVulnerability contains information about a security vulnerability
type SecurityVulnerability struct {
	Package   PackageInfo `json:"package"`
	Severity  string      `json:"severity,omitempty"`
	UpdatedAt time.Time   `json:"updatedAt,omitempty"`

	FirstPatchedVersion    *VersionSpec `json:"firstPatchedVersion,omitempty"`
	VulnerableVersionRange string       `json:"vulnerableVersionRange,omitempty"`
}

// SecurityVulnerabilityConnection connects a security vulnerability to an advisory
type SecurityVulnerabilityConnection struct {
	SecurityVulnerability `json:",inline"`

	Advisory Advisory `json:"advisory,omitempty"`
}

// AdvisoryWithVulnerabilities combines an advisory with all relevant vulnerabilities.
type AdvisoryWithVulnerabilities struct {
	Advisory        `json:",inline"`
	Vulnerabilities []*SecurityVulnerability `json:"vulnerabilities,inline"`
}
