package v1

import "github.com/stackrox/scanner/database"

type Severity string

const (
	UnknownSeverity Severity = "Unknown"
	LowSeverity Severity = "Low"
	ModerateSeverity Severity = "Moderate"
	ImportantSeverity Severity = "Important"
	CriticalSeverity Severity = "Critical"
)

func databaseVulnToSeverity(dbVuln database.Vulnerability) Severity  {
	switch dbVuln.Severity {
	case database.UnknownSeverity:
		return UnknownSeverity
	case database.NegligibleSeverity, database.LowSeverity:
		return LowSeverity
	case database.MediumSeverity:
		return ModerateSeverity
	case database.HighSeverity:
		return ImportantSeverity
	case database.CriticalSeverity, database.Defcon1Severity:
		return CriticalSeverity
	}
	return LowSeverity
}
