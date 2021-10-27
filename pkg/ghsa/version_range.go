package ghsa

import (
	"strings"

	"github.com/pkg/errors"
)

// VersionRange describes a version range that is part of an
type VersionRange struct {
	MinVersion          string
	MinVersionExclusive bool

	MaxVersion          string
	MaxVersionInclusive bool
}

// ParseVersionRange parses a version range string.
func ParseVersionRange(verRangeStr string) (VersionRange, error) {
	parts := strings.Split(strings.TrimSpace(verRangeStr), ",")
	if len(parts) < 1 || len(parts) > 2 {
		return VersionRange{}, errors.Errorf("incorrect number of comma-separated parts in version range %q", verRangeStr)
	}

	var res VersionRange

	subParts := strings.Split(strings.TrimSpace(parts[0]), " ")
	if len(subParts) != 2 {
		return VersionRange{}, errors.Errorf("expected each part of the version range to consist of an operator and a version, but first part was %q", parts[0])
	}
	switch subParts[0] {
	case ">":
		res.MinVersionExclusive = true
		fallthrough
	case ">=":
		res.MinVersion = subParts[1]

	case "=":
		res.MinVersion = subParts[1]
		fallthrough
	case "<=":
		res.MaxVersionInclusive = true
		fallthrough
	case "<":
		res.MaxVersion = subParts[1]
		if len(parts) != 1 {
			return VersionRange{}, errors.Errorf("version range must not contain a second part if first operator is %s", verRangeStr)
		}
	default:
		return VersionRange{}, errors.Errorf("invalid operator %q in first part of version range", subParts[0])
	}

	if len(parts) == 1 {
		return res, nil
	}

	subParts = strings.Split(strings.TrimSpace(parts[1]), " ")
	switch subParts[0] {
	case "<=":
		res.MaxVersionInclusive = true
		fallthrough
	case "<":
		res.MaxVersion = subParts[1]
	default:
		return VersionRange{}, errors.Errorf("invalid operator %q in second part of version range", subParts[0])
	}

	return res, nil
}
