package common

import (
	"fmt"
	"github.com/pkg/errors"
	v1 "github.com/stackrox/scanner/generated/shared/api/v1"
	"strings"
)

// FeatureNameVersionToString serialize v1.FeatureNameVersion to a string
func FeatureNameVersionToString(nameVersion *v1.FeatureNameVersion) string {
	return fmt.Sprintf("%s::::%s", nameVersion.Name, nameVersion.Version)
}

// ParseFeatureNameVersion parse FeatureNameVersion from a string.
func ParseFeatureNameVersion(input string) (*v1.FeatureNameVersion, error) {
	parts := strings.Split(input, "::::")
	if len(parts) != 2 {
		return nil, errors.Errorf("failed to parse %s into feature name version %v", input, parts)
	}
	return &v1.FeatureNameVersion{Name: parts[0], Version: parts[1]}, nil
}
