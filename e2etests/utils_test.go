//go:build e2e || slim_e2e
// +build e2e slim_e2e

package e2etests

import (
	"testing"

	v1 "github.com/stackrox/scanner/api/v1"
	"github.com/stretchr/testify/require"
)

func getMatchingFeature(t *testing.T, featureList []v1.Feature, featureToFind v1.Feature, allowNotFound bool) *v1.Feature {
	candidateIdx := -1
	for i, f := range featureList {
		if f.Name == featureToFind.Name && f.Version == featureToFind.Version {
			require.Equal(t, -1, candidateIdx, "Found multiple features for %s/%s", f.Name, f.Version)
			candidateIdx = i
		}
	}
	if allowNotFound && candidateIdx == -1 {
		return nil
	}
	require.NotEqual(t, -1, candidateIdx, "Feature %+v not in list: %+v", featureToFind, featureList)
	return &featureList[candidateIdx]
}
