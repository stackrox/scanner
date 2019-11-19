package v1

import (
	"fmt"
	"testing"

	"github.com/stackrox/scanner/pkg/component"
	"github.com/stretchr/testify/assert"
)

func TestDedupeVersionMatcher(t *testing.T) {
	cases := []struct {
		v1, v2   string
		expected bool
	}{
		{
			v1:       "diff1",
			v2:       "diff2",
			expected: false,
		},
		{
			v1:       "3.5.13",
			v2:       "3.5.13",
			expected: true,
		},
		{
			v1:       "3.5.13",
			v2:       "3.5.13-1",
			expected: true,
		},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s-%s", c.v1, c.v2), func(t *testing.T) {
			assert.Equal(t, c.expected, dedupeVersionMatcher(c.v1, c.v2))
		})
	}
}

func TestShouldDedupeLanguageFeature(t *testing.T) {
	cases := []struct {
		name       string
		feature    Feature
		osFeatures []Feature
		dedupe     bool
	}{
		{
			name: "jinja-individual",
			feature: Feature{
				Name:          "jinja2",
				VersionFormat: "Python",
				Version:       "2.10",
			},
			dedupe: false,
		},
		{
			name: "jinja-duplicate",
			feature: Feature{
				Name:          "jinja2",
				VersionFormat: "Python",
				Version:       "2.10",
			},
			osFeatures: []Feature{
				{
					Name:          "jinja2",
					VersionFormat: "dpkg",
					Version:       "2.10-2",
				},
			},
			dedupe: true,
		},
		{
			name: "python-werkzeug",
			feature: Feature{
				Name:          "werkzeug",
				VersionFormat: component.PythonSourceType.String(),
				Version:       "0.14.1",
			},
			osFeatures: []Feature{
				{
					Name:          "python-werkzeug",
					VersionFormat: "dpkg",
					Version:       "0.14.1+dfsg1-4",
				},
			},
			dedupe: true,
		},
		{
			name: "libsass",
			feature: Feature{
				Name:          "libsass",
				VersionFormat: component.PythonSourceType.String(),
				Version:       "0.17.1",
			},
			osFeatures: []Feature{
				{
					Name:          "libsass-python",
					VersionFormat: "dpkg",
					Version:       "0.17.1-1",
				},
			},
			dedupe: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.dedupe, shouldDedupeLanguageFeature(c.feature, c.osFeatures))
		})
	}
}
