package common

import (
	"testing"

	"github.com/stackrox/scanner/pkg/component"
	"github.com/stretchr/testify/assert"
)

func TestGenerateNameKeys(t *testing.T) {
	cases := []struct {
		name string
		keys []string
	}{
		{
			name: "",
		},
		{
			name: "name",
			keys: []string{
				"name",
			},
		},
		{
			name: "struts-showcase",
			keys: []string{
				"struts-showcase",
				"struts_showcase",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			comp := &component.Component{Name: c.name}
			assert.ElementsMatch(t, c.keys, GenerateNameKeys(comp).AsSlice())
		})
	}
}
