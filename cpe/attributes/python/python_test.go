package python

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseAuthorEmailAsVendor(t *testing.T) {
	cases := []struct {
		email  string
		vendor string
	}{
		{
			email:  "",
			vendor: "",
		},
		{
			email:  "a",
			vendor: "",
		},
		{
			email:  "a@",
			vendor: "",
		},
		{
			email:  "a@stackrox",
			vendor: "",
		},
		{
			email:  "a@stackrox.com",
			vendor: "stackrox",
		},
	}
	for _, c := range cases {
		t.Run(c.email, func(t *testing.T) {
			assert.Equal(t, c.vendor, parseAuthorEmailAsVendor(c.email))
		})
	}
}
