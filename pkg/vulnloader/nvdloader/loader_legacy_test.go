package nvdloader

import (
	"testing"

	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/stretchr/testify/assert"
)

// shorthand to make code cleaner
type c = schema.CVEJSON40

func TestRejected(t *testing.T) {
	l := new(legacyLoader)

	tcs := []struct {
		desc string
		want bool
		cve  *schema.CVEJSON40
	}{
		{"nil desc", false, &c{
			Description: nil,
		}},
		{"nil desc data", false, &c{
			Description: &schema.CVEJSON40Description{
				DescriptionData: nil,
			},
		}},
		{"empty desc data", false, &c{
			Description: &schema.CVEJSON40Description{
				DescriptionData: []*schema.CVEJSON40LangString{},
			},
		}},
		{"not rejected desc", false, &c{
			Description: &schema.CVEJSON40Description{
				DescriptionData: []*schema.CVEJSON40LangString{
					{Value: "very bad"},
				},
			},
		}},
		{"rejected desc", true, &c{
			Description: &schema.CVEJSON40Description{
				DescriptionData: []*schema.CVEJSON40LangString{
					{Value: rejectedReason + "blah blah"},
				},
			},
		}},
		{"rejected on second desc", true, &c{
			Description: &schema.CVEJSON40Description{
				DescriptionData: []*schema.CVEJSON40LangString{
					{Value: "blah blah"},
					{Value: rejectedReason + "blah blah"},
				},
			},
		}},
	}
	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			item := &schema.NVDCVEFeedJSON10DefCVEItem{CVE: tc.cve}
			assert.Equal(t, l.rejected(item), tc.want)
		})
	}

}
