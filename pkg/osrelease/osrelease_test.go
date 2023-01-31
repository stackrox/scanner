package osrelease

import (
	"reflect"
	"testing"
)

func TestGetOSReleaseMap(t *testing.T) {
	type args struct {
		data   []byte
		fields []string
	}
	tests := []struct {
		name          string
		args          args
		want          map[string]string
		osReleaseData string
	}{
		{
			name: "when line that is not sh assignment then ignored",
			want: map[string]string{
				"FOO": "bar",
				"BAR": "foo",
			},
			osReleaseData: `
FOO=BAR
FOOZ
BAR=foo
`,
		},
		{
			name: "when empty line that is not sh assignment then ignored",
			want: map[string]string{
				"FOO": "bar",
				"BAR": "foo",
			},
			osReleaseData: `
FOO=BAR

BAR=foo
`,
		},
		{
			name: "when assignment without value then value is empty",
			want: map[string]string{
				"FOO": "bar",
				"BAR": "",
			},
			osReleaseData: `
FOO=bar
BAR=
`,
		},
	}
	for _, tt := range tests {
		if tt.osReleaseData != "" {
			tt.args.data = []byte(tt.osReleaseData)
		}
		t.Run(tt.name, func(t *testing.T) {
			if got := GetOSReleaseMap(tt.args.data, tt.args.fields...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetOSReleaseMap() = %v, want %v", got, tt.want)
			}
		})
	}
}
