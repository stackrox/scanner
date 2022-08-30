package tarutil

import (
	"testing"

	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stretchr/testify/assert"
)

func TestLayerFiles_GetFilesPrefix(t *testing.T) {
	type fields struct {
		data    map[string]analyzer.FileData
		links   map[string]string
		removed set.StringSet
	}
	type args struct {
		prefix string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   map[string]analyzer.FileData
	}{
		{
			name: "no match",
			fields: fields{
				data: map[string]analyzer.FileData{
					"foo/fooz": {},
					"bar/barz": {},
				},
			},
			args: args{
				prefix: "foobar",
			},
			want: map[string]analyzer.FileData{},
		},
		{
			name: "match and ignore prefix",
			fields: fields{
				data: map[string]analyzer.FileData{
					"var/lib/dpkg":          {},
					"var/lib/dpkg/status.d": {},
					"var/lib/dpkg/status.d/foo.json": {
						Contents: []byte("foo.json"),
					},
					"var/lib/dpkg/status.d/subdir/bar.json": {
						Contents: []byte("bar.json"),
					},
				},
			},
			args: args{
				prefix: "var/lib/dpkg/status.d",
			},
			want: map[string]analyzer.FileData{
				"var/lib/dpkg/status.d/foo.json": {
					Contents: []byte("foo.json"),
				},
				"var/lib/dpkg/status.d/subdir/bar.json": {
					Contents: []byte("bar.json"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := LayerFiles{
				data:    tt.fields.data,
				links:   tt.fields.links,
				removed: tt.fields.removed,
			}
			assert.Equalf(t, tt.want, f.GetFilesPrefix(tt.args.prefix), "GetFilesPrefix(%v)", tt.args.prefix)
		})
	}
}
