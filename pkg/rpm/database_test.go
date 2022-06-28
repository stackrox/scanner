package rpm

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}

func Test_rpmDatabaseQuery_Next(t *testing.T) {
	type fields struct {
		rpmWait        func() error
		rpmStderr      *bytes.Buffer
		rpmStdout      io.ReadCloser
		rpmScanStopped bool
		err            error
	}
	tests := []struct {
		name      string
		fields    fields
		rpmOutput string

		want             bool
		wantPackage      rpmPackage
		wantRPMError     error
		wantRPMReadError error
	}{
		{
			name: "when err is set, returns false",
			fields: fields{
				err: errors.Errorf("foobar"),
			},
		},
		{
			name: "when rpmScanStopped is set and no error, returns false",
			fields: fields{
				rpmScanStopped: true,
			},
		},
		{
			name: "when rpm output is the empty line, returns false",
		},
		{
			name:      "when gpg package is listed, returns false",
			rpmOutput: "gpg-pubkey",
		},
		{
			name:             "when rpm command fails, returns false and error",
			wantRPMReadError: errors.Errorf("foobar"),
		},
		{
			name:         "when rpm exits with error, returns false with error",
			wantRPMError: errors.Errorf("foobar"),
		},
		{
			name: "when rpm output is one package, return true",
			want: true,
			wantPackage: rpmPackage{
				Name:    "vim-enhanced",
				Version: "2:8.0.1763-15.el8",
				Arch:    "x86_64",
				Filenames: []string{
					"/etc/profile.d/vim.sh",
					"/usr/bin/vim",
					"/usr/bin/vimdiff",
				},
			},
			rpmOutput: `vim-enhanced
2:8.0.1763-15.el8
x86_64
(none)
/etc/profile.d/vim.sh
/usr/bin/vim
/usr/bin/vimdiff
.
`,
		},
		{
			name: "when rpm output is two package, return true and the first package",
			want: true,
			wantPackage: rpmPackage{
				Name:    "vim-enhanced",
				Version: "2:8.0.1763-15.el8",
				Arch:    "x86_64",
				Filenames: []string{
					"/etc/profile.d/vim.sh",
					"/usr/bin/vim",
					"/usr/bin/vimdiff",
				},
			},
			rpmOutput: `vim-enhanced
2:8.0.1763-15.el8
x86_64
(none)
/etc/profile.d/vim.sh
/usr/bin/vim
/usr/bin/vimdiff
.
sed
4.5-2.el8
x86_64
(none)
/usr/bin/sed
/usr/share/doc/sed
/usr/share/doc/sed/sedfaq.txt.gz
/usr/share/info/sed.info.gz
/usr/share/licenses/sed
`,
		},
	}
	for _, tt := range tests {
		var r io.Reader
		if tt.wantRPMReadError != nil {
			r = &errorReader{err: tt.wantRPMReadError}
		} else {
			r = strings.NewReader(tt.rpmOutput)
		}
		tt.fields.rpmStdout = io.NopCloser(r)
		rpmScanner := bufio.NewScanner(r)
		tt.fields.rpmStderr = &bytes.Buffer{}
		if tt.fields.rpmWait == nil {
			tt.fields.rpmWait = func() error { return tt.wantRPMError }
		}
		t.Run(tt.name, func(t *testing.T) {
			q := &rpmDatabaseQuery{
				rpmWait:        tt.fields.rpmWait,
				rpmStderr:      tt.fields.rpmStderr,
				rpmScanner:     rpmScanner,
				rpmStdout:      tt.fields.rpmStdout,
				rpmScanStopped: tt.fields.rpmScanStopped,
				err:            tt.fields.err,
			}
			if got := q.Next(); got != tt.want {
				t.Errorf("Next() = %v, want %v", got, tt.want)
			}
			if tt.want {
				assert.NoError(t, q.Err())
				assert.Equal(t, tt.wantPackage, q.Package())
			}
			if tt.wantRPMReadError != nil {
				assert.ErrorContains(t, q.Err(), "rpm: error reading rpm output: foobar")
			}
			if tt.wantRPMError != nil {
				assert.ErrorIs(t, q.Err(), tt.wantRPMError)
			}
		})
	}
}

func Test_rpmDatabaseQuery_Next_MultipleCalls(t *testing.T) {
	t.Run("when output has multiple packages, then return all of them", func(t *testing.T) {
		r := strings.NewReader(`vim-enhanced
2:8.0.1763-15.el8
x86_64
(none)
/etc/profile.d/vim.sh
/usr/bin/vim
/usr/bin/vimdiff
.
sed
4.5-2.el8
x86_64
(none)
/usr/bin/sed
/usr/share/doc/sed
/usr/share/doc/sed/sedfaq.txt.gz
/usr/share/info/sed.info.gz
/usr/share/licenses/sed
.
`)
		q := &rpmDatabaseQuery{
			rpmWait:    func() error { return nil },
			rpmScanner: bufio.NewScanner(r),
			rpmStderr:  &bytes.Buffer{},
			rpmStdout:  io.NopCloser(r),
		}
		assert.True(t, q.Next())
		assert.Equal(t,
			rpmPackage{
				Name:    "vim-enhanced",
				Version: "2:8.0.1763-15.el8",
				Arch:    "x86_64",
				Filenames: []string{
					"/etc/profile.d/vim.sh",
					"/usr/bin/vim",
					"/usr/bin/vimdiff",
				},
			},
			q.Package())
		assert.True(t, q.Next())
		assert.Equal(t,
			rpmPackage{
				Name:    "sed",
				Version: "4.5-2.el8",
				Arch:    "x86_64",
				Filenames: []string{
					"/usr/bin/sed",
					"/usr/share/doc/sed",
					"/usr/share/doc/sed/sedfaq.txt.gz",
					"/usr/share/info/sed.info.gz",
					"/usr/share/licenses/sed",
				},
			},
			q.Package())
		assert.False(t, q.Next())
		assert.Nil(t, q.Err())
	})
}
