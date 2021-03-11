package apk

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b  string
		value int
	}{
		{
			a:     "",
			b:     "",
			value: 0,
		},
		{
			a:     "0.7.2-r3",
			b:     "0.7.2-r3",
			value: 0,
		},
		{
			a:     "0.7.2-r3",
			b:     "0.7.2-r4",
			value: -1,
		},
		{
			a:     "0.7.2-r3",
			b:     "0.7.3-r3",
			value: -1,
		},
		{
			a:     "0.7.2-r3",
			b:     "0.8.2-r3",
			value: -1,
		},
		{
			a:     "0.7.2-r3",
			b:     "1.7.2-r3",
			value: -1,
		},
		{
			a:     "0.7.2-r3",
			b:     "1.7.2-r3",
			value: -1,
		},
		{
			a:     "1.2.2_pre2-r0",
			b:     "1.2.2-r0",
			value: -1,
		},
	}

	p := parser{}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s+%s", c.a, c.b), func(t *testing.T) {
			value, err := p.Compare(c.a, c.b)
			assert.NoError(t, err)
			assert.Equal(t, c.value, value)

			// Flip and ensure that the opposite works as well
			value, err = p.Compare(c.b, c.a)
			assert.NoError(t, err)
			assert.Equal(t, c.value*-1, value)
		})
	}
	/*
		{
		  "name": "libc-utils",
		  "version": "0.7.2-r3"
		}
		{
		  "name": "ca-certificates-bundle",
		  "version": "20191127-r5"
		}
		{
		  "name": "zlib",
		  "version": "1.2.11-r3"
		}
		{
		  "name": "musl",
		  "version": "1.2.2-r0"
		}
		{
		  "name": "libcrypto1.1",
		  "version": "1.1.1j-r0"
		}
		{
		  "name": "scanelf",
		  "version": "1.2.8-r0"
		}
		{
		  "name": "alpine-keys",
		  "version": "2.2-r0"
		}
		{
		  "name": "ssl_client",
		  "version": "1.32.1-r3"
		}
		{
		  "name": "musl-utils",
		  "version": "1.2.2-r0"
		}
		{
		  "name": "alpine-baselayout",
		  "version": "3.2.0-r8"
		}
		{
		  "name": "libtls-standalone",
		  "version": "2.9.1-r1"
		}
		{
		  "name": "apk-tools",
		  "version": "2.12.1-r0"
		}
		{
		  "name": "libssl1.1",
		  "version": "1.1.1j-r0"
		}
		{
		  "name": "busybox",
		  "version": "1.32.1-r3"
		}
	*/

	/*

		// ParserName is the name by which the dpkg parser is registered.
		const ParserName = "apk"

		type parser struct{}

		func (p parser) Valid(str string) bool {
			_, err := version.NewVersion(str)
			return err == nil
		}

		// Compare function compares two Alpine package versions
		func (p parser) Compare(a, b string) (int, error) {
			// Quick check
			if a == b {
				return 0, nil
			}

			a = strings.TrimSpace(a)
			if a == "" {
				return 0, errors.New("version string is empty")
			}
			b = strings.TrimSpace(b)
			if b == "" {
				return 0, errors.New("version string is empty")
			}

			if a == versionfmt.MinVersion || b == versionfmt.MaxVersion {
				return -1, nil
			}
			if b == versionfmt.MinVersion || a == versionfmt.MaxVersion {
				return 1, nil
			}

			v1, err := version.NewVersion(a)
			if err != nil {
				return 0, nil
			}

			v2, err := version.NewVersion(b)
			if err != nil {
				return 0, nil
			}

			return v1.Compare(v2), nil
		}

		func init() {
			versionfmt.RegisterParser(ParserName, parser{})
		}

	*/

}
