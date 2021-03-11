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
}
