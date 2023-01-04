package fsutil

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithin(t *testing.T) {
	testcases := []struct {
		parent string
		child  string
		within bool
	}{
		{
			parent: "/a/b",
			child:  "/a/b/c",
			within: true,
		},
		{
			parent: "/a/b/c",
			child:  "/a/b",
			within: false,
		},
		{
			parent: "/a/b",
			child:  "/a/b",
			within: true,
		},
		{
			parent: "a/b",
			child:  "a/b",
			within: true,
		},
		{
			parent: "a/b",
			child:  "/a/b",
			within: false,
		},
		{
			parent: "/a/b",
			child:  "a/b",
			within: false,
		},
		{
			parent: "/a",
			child:  "/a/b/../c/..",
			within: true,
		},
		{
			parent: "/a",
			child:  "/a/b/../..",
			within: false,
		},
	}
	for _, testcase := range testcases {
		t.Run(fmt.Sprintf("%s %s", testcase.parent, testcase.child), func(t *testing.T) {
			assert.Equal(t, testcase.within, Within(testcase.parent, testcase.child))
		})
	}
}
