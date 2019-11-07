package cpe

import "github.com/facebookincubator/nvdtools/wfn"

type mockVuln struct {
	id string
}

func (m mockVuln) Match(attrs []*wfn.Attributes, requireVersion bool) (matches []*wfn.Attributes) {
	panic("implement me")
}

func (m mockVuln) Config() []*wfn.Attributes {
	panic("implement me")
}

func (m mockVuln) ID() string {
	return m.id
}

func (m mockVuln) CVEs() []string {
	panic("implement me")
}

func (m mockVuln) CWEs() []string {
	panic("implement me")
}

func (m mockVuln) CVSSv2BaseScore() float64 {
	panic("implement me")
}

func (m mockVuln) CVSSv2Vector() string {
	panic("implement me")
}

func (m mockVuln) CVSSv3BaseScore() float64 {
	panic("implement me")
}

func (m mockVuln) CVSSv3Vector() string {
	panic("implement me")
}
