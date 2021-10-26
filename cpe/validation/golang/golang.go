package golang

import (
	"github.com/stackrox/scanner/cpe/match"
	"github.com/stackrox/scanner/cpe/validation"
	"github.com/stackrox/scanner/pkg/component"
)

func init() {
	validation.Register(component.GolangSourceType, &validator{})
}

type validator struct{}

func (v validator) ValidateResult(_ match.Result) bool {
	return true
}
