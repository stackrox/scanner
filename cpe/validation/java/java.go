package java

import (
	"github.com/stackrox/scanner/cpe/match"
	"github.com/stackrox/scanner/cpe/validation"
	"github.com/stackrox/scanner/pkg/component"
)

type validator struct{}

func (v validator) ValidateResult(result match.Result) bool {
	return true
}

func init() {
	validation.Register(component.JavaSourceType, &validator{})
}
