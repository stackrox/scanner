package java

import (
	"github.com/stackrox/scanner/cpe/match"
	"github.com/stackrox/scanner/cpe/validation"
	"github.com/stackrox/scanner/pkg/component"
)

type validator struct{}

func (v validator) ValidateResult(result match.Result) bool {
	return validation.TargetSWMatches(result, "java")
}

func init() {
	validation.Register(component.JavaSourceType, &validator{})
}
