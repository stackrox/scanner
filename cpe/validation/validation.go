package validation

import (
	"fmt"

	"github.com/stackrox/scanner/cpe/match"
	"github.com/stackrox/scanner/pkg/component"
)

var (
	Validators = make(map[component.SourceType]Validator)
)

type Validator interface {
	ValidateResult(result match.Result) bool
}

func Register(src component.SourceType, validator Validator) {
	if _, ok := Validators[src]; ok {
		panic(fmt.Sprintf("%q has already been registered", src))
	}
	Validators[src] = validator
}
