package features

type options struct {
	noRoxAllowed bool
}

type FeatureFlagOption interface {
	apply(o *options)
}

// NoRoxAllowed returns a feature flag option which allows for a variant
// of the flag missing the ROX_ prefix as well as with the prefix.
func NoRoxAllowed() FeatureFlagOption {
	return noRoxAllowed{}
}

type noRoxAllowed struct{}

func (noRoxAllowed) apply(o *options) {
	o.noRoxAllowed = true
}
