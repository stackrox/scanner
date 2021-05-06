package featurens

type DetectorOptions struct {
	UncertifiedRHEL bool
}

func (do *DetectorOptions) GetUncertifiedRHEL() bool {
	if do == nil {
		return false
	}

	return do.UncertifiedRHEL
}
