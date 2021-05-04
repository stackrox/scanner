package rhel

const (
	suffix = "uncertified"
)

func GetUncertifiedLayerName(layerName string) string {
	return layerName + suffix
}
