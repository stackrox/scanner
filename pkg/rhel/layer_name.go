package rhel

import "strings"

const (
	suffix = "uncertified"
)

func GetUncertifiedLayerName(layerName string) string {
	return layerName + suffix
}

func GetOriginalLayerName(layerName string) string {
	return strings.TrimSuffix(layerName, suffix)
}
