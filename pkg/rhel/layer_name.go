package rhel

import "strings"

const (
	suffix = "uncertified"
)

func GetUncertifiedLayerName(layerName string) string {
	return layerName + suffix
}

func GetOriginalLayerName(uncertifiedLayerName string) string {
	return strings.TrimSuffix(uncertifiedLayerName, suffix)
}
