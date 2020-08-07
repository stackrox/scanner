package util

func NormalizeOSName(os string) string {
	switch os {
	case "ol", "oracle":
		return "oracle"
	default:
		return os
	}
}
