package whiteout

var (
	// Prefix prefix means file is a whiteout. If this is followed by a
	// filename this means that file has been removed from the base layer.
	Prefix = ".wh."
)
