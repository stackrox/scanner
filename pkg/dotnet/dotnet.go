package dotnet

import "regexp"

var (
	DLLPattern = regexp.MustCompile(`^.*/dotnet/shared/(Microsoft\.(?:AspNet|NET)Core\.(?:App|All))/([0-9]+\.[0-9]+\.[0-9]+)/.*.dll$`)
)
