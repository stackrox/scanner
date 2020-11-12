package server

import (
	"fmt"
	"testing"
	"github.com/stackrox/scanner/pkg/clairify/types"
)

func TestFetchLayers(t *testing.T) {

	reg, err := types.DockerRegistryCreator("https://mcr.microsoft.com","","")
	if err != nil {
		panic(err)
	}
	digest, layers, err := fetchLayers(reg, &types.Image{
		Registry: "https://mcr.microsoft.com",
		Remote:   "dotnet/core/sdk",
		Tag:      "3.1.100",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(digest, layers)

}
