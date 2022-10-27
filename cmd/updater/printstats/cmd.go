package printstats

import (
	"fmt"
	"sort"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/cmd/updater/common"
	"github.com/stackrox/scanner/pkg/vulndump"
)

// Command defines the `print-stats` command.
func Command() *cobra.Command {
	c := &cobra.Command{
		Use:  "print-stats",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			dumpFile := args[0]
			zipR, _, err := common.OpenGenesisDumpAndExtractManifest(dumpFile)
			if err != nil {
				return errors.Wrap(err, "loading dump")
			}
			defer utils.IgnoreError(zipR.Close)
			vulns, err := vulndump.LoadOSVulnsFromDump(&zipR.Reader)
			if err != nil {
				return errors.Wrap(err, "loading os vulns from dump")
			}
			vulnsByNS := make(map[string]int)
			for _, vuln := range vulns {
				vulnsByNS[vuln.Namespace.Name]++
			}
			fmt.Print("Vuln counts by namespace:\n")
			keys := make([]string, 0, len(vulnsByNS))
			for key := range vulnsByNS {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Printf("%s\t%d\n", k, vulnsByNS[k])
			}
			fmt.Printf("Total vulns: %d", len(vulns))
			return nil
		},
	}

	return c
}
