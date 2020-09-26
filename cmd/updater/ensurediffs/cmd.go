package ensurediffs

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/scanner/database"
)

func parseVulnsFromDir(dir string) (map[string]set.StringSet, error) {
	osVulnsPath := filepath.Join(dir, "os_vulns.json")
	data, err := ioutil.ReadFile(osVulnsPath)
	if err != nil {
		return nil, err
	}
	var vulns []database.Vulnerability
	if err := json.Unmarshal(data, &vulns); err != nil {
		return nil, err
	}
	namespaceMap := make(map[string]set.StringSet)
	for _, v := range vulns {
		vulnSet, ok := namespaceMap[v.Namespace.Name]
		if !ok {
			vulnSet = set.NewStringSet()
			namespaceMap[v.Namespace.Name] = vulnSet
		}
		vulnSet.Add(v.Name)
	}
	return namespaceMap, nil
}

func ensureDiffs(oldGenesis, oldGenesisDiff, newGenesis string) error {
	oldGenesisMap, err := parseVulnsFromDir(oldGenesis)
	if err != nil {
		return err
	}
	oldGenesisDiffMap, err := parseVulnsFromDir(oldGenesisDiff)
	if err != nil {
		return err
	}

	// Merge oldGenesisDiffMap on top of oldGenesisMap
	for namespace := range oldGenesisDiffMap {
		oldGenesisMap[namespace] = oldGenesisDiffMap[namespace].Union(oldGenesisMap[namespace])
	}

	newGenesisDumpMap, err := parseVulnsFromDir(newGenesis)
	if err != nil {
		return err
	}

	if len(oldGenesisMap) > len(newGenesisDumpMap) {
		for namespace := range oldGenesisMap {
			if _, ok := newGenesisDumpMap[namespace]; !ok {
				log.Errorf("Found namespace %s in old dump, but not new dump")
			}
		}
		for namespace := range newGenesisDumpMap {
			if _, ok := oldGenesisMap[namespace]; !ok {
				log.Errorf("Found namespace %s in new dump, but not in old dump")
			}
		}
		return errors.New("old dump has more namespaces than new dump")
	}

	var fatalDiff bool
	for namespace := range oldGenesisMap {
		diff := oldGenesisMap[namespace].Difference(newGenesisDumpMap[namespace])
		if len(diff) > 0 {
			fatalDiff = true
			for vuln := range diff {
				log.Errorf("Found %v in namespace %v, but not in new dump", vuln, namespace)
			}
		}
	}
	if fatalDiff {
		return errors.New("found vulns in old dump that were not in new dump. See logs")
	}
	return nil
}

func Command() *cobra.Command {
	var (
		oldGenesis     string
		oldGenesisDiff string
		newGenesis     string
	)

	c := &cobra.Command{
		Use: "ensure-diffs",
		RunE: func(cmd *cobra.Command, args []string) error {
			if stringutils.AtLeastOneEmpty(oldGenesis, oldGenesisDiff, newGenesis) {
				return cmd.Help()
			}
			return ensureDiffs(oldGenesis, oldGenesisDiff, newGenesis)
		},
	}
	c.Flags().StringVar(&oldGenesis, "old-genesis", "", "")
	c.Flags().StringVar(&oldGenesisDiff, "old-genesis-diff", "", "")
	c.Flags().StringVar(&newGenesis, "new-genesis", "", "")

	return c
}
