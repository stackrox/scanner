package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/stackrox/scanner/pkg/ghsa"
	"github.com/stackrox/scanner/pkg/ghsa/crawler"
)

func main() {
	if err := mainCmd(); err != nil {
		panic(err)
	}
}

func mainCmd() error {
	var outputDir string
	flag.StringVar(&outputDir, "out", "", "output directory to write advisory data to")
	flag.Parse()

	if outputDir == "" {
		return errors.New("no output directory specified")
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return errors.Wrap(err, "ensuring output directory exists")
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return errors.New("GITHUB_TOKEN is not set")
	}

	c := crawler.NewCrawler(token)

	vulns, err := c.FetchAll(context.Background())
	if err != nil {
		return errors.Wrap(err, "crawling GHSA database")
	}

	advisories := ghsa.GroupByAdvisory(vulns)

	for _, adv := range advisories {
		if err := writeAdvisory(adv, outputDir); err != nil {
			return errors.Wrap(err, "writing vulnerability")
		}
	}
	return nil
}

func writeAdvisory(adv *ghsa.AdvisoryWithVulnerabilities, outputDir string) error {
	yamlBytes, err := yaml.Marshal(adv)
	if err != nil {
		return errors.Wrap(err, "marshaling YAML")
	}

	targetFilePath := filepath.Join(outputDir, adv.ID+".yaml")

	f, err := os.OpenFile(targetFilePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0755)
	if err != nil {
		return err
	}
	fileToClose := f
	defer func() {
		if fileToClose != nil {
			_ = fileToClose.Close()
		}
	}()

	if _, err := f.Write(yamlBytes); err != nil {
		return errors.Wrap(err, "writing to file")
	}

	fileToClose = nil
	if err := f.Close(); err != nil {
		return errors.Wrap(err, "closing file")
	}
	return nil
}
