package rpm

import (
	"os"
	"os/exec"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/component"
	"github.com/stackrox/scanner/pkg/tarutil"
)

// WrapAnalyzer wraps the generic analyzer function with one that determines if the language
// component was added via RPM
func WrapAnalyzer() func(tarutil.FilesMap, []analyzer.Analyzer) ([]*component.Component, error) {
	return func(files tarutil.FilesMap, analyzers []analyzer.Analyzer) ([]*component.Component, error) {
		components, err := analyzer.Analyze(files, analyzers)
		if err != nil {
			return nil, err
		}

		f, hasFile := files[packages]
		if !hasFile {
			return components, nil
		}
		matcher, finish, err := GetIsNotProvidedByRPMPackage(f)
		if err != nil {
			return nil, err
		}
		defer finish()

		locationAlreadyChecked := make(map[string]bool)
		for _, c := range components {
			normalizedLocation := stringutils.GetUpTo(c.Location, ":")
			fromPackageManager, ok := locationAlreadyChecked[normalizedLocation]
			if ok {
				c.FromPackageManager = fromPackageManager
				continue
			}
			c.FromPackageManager = matcher(normalizedLocation)
			locationAlreadyChecked[normalizedLocation] = c.FromPackageManager
		}
		return components, nil
	}
}

// GetIsNotProvidedByRPMPackage uses the given package contents (expected to be an RPM Berkeley DB)
// to return:
// * a function which returns if the given file path is not provided by an RPM package.
// * a function to be called once the package contents are no longer needed which cleans up any used resources.
// * an error.
func GetIsNotProvidedByRPMPackage(packagesContents []byte) (func(string) bool, func(), error) {
	if packagesContents == nil {
		// Default return always says the given path is not provided by an RPM package.
		return func(string) bool { return true }, func() {}, nil
	}

	// Write the required "Packages" file to disk
	tmpDir, err := os.MkdirTemp("", "rpm")
	if err != nil {
		log.WithError(err).Error("could not create temporary folder for RPM detection")
		return nil, nil, err
	}

	err = os.WriteFile(tmpDir+"/Packages", packagesContents, 0700)
	if err != nil {
		log.WithError(err).Error("could not create temporary file for RPM detection")
		return nil, nil, err
	}

	return func(path string) bool {
		// We need the full path of the file.
		// When we originally extract the file, the `/` prefix is removed.
		// Add it back here.
		fullPath := "/" + path

		cmd := exec.Command("rpm",
			`--dbpath`, tmpDir,
			`-q`, `--whatprovides`, fullPath)

		if err := cmd.Run(); err != nil {
			// When an RPM package does not provide a file, the expected output has
			// status code 1.
			if exitError, ok := err.(*exec.ExitError); ok && exitError.ExitCode() == 1 {
				// RPM does NOT provide this package.
				return true
			}

			log.WithError(err).Errorf("unexpected error when determining if %s belongs to an RPM package", fullPath)
			// Upon error, say no RPM package provides this file.
			return true
		}

		// The command exited properly, which implies the file IS provided by an RPM package.
		return false

	}, func() { _ = os.RemoveAll(tmpDir) }, nil
}
