package orchestratorscan

import (
	"regexp"
	"strings"

	rpmVersion "github.com/knqyf263/go-rpm-version"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/scanner/api/v1/convert"
)

var (
	versionFamilyRegex = regexp.MustCompile(`^(3\.11|[4-9][0-9]*)\.[0-9]+`)
	// Version families we can compare directly.
	// releaseDateRegex = regexp.MustCompile(`-[0-9]{12}(?:[.-].*)?$`)

	// qualifiedVersionFamilies = set.StringSet{"4.0": {}, "4.1": {}, "4.2": {}, "4.3": {}, "3.11": {}}
)

type openShiftVersion struct {
	version       rpmVersion.Version
	releaseDate   string
	versionFamily string
}

func newOpenShiftVersion(version string) (*openShiftVersion, error) {
	version = strings.Trim(version, "v")

	matched := versionFamilyRegex.FindStringSubmatch(version)
	if len(matched) != 2 {
		return nil, errors.Errorf("unrecognized OpenShift version: %s", version)
	}
	ver, err := convert.TruncateVersion(version)
	if err != nil {
		return nil, errors.Wrap(err, "unrecognized OpenShift version")
	}
	return &openShiftVersion{
		version:       rpmVersion.NewVersion(ver),
		versionFamily: matched[1],
		releaseDate:   "",
	}, nil
}

func (o *openShiftVersion) CreateCPE() string {
	return "cpe:/a:redhat:openshift:" + o.versionFamily
}

func (o *openShiftVersion) CreatePkgName() string {
	pkgName := "openshift-hyperkube"
	if o.versionFamily == "3.11" {
		return "atomic-" + pkgName
	}
	return pkgName
}

func (o *openShiftVersion) LessThan(ver string) (bool, error) {
	// if qualifiedVersionFamilies.Contains(o.versionFamily) {
	ver, err := convert.TruncateVersion(ver)
	if err != nil {
		return false, err
	}
	return o.version.LessThan(rpmVersion.NewVersion(ver)), nil
	// }
}

func getFixedVersion(ver string) string {
	if ver == "" {
		return ver
	}
	fixedBy, err := convert.TruncateVersion(ver)
	utils.Should(err)
	return fixedBy
}
