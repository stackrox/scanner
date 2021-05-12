///////////////////////////////////////////////////
// Influenced by ClairCore under Apache 2.0 License
// https://github.com/quay/claircore
///////////////////////////////////////////////////

package v1

import (
	"strconv"

	rpmVersion "github.com/knqyf263/go-rpm-version"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/stringutils"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/versionfmt/rpm"
	"github.com/stackrox/scanner/pkg/types"
)

const (
	timeFormat = "2006-01-02T15:04Z"
)

// addRHELv2Vulns appends vulnerabilities found during RHELv2 scanning.
// RHELv2 scanning performs the scanning/analysis needed to be
// certified as part of Red Hat's Scanner Certification Program.
// The returned bool indicates if full certified scanning was performed.
// This is typically only `false` for images without proper CPE information.
func addRHELv2Vulns(db database.Datastore, layer *Layer) (bool, error) {
	layers, err := db.GetRHELv2Layers(layer.Name)
	if err != nil {
		return false, err
	}

	cpesExist := shareCPEs(layers)

	pkgEnvs, records := getRHELv2PkgData(layers)

	vulns, err := db.GetRHELv2Vulnerabilities(records)
	if err != nil {
		return false, err
	}

	for _, pkgEnv := range pkgEnvs {
		pkg := pkgEnv.Pkg

		version := pkg.Version
		if version != "" {
			version += "." + pkg.Arch
		}

		feature := Feature{
			Name:          pkg.Name,
			NamespaceName: layer.NamespaceName,
			VersionFormat: rpm.ParserName,
			Version:       version,
			AddedBy:       pkgEnv.AddedBy,
		}

		pkgVersion := rpmVersion.NewVersion(pkg.Version)
		pkgArch := pkg.Arch
		fixedBy := pkgVersion

		// Database query results need more filtering.
		// Need to ensure:
		// 1. The package's version is less than the vuln's fixed-in version, if present.
		// 2. The ArchOperation passes.
		for _, vuln := range vulns[pkg.ID] {
			if len(vuln.PackageInfos) != 1 {
				log.Warnf("Unexpected number of package infos for vuln %q (%d != %d); Skipping...", vuln.Name, len(vuln.PackageInfos), 1)
				continue
			}
			vulnPkgInfo := vuln.PackageInfos[0]

			if len(vulnPkgInfo.Packages) != 1 {
				log.Warnf("Unexpected number of packages for vuln %q (%d != %d); Skipping...", vuln.Name, len(vulnPkgInfo.Packages), 1)
				continue
			}
			vulnPkg := vulnPkgInfo.Packages[0]

			// Assume the vulnerability is not fixed.
			// In that case, all versions are affected.
			affectedVersion := true
			var vulnVersion *rpmVersion.Version
			if vulnPkgInfo.FixedInVersion != "" {
				// The vulnerability is fixed. Determine if this package is affected.
				vulnVersion = rpmVersionPtr(rpmVersion.NewVersion(vulnPkgInfo.FixedInVersion))
				affectedVersion = pkgVersion.LessThan(*vulnVersion)
			}

			// Compare the package's architecture to the affected architecture.
			affectedArch := vulnPkgInfo.ArchOperation.Cmp(pkgArch, vulnPkg.Arch)

			if affectedVersion && affectedArch {
				feature.Vulnerabilities = append(feature.Vulnerabilities, rhelv2ToVulnerability(vuln, feature.NamespaceName))

				if vulnVersion != nil && vulnVersion.GreaterThan(fixedBy) {
					fixedBy = *vulnVersion
				}
			}
		}

		if fixedBy.GreaterThan(pkgVersion) {
			feature.FixedBy = fixedBy.String()
		}

		layer.Features = append(layer.Features, feature)
	}

	return cpesExist, nil
}

func rpmVersionPtr(ver rpmVersion.Version) *rpmVersion.Version {
	return &ver
}

// shareRepos takes repository definition and share it with other layers
// where repositories are missing.
// Returns a bool indicating if any CPEs exist.
func shareCPEs(layers []*database.RHELv2Layer) bool {
	var cpesExist bool

	// User's layers build on top of Red Hat images doesn't have a repository definition.
	// We need to share CPE repo definition to all layer where CPEs are missing
	var previousCPEs []string
	for i := 0; i < len(layers); i++ {
		if len(layers[i].CPEs) != 0 {
			previousCPEs = layers[i].CPEs

			// Some layer has CPEs.
			cpesExist = true
		} else {
			layers[i].CPEs = append(layers[i].CPEs, previousCPEs...)
		}
	}

	// Tha same thing has to be done in reverse
	// example:
	//   Red Hat's base images doesn't have repository definition
	//   We need to get them from layer[i+1]
	for i := len(layers) - 1; i >= 0; i-- {
		if len(layers[i].CPEs) != 0 {
			previousCPEs = layers[i].CPEs
		} else {
			layers[i].CPEs = append(layers[i].CPEs, previousCPEs...)
		}
	}

	return cpesExist
}

func getRHELv2PkgData(layers []*database.RHELv2Layer) (map[int]*database.RHELv2PackageEnv, []*database.RHELv2Record) {
	pkgEnvs := make(map[int]*database.RHELv2PackageEnv)

	// Find all packages that were ever added to the image
	// labelled with the layer hash that introduced it.
	for _, layer := range layers {
		for _, pkg := range layer.Pkgs {
			if _, ok := pkgEnvs[pkg.ID]; !ok {
				pkgEnvs[pkg.ID] = &database.RHELv2PackageEnv{
					Pkg:     pkg,
					AddedBy: layer.Hash,
					CPEs:    layer.CPEs,
				}
			}
		}
	}

	// Look for the packages that still remain in the final image.
	// Loop from highest layer to base in search of the latest version of
	// the packages database.
	for i := len(layers) - 1; i >= 0; i-- {
		if len(layers[i].Pkgs) != 0 {
			// Found the latest version of `var/lib/rpm/Packages`
			// This has the final version of all the packages in this image.
			finalPkgs := set.NewIntSet()
			for _, pkg := range layers[i].Pkgs {
				finalPkgs.Add(pkg.ID)
			}

			for pkgID := range pkgEnvs {
				// Remove packages that were in lower layers, but not at the highest.
				if !finalPkgs.Contains(pkgID) {
					delete(pkgEnvs, pkgID)
				}
			}

			break
		}
	}

	// Create a record for each pkgEnvironment for each CPE.
	var records []*database.RHELv2Record

	for _, pkgEnv := range pkgEnvs {
		if len(pkgEnv.CPEs) == 0 {
			records = append(records, &database.RHELv2Record{
				Pkg: pkgEnv.Pkg,
			})

			continue
		}

		for _, cpe := range pkgEnv.CPEs {
			records = append(records, &database.RHELv2Record{
				Pkg: pkgEnv.Pkg,
				CPE: cpe,
			})
		}
	}

	return pkgEnvs, records
}

func rhelv2ToVulnerability(vuln *database.RHELv2Vulnerability, namespace string) Vulnerability {
	var cvss2 types.MetadataCVSSv2
	if vuln.CVSSv2 != "" {
		scoreStr, vector := stringutils.Split2(vuln.CVSSv2, "/")
		score, err := strconv.ParseFloat(scoreStr, 64)
		if err != nil {
			log.Errorf("Unable to parse CVSSv2 score from RHEL vulnerability %s: %s", vuln.Name, vuln.CVSSv2)
		} else {
			cvss2Ptr, err := types.ConvertCVSSv2(vector)
			if err != nil {
				log.Errorf("Unable to parse CVSSv2 vector from RHEL vulnerability %s: %s", vuln.Name, vuln.CVSSv2)
			} else {
				if score != cvss2Ptr.Score {
					log.Warnf("Given CVSSv2 score and computed score differ for RHEL vulnerability %s: %f != %f. Using given score...", vuln.Name, score, cvss2Ptr.Score)
					cvss2Ptr.Score = score
				}

				cvss2 = *cvss2Ptr
			}
		}
	}

	var cvss3 types.MetadataCVSSv3
	if vuln.CVSSv3 != "" {
		scoreStr, vector := stringutils.Split2(vuln.CVSSv3, "/")
		score, err := strconv.ParseFloat(scoreStr, 64)
		if err != nil {
			log.Errorf("Unable to parse CVSSv3 score from RHEL vulnerability %s: %s", vuln.Name, vuln.CVSSv3)
		} else {
			cvss3Ptr, err := types.ConvertCVSSv3(vector)
			if err != nil {
				log.Errorf("Unable to parse CVSSv3 vector from RHEL vulnerability %s: %s", vuln.Name, vuln.CVSSv3)
			} else {
				if score != cvss3Ptr.Score {
					log.Warnf("Given CVSSv3 score and computed score differ for RHEL vulnerability %s: %f != %f. Using given score...", vuln.Name, score, cvss3Ptr.Score)
					cvss3Ptr.Score = score
				}

				cvss3 = *cvss3Ptr
			}
		}
	}

	var publishedTime, modifiedTime string
	if !vuln.Issued.IsZero() {
		publishedTime = vuln.Issued.Format(timeFormat)
	}
	if !vuln.Updated.IsZero() {
		modifiedTime = vuln.Updated.Format(timeFormat)
	}

	metadata := map[string]interface{}{
		"Red Hat": &types.Metadata{
			PublishedDateTime:    publishedTime,
			LastModifiedDateTime: modifiedTime,
			CVSSv2:               cvss2,
			CVSSv3:               cvss3,
		},
	}

	return Vulnerability{
		Name:          vuln.Name,
		NamespaceName: namespace,
		Description:   vuln.Description,
		Link:          vuln.Link,
		Severity:      vuln.Severity,
		Metadata:      metadata,
		// It is guaranteed there is 1 and only one element in `vuln.PackageInfos`.
		FixedBy: vuln.PackageInfos[0].FixedInVersion, // Empty string if not fixed.
	}
}
