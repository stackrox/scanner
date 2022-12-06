package rhcos

const (
	cpeManifests = `usr/share/buildinfo`
)

func RequiredFilenames() []string {
	return append([]string{cpeManifests}) // FIXME: Nothing is aware of CPE manifests yet, e.g. SingletonOSMatcher
}
