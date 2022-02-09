package main

import (
	"fmt"
)

// ImageAndID encapsulates a name and id pair for a sample image
type ImageAndID struct {
	Name string
	ID   string
}

// FullName returns the name including the digest
func (i ImageAndID) FullName() string {
	return fmt.Sprintf("%s@%s", i.Name, i.ID)
}

var (
	// ImageNames lists the top images from DockerHub.
	ImageNames = []ImageAndID{
		{"openshift/origin-metrics-hawkular-metrics", "sha256:eb0b65bf9a1ad0de8aca482c3bb79d8ad28b3bac3a28670bf44b38f1a11fef68"},
		{"openshift/origin-metrics-heapster", "sha256:0b7a2cc26e9c29580dee994a7dc2e82665dce91833f76a9d099fce00f4c21f15"},
		{"openshift/origin-node", "sha256:547322a57e26296c335e7048ba9cb06041e124d611245e03ea45b6e497c9c248"},
		{"openshift/origin-pod", "sha256:d61921e97f2850bcff984990dae93e9e4ada5b34e2c0f70985e84b91d4090880"},
		{"openshift/origin-service-catalog", "sha256:cc22f2af68a261c938fb1ec9a9e94643eba23a3bb8c9e22652139f80ee57681b"},
		{"openshift/wildfly-100-centos7", "sha256:0b1f4092df0a24bb67e34094bc0332b8412bcd4ea9b054fbf678eabfcb0b8ad3"},
		{"openshift/wildfly-101-centos7", "sha256:7775d40f77e22897dc760b76f1656f67ef6bd5561b4d74fbb030b977f61d48e8"},
		{"openshift/wildfly-110-centos7", "sha256:5828134f4b215ab02ccc832a5f17f06c5b5d8c71c11f138cd7461e3f246b1929"},
		{"openshift/wildfly-120-centos7", "sha256:a1fbd1b235102ae18344527b44201c34ad4c2181b0b4cbf295b1a8f0cbde8e73"},
		{"openshift/wildfly-81-centos7", "sha256:9f66d9efe2565d1799219f2a3e07373e62eb2d2cea323596a02aaf00c3ee0750"},
		{"openshift/wildfly-90-centos7", "sha256:ea374cc4aee82ed9afe41ce34122136d5837f04d8009a27e4baffbb7980454ff"},
		{"openshiftdemos/gogs", "sha256:ca56061043c21500f587e938321d4f0ae38a74d4a9dd50ae70f8b628d19e0f32"},
		{"openstec/itc-conector", "sha256:0662ed5a3481d709122a8a994ed8ef3b49bd1624493f68c0718761296efdba16"},
		{"openstec/itc-conector", "sha256:35b4b386f0540198ae71355ed0af9cfdc61e07538caafe17ff2339636827f1aa"},
		{"openstec/q-manager", "sha256:21899fc6a12aa0c18bb2ee9b8ed936405cdbca52d83042db341ec7561878fdb5"},
		{"openstf/stf", "sha256:b2a6c649773d89ca2d1939c603170fd48232b5860dbefa1c4d7e567a9c7d50c9"},
		{"openstorage/stork", "sha256:f6cf243e98e23e83eff21e67996bd4d7a8264833975fc36f72eab11f4a497f61"},
		{"opensuse/leap", "sha256:50aaf6277e48469b312cdf6d98aa220219809e99079d090a2613a055f3a969f0"},
		{"opensuse/tumbleweed", "sha256:2123d9fa3c022d2567a3a9081bd6be1e126b3847090882893eb0704994020f7c"},
		{"openzim/uploader", "sha256:68d2754e2356782b50c60ea438ca3afc860275dc6f425f423b72d0c4216ee5d9"},
		{"openzipkin/zipkin", "sha256:651038f7a904bdcffb7176b4a4430e8c8fdc890326a7e4a470d388f8c6c755a1"},
		{"openzipkin/zipkin", "sha256:80c5aef490522ffd3f377fb670fdb153e0455d15e3031a3d605b3b03aaf95e04"},
		{"openzipkin/zipkin-dependencies", "sha256:f1039a688aee87557cda2de78364caeada41e4f6b851b2de13557f978d06fa69"},
		{"openzipkin/zipkin-dependencies", "sha256:fc5b2dd12516953391ca3a42dc53008ab4fe01be913432b1fad07d8579b8e964"},
		{"operable/cog", "sha256:7701ed49e5aededdad97f2e193fcb48a46593f2bd68663150715601ebda056d3"},
		{"orangecloudfoundry/cf-ops-automation", "sha256:3efff86f94f13a77155f206aeb74edaf7c83801d15f20c18020aa0f075ae0b4d"},
		// Crash.
		{"orangecloudfoundry/concourse-fly-resource", "sha256:fd4688d36cfb431f6de1e6bbb2317bce768835795f4f090fd6b0a7fc21a7a915"},
		{"orangecloudfoundry/git-branch-heads-resource", "sha256:8ced680d282a2eb1b0a47ad6f5a22879277c6d28bb5980747d64f89001630d8a"},
	}
)
