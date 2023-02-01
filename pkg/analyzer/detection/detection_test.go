package detection

import (
	"reflect"
	"testing"

	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/pkg/analyzer"
	"github.com/stackrox/scanner/pkg/tarutil"
)

func Test_isCertifiedRHELNamespace(t *testing.T) {
	type args struct {
		namespace *database.Namespace
	}
	tests := []struct {
		name      string
		namespace *database.Namespace
		want      bool
	}{
		{
			namespace: nil,
			want:      false,
		},
		{
			namespace: &database.Namespace{
				Name: "rhel",
			},
			want: true,
		},
		{
			namespace: &database.Namespace{
				Name: "rhcos",
			},
			want: true,
		},
		{
			namespace: &database.Namespace{
				Name: "notrhel",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCertifiedRHELNamespace(tt.namespace); got != tt.want {
				t.Errorf("isCertifiedRHELNamespace() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getHardcodedRHCOSContentSets(t *testing.T) {
	type args struct {
		files analyzer.Files
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
		// If specified, sets args.files["etc/os-release"].
		osReleaseContents string
	}{
		{
			name: "when ocp/4.9 then valid",
			osReleaseContents: `
NAME="Red Hat Enterprise Linux CoreOS"
VERSION="49.84.202212201621-0"
ID="rhcos"
ID_LIKE="rhel fedora"
VERSION_ID="4.9"
PLATFORM_ID="platform:el8"
PRETTY_NAME="Red Hat Enterprise Linux CoreOS 49.84.202212201621-0 (Ootpa)"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:redhat:enterprise_linux:8::coreos"
HOME_URL="https://www.redhat.com/"
DOCUMENTATION_URL="https://docs.openshift.com/container-platform/4.9/"
BUG_REPORT_URL="https://bugzilla.redhat.com/"
REDHAT_BUGZILLA_PRODUCT="OpenShift Container Platform"
REDHAT_BUGZILLA_PRODUCT_VERSION="4.9"
REDHAT_SUPPORT_PRODUCT="OpenShift Container Platform"
REDHAT_SUPPORT_PRODUCT_VERSION="4.9"
OPENSHIFT_VERSION="4.9"
RHEL_VERSION="8.4"
OSTREE_VERSION='49.84.202212201621-0'
`,
			want: []string{
				"rhel-8-for-x86_64-baseos-eus-rpms__8_DOT_4",
				"rhel-8-for-x86_64-appstream-eus-rpms__8_DOT_4",
				"rhel-8-for-x86_64-nfv-tus-rpms__8_DOT_4",
				"fast-datapath-for-rhel-8-x86_64-rpms",
				"rhocp-4.9-for-rhel-8-x86_64-rpms",
				"advanced-virt-for-rhel-8-x86_64-eus-rpms",
			},
		},
		{
			name: "when ocp/4.7 then should not use advanced-virt",
			osReleaseContents: `
ID="rhcos"
VERSION_ID="4.7"
OPENSHIFT_VERSION="4.7"
RHEL_VERSION="8.4"
`,
			want: []string{
				"rhel-8-for-x86_64-baseos-eus-rpms__8_DOT_4",
				"rhel-8-for-x86_64-appstream-eus-rpms__8_DOT_4",
				"rhel-8-for-x86_64-nfv-tus-rpms__8_DOT_4",
				"fast-datapath-for-rhel-8-x86_64-rpms",
				"rhocp-4.7-for-rhel-8-x86_64-rpms",
			},
		},
		{
			name: "when not RHCOS then error",
			osReleaseContents: `
ID="rhel"
VERSION_ID="4.9"
OPENSHIFT_VERSION="4.9"
RHEL_VERSION="8.4"
`,
			wantErr: true,
		},
		{
			name: "when missing ID then error",
			osReleaseContents: `
VERSION_ID="4.9"
OPENSHIFT_VERSION="4.9"
RHEL_VERSION="8.4"
`,
			wantErr: true,
		},
		{
			name: "when version 4.6 then ignored",
			osReleaseContents: `
ID=rhcos
VERSION_ID="4.6"
OPENSHIFT_VERSION="A.B"
RHEL_VERSION="X.Y"
`,
			wantErr: false,
		},
		{
			name: "when version 4.10 then ignored",
			osReleaseContents: `
ID=rhcos
VERSION_ID="4.10"
OPENSHIFT_VERSION="A.B"
RHEL_VERSION="X.Y"
`,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		if tt.osReleaseContents != "" {
			tt.args.files = tarutil.CreateNewLayerFiles(map[string]analyzer.FileData{
				"etc/os-release": {Contents: []byte(tt.osReleaseContents)},
			})
		}
		t.Run(tt.name, func(t *testing.T) {
			got, err := getHardcodedRHCOSContentSets(tt.args.files)
			if (err != nil) != tt.wantErr {
				t.Errorf("getHardcodedRHCOSContentSets() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getHardcodedRHCOSContentSets() got = %v, want %v", got, tt.want)
			}
		})
	}
}
