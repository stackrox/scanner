package detection

import (
	"testing"

	"github.com/stackrox/scanner/database"
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
