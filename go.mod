module github.com/stackrox/scanner

go 1.24

toolchain go1.24.4

require (
	cloud.google.com/go/storage v1.56.0
	github.com/NYTimes/gziphandler v1.1.1
	github.com/PuerkitoBio/goquery v1.9.3
	github.com/ckaznocha/protoc-gen-lint v0.3.0
	github.com/containers/image/v5 v5.36.1
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc
	github.com/distribution/reference v0.6.0
	github.com/docker/distribution v2.8.3+incompatible
	github.com/facebookincubator/nvdtools v0.1.5
	github.com/go-git/go-billy/v5 v5.6.2
	github.com/go-git/go-git/v5 v5.16.2
	github.com/google/go-cmp v0.7.0
	github.com/gorilla/mux v1.8.1
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.1-0.20210315223345-82c243799c99
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.1
	github.com/guregu/null v4.0.0+incompatible
	github.com/hashicorp/go-version v1.7.0
	github.com/heroku/docker-registry-client v0.0.0
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f
	github.com/knqyf263/go-rpm-version v0.0.0-20220614171824-631e686d1075
	github.com/lib/pq v1.10.9
	github.com/mailru/easyjson v0.9.0
	github.com/mholt/archiver/v3 v3.5.1
	github.com/mitchellh/hashstructure/v2 v2.0.2
	github.com/opencontainers/go-digest v1.0.0
	github.com/pborman/uuid v1.2.1
	github.com/pkg/errors v0.9.1
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10
	github.com/prometheus/client_golang v1.23.0
	github.com/quay/goval-parser v0.8.8
	github.com/remind101/migrate v0.0.0-20170729031349-52c1edff7319
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.9.1
	github.com/stackrox/dotnet-scraper v0.0.0-20201023051640-72ef543323dd
	github.com/stackrox/istio-cves v0.0.0-20221007013142-0bde9b541ec8
	github.com/stackrox/k8s-cves v0.0.0-20220818200547-7d0d1420c58d
	github.com/stackrox/rox v0.0.0-20210914215712-9ac265932e28
	github.com/stretchr/testify v1.10.0
	go.etcd.io/bbolt v1.4.2
	go.uber.org/goleak v1.3.0
	go.uber.org/ratelimit v0.3.1
	go.yaml.in/yaml/v3 v3.0.4
	golang.org/x/exp v0.0.0-20241217172543-b2144cdd0a67
	golang.org/x/sys v0.35.0
	google.golang.org/api v0.245.0
	google.golang.org/genproto/googleapis/api v0.0.0-20250721164621-a45f3dfb1074
	google.golang.org/grpc v1.75.0
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.5.1
	google.golang.org/protobuf v1.36.7
	sigs.k8s.io/yaml v1.6.0
)

require (
	cel.dev/expr v0.24.0 // indirect
	cloud.google.com/go v0.121.4 // indirect
	cloud.google.com/go/auth v0.16.3 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.7.0 // indirect
	cloud.google.com/go/iam v1.5.2 // indirect
	cloud.google.com/go/monitoring v1.24.2 // indirect
	dario.cat/mergo v1.0.2 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp v1.29.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric v0.53.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/internal/resourcemapping v0.53.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/ProtonMail/go-crypto v1.1.6 // indirect
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/andybalholm/cascadia v1.3.2 // indirect
	github.com/benbjohnson/clock v1.3.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/cfssl v1.6.5 // indirect
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/cncf/xds/go v0.0.0-20250501225837-2ac532fd4443 // indirect
	github.com/containers/libtrust v0.0.0-20230121012942-c1716e8a8d01 // indirect
	github.com/containers/ocicrypt v1.2.1 // indirect
	github.com/containers/storage v1.59.1 // indirect
	github.com/cyphar/filepath-securejoin v0.4.1 // indirect
	github.com/docker/docker v28.3.3+incompatible // indirect
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/dsnet/compress v0.0.2-0.20210315054119-f66993602bf5 // indirect
	github.com/emicklei/go-restful/v3 v3.11.0 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/envoyproxy/go-control-plane/envoy v1.32.4 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.2.1 // indirect
	github.com/evanphx/json-patch v5.7.0+incompatible // indirect
	github.com/facebookincubator/flog v0.0.0-20190930132826-d2511d0ce33c // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/ghodss/yaml v1.0.1-0.20190212211648-25d852aebe32 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-jose/go-jose/v4 v4.1.1 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/jsonpointer v0.21.0 // indirect
	github.com/go-openapi/jsonreference v0.21.0 // indirect
	github.com/go-openapi/swag v0.23.1 // indirect
	github.com/gofrs/uuid v4.4.0+incompatible // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/glog v1.2.5 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/certificate-transparency-go v1.2.1 // indirect
	github.com/google/gnostic-models v0.6.9-0.20230804172637-c7be7c783f49 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.6 // indirect
	github.com/googleapis/gax-go/v2 v2.15.0 // indirect
	github.com/graph-gophers/graphql-go v1.5.0 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jmoiron/sqlx v1.3.5 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/klauspost/pgzip v1.2.6 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nwaples/rardecode v1.1.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/openshift/api v0.0.0-20231117201702-2ea16bbab164 // indirect
	github.com/openshift/client-go v0.0.0-20230926161409-848405da69e1 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pierrec/lz4/v4 v4.1.15 // indirect
	github.com/pjbgf/sha1cd v0.3.2 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.65.0 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/sergi/go-diff v1.3.2-0.20230802210424-5b0b94c5c0d3 // indirect
	github.com/skeema/knownhosts v1.3.1 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/spiffe/go-spiffe/v2 v2.5.0 // indirect
	github.com/tkuchiki/go-timezone v0.2.3 // indirect
	github.com/ulikunitz/xz v0.5.12 // indirect
	github.com/weppos/publicsuffix-go v0.30.1-0.20230620154423-38c92ad2d5c6 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	github.com/zeebo/errs v1.4.0 // indirect
	github.com/zmap/zcrypto v0.0.0-20230310154051-c8b263fd8300 // indirect
	github.com/zmap/zlint/v3 v3.5.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/detectors/gcp v1.36.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.61.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.61.0 // indirect
	go.opentelemetry.io/otel v1.37.0 // indirect
	go.opentelemetry.io/otel/metric v1.37.0 // indirect
	go.opentelemetry.io/otel/sdk v1.37.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.37.0 // indirect
	go.opentelemetry.io/otel/trace v1.37.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/mock v0.4.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/oauth2 v0.30.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/term v0.33.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	golang.org/x/time v0.12.0 // indirect
	golang.stackrox.io/grpc-http1 v0.3.12 // indirect
	google.golang.org/genproto v0.0.0-20250603155806-513f23925822 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250728155136-f173205681a0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/api v0.29.3 // indirect
	k8s.io/apimachinery v0.29.3 // indirect
	k8s.io/client-go v0.29.3 // indirect
	k8s.io/klog/v2 v2.120.1 // indirect
	k8s.io/kube-openapi v0.0.0-20240105020646-a37d4de58910 // indirect
	k8s.io/utils v0.0.0-20240102154912-e7106e64919e // indirect
	nhooyr.io/websocket v1.8.11 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
)

// @stackrox/scanner
// Due to github.com/stackrox/rox dependency.
// BE SURE TO KEEP THIS UP-TO-DATE.
replace (
	github.com/facebookincubator/nvdtools => github.com/stackrox/nvdtools v0.0.0-20231111002313-57e262e4797e

	github.com/heroku/docker-registry-client => github.com/stackrox/docker-registry-client v0.2.1

	// The current latest version of github.com/mholt/archiver/v3 (v3.5.1) suffers from CVE-2024-0406.
	// There is currently a PR in place to resolve it (https://github.com/mholt/archiver/pull/396),
	// but it has not had much attention recently.
	// Just replace our usage of github.com/mholt/archiver/v3 with github.com/anchore/archiver/v3 (v3.5.2)
	// so static vulnerability scanners will be happy.
	// This version (probably) fixes CVE-2024-0406, but we are also unaffected by that vulnerability anyway,
	// as we do not use [(*archiver.Tar).Unarchive()], so it doesn't really matter.
	// What is important, though, is the code changes between github.com/mholt/archiver/v3 v3.5.1
	// and github.com/anchore/archiver/v3 v3.5.2 only touch the [(*archiver.Tar).Unarchive()] path,
	// and nothing we use. See https://github.com/mholt/archiver/compare/v3.5.1...anchore:archiver:v3.5.2
	// for more details of the exact difference.
	github.com/mholt/archiver/v3 => github.com/anchore/archiver/v3 v3.5.2

	github.com/operator-framework/helm-operator-plugins => github.com/stackrox/helm-operator v0.0.12-0.20230825152000-1361e2f7db46
	github.com/stackrox/rox => github.com/stackrox/stackrox v0.0.0-20240723082904-cdfb007fd7e9

	go.uber.org/zap => github.com/stackrox/zap v1.18.2-0.20240314134248-5f932edd0404
)
