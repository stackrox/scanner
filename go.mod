module github.com/stackrox/scanner

go 1.18

require (
	cloud.google.com/go/storage v1.30.1
	github.com/NYTimes/gziphandler v1.1.1
	github.com/PuerkitoBio/goquery v1.8.1
	github.com/ckaznocha/protoc-gen-lint v0.3.0
	github.com/containers/image/v5 v5.25.0
	github.com/davecgh/go-spew v1.1.1
	github.com/docker/distribution v2.8.2+incompatible
	github.com/facebookincubator/nvdtools v0.1.5
	github.com/ghodss/yaml v1.0.0
	github.com/go-git/go-billy/v5 v5.4.1
	github.com/go-git/go-git/v5 v5.6.1
	github.com/gogo/protobuf v1.3.2
	github.com/golang/protobuf v1.5.3
	github.com/google/go-cmp v0.5.9
	github.com/gorilla/mux v1.8.0
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/grpc-ecosystem/grpc-gateway v1.16.0
	github.com/guregu/null v4.0.0+incompatible
	github.com/hashicorp/go-version v1.6.0
	github.com/heroku/docker-registry-client v0.0.0
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f
	github.com/knqyf263/go-rpm-version v0.0.0-20220614171824-631e686d1075
	github.com/lib/pq v1.10.9
	github.com/mailru/easyjson v0.7.7
	github.com/mholt/archiver/v3 v3.5.1
	github.com/mitchellh/hashstructure/v2 v2.0.2
	github.com/opencontainers/go-digest v1.0.0
	github.com/pborman/uuid v1.2.1
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.15.1
	github.com/quay/goval-parser v0.8.8
	github.com/remind101/migrate v0.0.0-20170729031349-52c1edff7319
	github.com/sirupsen/logrus v1.9.1
	github.com/spf13/cobra v1.7.0
	github.com/stackrox/dotnet-scraper v0.0.0-20201023051640-72ef543323dd
	github.com/stackrox/k8s-cves v0.0.0-20220818200547-7d0d1420c58d
	github.com/stackrox/rox v0.0.0-20210914215712-9ac265932e28
	github.com/stretchr/testify v1.8.2
	go.etcd.io/bbolt v1.3.7
	go.uber.org/goleak v1.2.1
	go.uber.org/ratelimit v0.2.0
	golang.org/x/exp v0.0.0-20230321023759-10a507213a29
	golang.org/x/sys v0.8.0
	google.golang.org/api v0.122.0
	google.golang.org/grpc v1.55.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/containers/storage v1.46.0 // indirect
	github.com/google/s2a-go v0.1.3 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.1 // indirect
	github.com/opencontainers/image-spec v1.1.0-rc2 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
)

require (
	cloud.google.com/go v0.110.0 // indirect
	cloud.google.com/go/compute v1.19.0 // indirect
	cloud.google.com/go/compute/metadata v0.2.3 // indirect
	cloud.google.com/go/iam v0.13.0 // indirect
	github.com/Microsoft/go-winio v0.6.0 // indirect
	github.com/ProtonMail/go-crypto v0.0.0-20230217124315-7d5c6f04bbb8 // indirect
	github.com/acomagu/bufpipe v1.0.4 // indirect
	github.com/andres-erbsen/clock v0.0.0-20160526145045-9e14626cd129 // indirect
	github.com/andybalholm/brotli v1.0.3 // indirect
	github.com/andybalholm/cascadia v1.3.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/cloudflare/cfssl v1.6.3 // indirect
	github.com/cloudflare/circl v1.3.3 // indirect
	github.com/containers/libtrust v0.0.0-20230121012942-c1716e8a8d01 // indirect
	github.com/containers/ocicrypt v1.1.7 // indirect
	github.com/docker/docker v23.0.3+incompatible // indirect
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/dsnet/compress v0.0.2-0.20210315054119-f66993602bf5 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/facebookincubator/flog v0.0.0-20190930132826-d2511d0ce33c // indirect
	github.com/go-git/gcfg v1.5.0 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/gofrs/uuid v4.3.1+incompatible // indirect
	github.com/golang/glog v1.1.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/certificate-transparency-go v1.1.4 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.2.3 // indirect
	github.com/googleapis/gax-go/v2 v2.8.0 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/imdario/mergo v0.3.15 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jmoiron/sqlx v1.3.5 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/klauspost/compress v1.16.3 // indirect
	github.com/klauspost/pgzip v1.2.6-0.20220930104621-17e8dac29df8 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/nwaples/rardecode v1.1.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.2 // indirect
	github.com/pjbgf/sha1cd v0.3.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/common v0.42.0 // indirect
	github.com/prometheus/procfs v0.9.0 // indirect
	github.com/sergi/go-diff v1.2.0 // indirect
	github.com/skeema/knownhosts v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stackrox/istio-cves v0.0.0-20221007013142-0bde9b541ec8
	github.com/tkuchiki/go-timezone v0.2.2 // indirect
	github.com/ulikunitz/xz v0.5.11 // indirect
	github.com/weppos/publicsuffix-go v0.20.1-0.20221031080346-e4081aa8a6de // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	github.com/zmap/zcrypto v0.0.0-20220402174210-599ec18ecbac // indirect
	github.com/zmap/zlint/v3 v3.4.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/multierr v1.9.0 // indirect
	go.uber.org/zap v1.24.0 // indirect
	golang.org/x/crypto v0.7.0 // indirect
	golang.org/x/mod v0.9.0 // indirect
	golang.org/x/net v0.9.0 // indirect
	golang.org/x/oauth2 v0.7.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/tools v0.6.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	golang.stackrox.io/grpc-http1 v0.2.6 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apimachinery v0.24.10 // indirect
	k8s.io/klog/v2 v2.80.1 // indirect
	k8s.io/utils v0.0.0-20220210201930-3a6ce19ff2f9 // indirect
	nhooyr.io/websocket v1.8.7 // indirect
)

replace (
	// Due to github.com/stackrox/rox dependency.
	// BE SURE TO KEEP THIS UP-TO-DATE.
	github.com/blevesearch/bleve => github.com/stackrox/bleve v0.0.0-20220907150529-4ecbd2543f9e

	github.com/facebookincubator/nvdtools => github.com/stackrox/nvdtools v0.0.0-20230214202552-24e684e3ad9d
	github.com/fullsailor/pkcs7 => github.com/stackrox/pkcs7 v0.0.0-20220914154527-cfdb0aa47179
	github.com/gogo/protobuf => github.com/connorgorman/protobuf v1.2.2-0.20210115205927-b892c1b298f7
	github.com/heroku/docker-registry-client => github.com/stackrox/docker-registry-client v0.0.0-20230411213734-d75b95d65d28

	github.com/operator-framework/helm-operator-plugins => github.com/stackrox/helm-operator v0.0.10-0.20220919093109-89f9785764c6
	github.com/stackrox/rox => github.com/stackrox/stackrox v0.0.0-20230301153935-a7fafd5bc0bd

	go.uber.org/zap => github.com/stackrox/zap v1.15.1-0.20200720133746-810fd602fd0f
)
