module github.com/stackrox/scanner

go 1.13

require (
	cloud.google.com/go/storage v1.10.0
	github.com/NYTimes/gziphandler v1.1.1
	github.com/PuerkitoBio/goquery v1.5.1
	github.com/davecgh/go-spew v1.1.1
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/docker-credential-helpers v0.6.3
	github.com/facebookincubator/nvdtools v0.1.4
	github.com/ghodss/yaml v1.0.0
	github.com/go-git/go-git/v5 v5.2.0
	github.com/gogo/protobuf v1.3.1
	github.com/golang/protobuf v1.4.2
	github.com/gorilla/mux v1.7.4
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.0
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/grpc-ecosystem/grpc-gateway v1.11.4-0.20191004150533-c677e419aa5c
	github.com/guregu/null v3.0.2-0.20160228005316-41961cea0328+incompatible
	github.com/hashicorp/go-version v1.2.1
	github.com/hashicorp/golang-lru v0.5.3
	github.com/heroku/docker-registry-client v0.0.0
	github.com/lib/pq v1.7.0
	github.com/mailru/easyjson v0.7.6
	github.com/mholt/archiver v3.1.1+incompatible
	github.com/opencontainers/go-digest v1.0.0
	github.com/pborman/uuid v1.2.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.7.1
	github.com/remind101/migrate v0.0.0-20160423010909-d22d647232c2
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/cobra v1.0.0
	github.com/stackrox/k8s-cves v0.0.0-20201108201937-92bcef5ac375
	github.com/stackrox/rox v0.0.0-20200902200840-183e12662c50
	github.com/stretchr/testify v1.6.1
	go.etcd.io/bbolt v1.3.5
	golang.org/x/lint v0.0.0-20200302205851-738671d3881b
	golang.org/x/sys v0.0.0-20200803210538-64077c9b5642
	golang.org/x/tools v0.0.0-20200804011535-6c149bb5ef0d
	google.golang.org/api v0.30.0
	google.golang.org/grpc v1.31.0
	gopkg.in/yaml.v2 v2.3.0
	honnef.co/go/tools v0.0.1-2020.1.5
)

replace (
	github.com/blevesearch/bleve => github.com/stackrox/bleve v0.0.0-20190918030150-5ebdc2278ffe
	github.com/dgraph-io/badger => github.com/stackrox/badger v1.6.1-0.20191025195058-f2b50b9f079c
	github.com/facebookincubator/nvdtools => github.com/stackrox/nvdtools v0.0.0-20200903060121-ccc2b5ea9f6f
	github.com/fullsailor/pkcs7 => github.com/misberner/pkcs7 v0.0.0-20190417093538-a48bf0f78dea
	github.com/go-resty/resty => gopkg.in/resty.v1 v1.11.0
	github.com/gogo/protobuf => github.com/connorgorman/protobuf v1.2.2-0.20200827223713-3c42fc2eb426
	github.com/heroku/docker-registry-client => github.com/stackrox/docker-registry-client v0.0.0-20181115184320-3d98b2b79d1b
	github.com/mattn/goveralls => github.com/viswajithiii/goveralls v0.0.3-0.20190917224517-4dd02c532775
	github.com/nilslice/protolock => github.com/viswajithiii/protolock v0.10.1-0.20190117180626-43bb8a9ba4e8
	go.uber.org/zap => github.com/stackrox/zap v1.15.1-0.20200720133746-810fd602fd0f
)
