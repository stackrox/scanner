module github.com/stackrox/scanner

go 1.13

require (
	github.com/NYTimes/gziphandler v1.1.1
	github.com/davecgh/go-spew v1.1.1
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/docker-credential-helpers v0.6.3
	github.com/etcd-io/bbolt v1.3.3
	github.com/facebookincubator/nvdtools v0.1.4-0.20191024132624-1cb041402875
	github.com/gogo/protobuf v1.2.2-0.20190723190241-65acae22fc9d
	github.com/golang/protobuf v1.3.5
	github.com/gorilla/mux v1.7.3
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.0
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/grpc-ecosystem/grpc-gateway v1.11.4-0.20191004150533-c677e419aa5c
	github.com/guregu/null v3.0.2-0.20160228005316-41961cea0328+incompatible
	github.com/hashicorp/golang-lru v0.5.3
	github.com/heroku/docker-registry-client v0.0.0
	github.com/lib/pq v1.2.0
	github.com/mailru/easyjson v0.0.0-20190614124828-94de47d64c63
	github.com/mholt/archiver v3.1.1+incompatible
	github.com/opencontainers/go-digest v1.0.0-rc1
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v0.9.2
	github.com/remind101/migrate v0.0.0-20160423010909-d22d647232c2
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.5
	github.com/stackrox/rox v0.0.0-20200514201203-38f7800e2e7a
	github.com/stretchr/testify v1.4.0
	go.etcd.io/bbolt v1.3.4 // indirect
	golang.org/x/lint v0.0.0-20190930215403-16217165b5de
	golang.org/x/tools v0.0.0-20191130070609-6e064ea0cf2d
	google.golang.org/grpc v1.24.0
	gopkg.in/yaml.v2 v2.2.4
	honnef.co/go/tools v0.0.1-2019.2.3
)

replace (
	github.com/blevesearch/bleve => github.com/stackrox/bleve v0.0.0-20190918030150-5ebdc2278ffe
	github.com/dgraph-io/badger => github.com/stackrox/badger v1.6.1-0.20191025195058-f2b50b9f079c
	github.com/facebookincubator/nvdtools => github.com/stackrox/nvdtools v0.0.0-20191120225537-fe4e9a7e467f
	github.com/fullsailor/pkcs7 => github.com/misberner/pkcs7 v0.0.0-20190417093538-a48bf0f78dea
	github.com/go-resty/resty => gopkg.in/resty.v1 v1.11.0
	github.com/gogo/protobuf => github.com/connorgorman/protobuf v1.2.2-0.20190220010025-a81e5c3a5053
	github.com/heroku/docker-registry-client => github.com/stackrox/docker-registry-client v0.0.0-20181115184320-3d98b2b79d1b
	github.com/mattn/goveralls => github.com/viswajithiii/goveralls v0.0.3-0.20190917224517-4dd02c532775
	github.com/nilslice/protolock => github.com/viswajithiii/protolock v0.10.1-0.20190117180626-43bb8a9ba4e8
)
