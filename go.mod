module github.com/stackrox/scanner

go 1.13

require (
	github.com/beorn7/perks v0.0.0-20160804104726-4c0e84591b9a // indirect
	github.com/davecgh/go-spew v1.1.1
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/fernet/fernet-go v0.0.0-20151007213151-1b2437bc582b
	github.com/golang/protobuf v1.3.2 // indirect
	github.com/gorilla/mux v1.7.3
	github.com/guregu/null v3.0.2-0.20160228005316-41961cea0328+incompatible
	github.com/hashicorp/go-version v1.2.0
	github.com/hashicorp/golang-lru v0.0.0-20160813221303-0a025b7e63ad
	github.com/heroku/docker-registry-client v0.0.0-20190909225348-afc9e1acc3d5
	github.com/lib/pq v0.0.0-20170324204654-2704adc878c2
	github.com/mattn/go-sqlite3 v1.11.0 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/opencontainers/go-digest v1.0.0-rc1
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/pborman/uuid v0.0.0-20160209185913-a97ce2ca70fa
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v0.8.0
	github.com/prometheus/client_model v0.0.0-20170216185247-6f3806018612 // indirect
	github.com/prometheus/common v0.0.0-20170427095455-13ba4ddd0caa // indirect
	github.com/prometheus/procfs v0.0.0-20170502131342-d098ca18df8b // indirect
	github.com/remind101/migrate v0.0.0-20160423010909-d22d647232c2
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	golang.org/x/lint v0.0.0-20190930215403-16217165b5de
	golang.org/x/tools v0.0.0-20191018203202-04252eccb9d5
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/yaml.v2 v2.2.2
	honnef.co/go/tools v0.0.1-2019.2.3
)

replace (
	github.com/blevesearch/bleve => github.com/stackrox/bleve v0.0.0-20190918030150-5ebdc2278ffe
	github.com/dgraph-io/badger => github.com/stackrox/badger v1.6.1-0.20190917050531-b23b7e1b1e94
	github.com/fullsailor/pkcs7 => github.com/misberner/pkcs7 v0.0.0-20190417093538-a48bf0f78dea
	github.com/go-resty/resty => gopkg.in/resty.v1 v1.11.0
	github.com/gogo/protobuf => github.com/connorgorman/protobuf v1.2.2-0.20190220010025-a81e5c3a5053
	github.com/heroku/docker-registry-client => github.com/stackrox/docker-registry-client v0.0.0-20181115184320-3d98b2b79d1b
	github.com/mattn/goveralls => github.com/viswajithiii/goveralls v0.0.3-0.20190917224517-4dd02c532775
	github.com/nilslice/protolock => github.com/viswajithiii/protolock v0.10.1-0.20190117180626-43bb8a9ba4e8
)
