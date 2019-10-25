module github.com/stackrox/scanner

go 1.13

require (
	github.com/beorn7/perks v1.0.0 // indirect
	github.com/davecgh/go-spew v1.1.1
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/fernet/fernet-go v0.0.0-20180830025343-9eac43b88a5e
	github.com/golang/protobuf v1.3.2 // indirect
	github.com/google/uuid v1.1.1 // indirect
	github.com/gorilla/mux v1.7.3
	github.com/guregu/null v3.0.2-0.20160228005316-41961cea0328+incompatible
	github.com/hashicorp/golang-lru v0.5.1
	github.com/heroku/docker-registry-client v0.0.0
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/lib/pq v1.2.0
	github.com/mattn/go-sqlite3 v1.11.0 // indirect
	github.com/opencontainers/go-digest v1.0.0-rc1
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/pborman/uuid v0.0.0-20180906182336-adf5a7427709
	github.com/pkg/errors v0.8.1
	github.com/prometheus/client_golang v0.9.1
	github.com/prometheus/client_model v0.0.0-20190129233127-fd36f4220a90 // indirect
	github.com/prometheus/common v0.4.1 // indirect
	github.com/prometheus/procfs v0.0.0-20190523193104-a7aeb8df3389 // indirect
	github.com/remind101/migrate v0.0.0-20160423010909-d22d647232c2
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	golang.org/x/lint v0.0.0-20190930215403-16217165b5de
	golang.org/x/sys v0.0.0-20190712062909-fae7ac547cb7 // indirect
	golang.org/x/tools v0.0.0-20191018203202-04252eccb9d5
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/yaml.v2 v2.2.3
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
