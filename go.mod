module github.com/stackrox/scanner

go 1.13

require (
	cloud.google.com/go/storage v1.12.0
	github.com/NYTimes/gziphandler v1.1.1
	github.com/PuerkitoBio/goquery v1.5.1
	github.com/davecgh/go-spew v1.1.1
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/docker-credential-helpers v0.6.3
	github.com/facebookincubator/nvdtools v0.1.4
	github.com/ghodss/yaml v1.0.0
	github.com/go-git/go-billy/v5 v5.0.0
	github.com/go-git/go-git/v5 v5.2.0
	github.com/gogo/protobuf v1.3.1
	github.com/golang/protobuf v1.4.3
	github.com/gorilla/mux v1.8.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.2.0
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/grpc-ecosystem/grpc-gateway v1.11.4-0.20191004150533-c677e419aa5c
	github.com/guregu/null v3.0.2-0.20160228005316-41961cea0328+incompatible
	github.com/hashicorp/go-version v1.2.1
	github.com/hashicorp/golang-lru v0.5.3
	github.com/heroku/docker-registry-client v0.0.0
	github.com/lib/pq v1.8.0
	github.com/mailru/easyjson v0.7.6
	github.com/mholt/archiver v3.1.1+incompatible
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.2-0.20190823105129-775207bd45b6
	github.com/pborman/uuid v1.2.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.7.1
	github.com/remind101/migrate v0.0.0-20160423010909-d22d647232c2
	github.com/sirupsen/logrus v1.8.0
	github.com/spf13/cobra v1.1.1
	github.com/stackrox/dotnet-scraper v0.0.0-20201023051640-72ef543323dd
	github.com/stackrox/k8s-cves v0.0.0-20201110001126-cc333981eaab
	github.com/stackrox/rox v0.0.0-20201222223839-042406f3664c
	github.com/stretchr/testify v1.7.0
	go.etcd.io/bbolt v1.3.5
	golang.org/x/lint v0.0.0-20200302205851-738671d3881b
	golang.org/x/sys v0.0.0-20201101102859-da207088b7d1
	golang.org/x/tools v0.0.0-20201019175715-b894a3290fff
	google.golang.org/api v0.33.0
	google.golang.org/grpc v1.33.0
	gopkg.in/yaml.v2 v2.3.0
	honnef.co/go/tools v0.0.1-2020.1.6
)

replace (
	github.com/blevesearch/bleve => github.com/stackrox/bleve v0.0.0-20190918030150-5ebdc2278ffe
	github.com/dgraph-io/badger => github.com/stackrox/badger v1.6.1-0.20191025195058-f2b50b9f079c
	github.com/facebookincubator/nvdtools => github.com/stackrox/nvdtools v0.0.0-20200903060121-ccc2b5ea9f6f
	github.com/fullsailor/pkcs7 => github.com/misberner/pkcs7 v0.0.0-20190417093538-a48bf0f78dea
	github.com/go-resty/resty => gopkg.in/resty.v1 v1.11.0
	github.com/gogo/protobuf => github.com/connorgorman/protobuf v1.2.2-0.20210115205927-b892c1b298f7
	github.com/heroku/docker-registry-client => github.com/stackrox/docker-registry-client v0.0.0-20210302165330-43446b0a41b5
	github.com/mattn/goveralls => github.com/viswajithiii/goveralls v0.0.3-0.20190917224517-4dd02c532775
	github.com/nilslice/protolock => github.com/viswajithiii/protolock v0.10.1-0.20190117180626-43bb8a9ba4e8
	go.uber.org/zap => github.com/stackrox/zap v1.15.1-0.20200720133746-810fd602fd0f

	// Due to github.com/stackrox/rox dependency.
	// BE SURE TO KEEP THIS UP-TO-DATE.
	k8s.io/client-go => k8s.io/client-go v0.19.2
)
