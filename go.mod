module github.com/stackrox/scanner

go 1.17

require (
	cloud.google.com/go/storage v1.12.0
	github.com/NYTimes/gziphandler v1.1.1
	github.com/PuerkitoBio/goquery v1.5.1
	github.com/ckaznocha/protoc-gen-lint v0.2.4
	github.com/containers/image/v5 v5.11.1
	github.com/davecgh/go-spew v1.1.1
	github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/docker-credential-helpers v0.6.3
	github.com/facebookincubator/nvdtools v0.1.4
	github.com/ghodss/yaml v1.0.0
	github.com/go-git/go-billy/v5 v5.0.0
	github.com/go-git/go-git/v5 v5.2.0
	github.com/gogo/protobuf v1.3.2
	github.com/golang/protobuf v1.5.2
	github.com/golangci/golangci-lint v1.33.0
	github.com/google/go-cmp v0.5.6
	github.com/gorilla/mux v1.8.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/grpc-ecosystem/grpc-gateway v1.16.0
	github.com/guregu/null v3.0.2-0.20160228005316-41961cea0328+incompatible
	github.com/hashicorp/go-version v1.3.0
	github.com/hashicorp/golang-lru v0.5.4
	github.com/heroku/docker-registry-client v0.0.0
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f
	github.com/knqyf263/go-rpm-version v0.0.0-20170716094938-74609b86c936
	github.com/lib/pq v1.9.0
	github.com/mailru/easyjson v0.7.7
	github.com/mholt/archiver/v3 v3.5.0
	github.com/mitchellh/hashstructure v1.1.0
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.2-0.20190823105129-775207bd45b6
	github.com/pborman/uuid v1.2.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.11.0
	github.com/quay/goval-parser v0.8.6
	github.com/remind101/migrate v0.0.0-20170729031349-52c1edff7319
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.1.3
	github.com/stackrox/dotnet-scraper v0.0.0-20201023051640-72ef543323dd
	github.com/stackrox/k8s-cves v0.0.0-20201110001126-cc333981eaab
	github.com/stackrox/rox v0.0.0-20210914215712-9ac265932e28
	github.com/stretchr/testify v1.7.0
	go.etcd.io/bbolt v1.3.6
	go.uber.org/ratelimit v0.2.0
	golang.org/x/sys v0.0.0-20210903071746-97244b99971b
	google.golang.org/api v0.33.0
	google.golang.org/grpc v1.40.0
	gopkg.in/yaml.v2 v2.4.0
	honnef.co/go/tools v0.0.1-2020.1.6
)

require (
	4d63.com/gochecknoglobals v0.0.0-20201008074935-acfc0b28355a // indirect
	cloud.google.com/go v0.70.0 // indirect
	github.com/BurntSushi/toml v0.3.1 // indirect
	github.com/Djarvur/go-err113 v0.0.0-20200511133814-5174e21577d5 // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/OpenPeeDeeP/depguard v1.0.1 // indirect
	github.com/RoaringBitmap/roaring v0.9.4 // indirect
	github.com/andres-erbsen/clock v0.0.0-20160526145045-9e14626cd129 // indirect
	github.com/andybalholm/brotli v1.0.0 // indirect
	github.com/andybalholm/cascadia v1.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bits-and-blooms/bitset v1.2.0 // indirect
	github.com/blevesearch/bleve v0.8.0 // indirect
	github.com/blevesearch/go-porterstemmer v1.0.2 // indirect
	github.com/blevesearch/segment v0.0.0-20160915185041-762005e7a34f // indirect
	github.com/bombsimon/wsl/v3 v3.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/containers/libtrust v0.0.0-20190913040956-14b96171aa3b // indirect
	github.com/containers/ocicrypt v1.1.0 // indirect
	github.com/couchbase/vellum v0.0.0-20190328134517-462e86d8716b // indirect
	github.com/daixiang0/gci v0.2.4 // indirect
	github.com/denis-tingajkin/go-header v0.3.1 // indirect
	github.com/docker/docker v1.4.2-0.20200203170920-46ec8731fbce // indirect
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/dsnet/compress v0.0.1 // indirect
	github.com/edsrzf/mmap-go v1.0.0 // indirect
	github.com/emirpasic/gods v1.12.0 // indirect
	github.com/etcd-io/bbolt v1.3.3 // indirect
	github.com/facebookincubator/flog v0.0.0-20190930132826-d2511d0ce33c // indirect
	github.com/fatih/color v1.10.0 // indirect
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/go-critic/go-critic v0.5.2 // indirect
	github.com/go-git/gcfg v1.5.0 // indirect
	github.com/go-toolsmith/astcast v1.0.0 // indirect
	github.com/go-toolsmith/astcopy v1.0.0 // indirect
	github.com/go-toolsmith/astequal v1.0.0 // indirect
	github.com/go-toolsmith/astfmt v1.0.0 // indirect
	github.com/go-toolsmith/astp v1.0.0 // indirect
	github.com/go-toolsmith/strparse v1.0.0 // indirect
	github.com/go-toolsmith/typep v1.0.2 // indirect
	github.com/go-xmlfmt/xmlfmt v0.0.0-20191208150333-d5b6f63a941b // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/gofrs/flock v0.8.0 // indirect
	github.com/gofrs/uuid v4.0.0+incompatible // indirect
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/golang/snappy v0.0.1 // indirect
	github.com/golangci/check v0.0.0-20180506172741-cfe4005ccda2 // indirect
	github.com/golangci/dupl v0.0.0-20180902072040-3e9179ac440a // indirect
	github.com/golangci/errcheck v0.0.0-20181223084120-ef45e06d44b6 // indirect
	github.com/golangci/go-misc v0.0.0-20180628070357-927a3d87b613 // indirect
	github.com/golangci/gocyclo v0.0.0-20180528144436-0a533e8fa43d // indirect
	github.com/golangci/gofmt v0.0.0-20190930125516-244bba706f1a // indirect
	github.com/golangci/ineffassign v0.0.0-20190609212857-42439a7714cc // indirect
	github.com/golangci/lint-1 v0.0.0-20191013205115-297bf364a8e0 // indirect
	github.com/golangci/maligned v0.0.0-20180506175553-b1d89398deca // indirect
	github.com/golangci/misspell v0.0.0-20180809174111-950f5d19e770 // indirect
	github.com/golangci/prealloc v0.0.0-20180630174525-215b22d4de21 // indirect
	github.com/golangci/revgrep v0.0.0-20180526074752-d9c87f5ffaf0 // indirect
	github.com/golangci/unconvert v0.0.0-20180507085042-28b1c447d1f4 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/googleapis/gax-go/v2 v2.0.5 // indirect
	github.com/gostaticanalysis/analysisutil v0.1.0 // indirect
	github.com/gostaticanalysis/comment v1.3.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jgautheron/goconst v0.0.0-20201117150253-ccae5bf973f3 // indirect
	github.com/jingyugao/rowserrcheck v0.0.0-20191204022205-72ab7603b68a // indirect
	github.com/jirfag/go-printf-func-name v0.0.0-20191110105641-45db9963cdd3 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/jstemmer/go-junit-report v0.9.1 // indirect
	github.com/kevinburke/ssh_config v0.0.0-20190725054713-01f96b0aa0cd // indirect
	github.com/kisielk/gotool v1.0.0 // indirect
	github.com/klauspost/compress v1.11.13 // indirect
	github.com/klauspost/pgzip v1.2.5 // indirect
	github.com/kunwardeep/paralleltest v1.0.2 // indirect
	github.com/kyoh86/exportloopref v0.1.8 // indirect
	github.com/magiconair/properties v1.8.5 // indirect
	github.com/maratori/testpackage v1.0.1 // indirect
	github.com/matoous/godox v0.0.0-20190911065817-5d6d842e92eb // indirect
	github.com/mattn/go-colorable v0.1.8 // indirect
	github.com/mattn/go-isatty v0.0.13 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/mauricelam/genny v0.0.0-20190320071652-0800202903e5 // indirect
	github.com/mbilski/exhaustivestruct v1.1.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/mitchellh/mapstructure v1.1.2 // indirect
	github.com/moricho/tparallel v0.2.1 // indirect
	github.com/mschoch/smat v0.2.0 // indirect
	github.com/nakabonne/nestif v0.3.0 // indirect
	github.com/nbutton23/zxcvbn-go v0.0.0-20180912185939-ae427f1e4c1d // indirect
	github.com/nishanths/exhaustive v0.1.0 // indirect
	github.com/nwaples/rardecode v1.1.0 // indirect
	github.com/pelletier/go-toml v1.2.0 // indirect
	github.com/phayes/checkstyle v0.0.0-20170904204023-bfd46e6a821d // indirect
	github.com/pierrec/lz4/v4 v4.0.3 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/polyfloyd/go-errorlint v0.0.0-20201006195004-351e25ade6e3 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.30.0 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/quasilyte/go-ruleguard v0.2.0 // indirect
	github.com/quasilyte/regex/syntax v0.0.0-20200407221936-30656e2c4a95 // indirect
	github.com/ryancurrah/gomodguard v1.1.0 // indirect
	github.com/ryanrolds/sqlclosecheck v0.3.0 // indirect
	github.com/securego/gosec/v2 v2.5.0 // indirect
	github.com/sergi/go-diff v1.2.0 // indirect
	github.com/shazow/go-diff v0.0.0-20160112020656-b6b7b6733b8c // indirect
	github.com/sonatard/noctx v0.0.1 // indirect
	github.com/sourcegraph/go-diff v0.6.1 // indirect
	github.com/spf13/afero v1.2.2 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	github.com/spf13/jwalterweatherman v1.0.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.7.1 // indirect
	github.com/ssgreg/nlreturn/v2 v2.1.0 // indirect
	github.com/stackrox/default-authz-plugin v0.0.0-20210608105219-00ad9c9f3855 // indirect
	github.com/steveyen/gtreap v0.0.0-20150807155958-0abe01ef9be2 // indirect
	github.com/stretchr/objx v0.3.0 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	github.com/tdakkota/asciicheck v0.0.0-20200416190851-d7f85be797a2 // indirect
	github.com/tetafro/godot v1.3.0 // indirect
	github.com/timakin/bodyclose v0.0.0-20190930140734-f7f2e9bca95e // indirect
	github.com/tkuchiki/go-timezone v0.1.3 // indirect
	github.com/tomarrell/wrapcheck v0.0.0-20200807122107-df9e8bcb914d // indirect
	github.com/tommy-muehle/go-mnd v1.3.1-0.20200224220436-e6f9a994e8fa // indirect
	github.com/ulikunitz/xz v0.5.10 // indirect
	github.com/ultraware/funlen v0.0.3 // indirect
	github.com/ultraware/whitespace v0.0.4 // indirect
	github.com/uudashr/gocognit v1.0.1 // indirect
	github.com/willf/bitset v1.1.11 // indirect
	github.com/xanzy/ssh-agent v0.2.1 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	go.opencensus.io v0.22.5 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.7.0 // indirect
	go.uber.org/zap v1.15.1-0.20200717220000-53a387079b46 // indirect
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5 // indirect
	golang.org/x/lint v0.0.0-20210508222113-6edffad5e616 // indirect
	golang.org/x/mod v0.5.0 // indirect
	golang.org/x/net v0.0.0-20210902165921-8d991716f632 // indirect
	golang.org/x/oauth2 v0.0.0-20210514164344-f6687ab2804c // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/tools v0.1.5 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20210831024726-fe130286e0e2 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/ini.v1 v1.51.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
	mvdan.cc/gofumpt v0.0.0-20200802201014-ab5a8192947d // indirect
	mvdan.cc/interfacer v0.0.0-20180901003855-c20040233aed // indirect
	mvdan.cc/lint v0.0.0-20170908181259-adc824a0674b // indirect
	mvdan.cc/unparam v0.0.0-20200501210554-b37ab49443f7 // indirect
)

replace (
	github.com/blevesearch/bleve => github.com/stackrox/bleve v0.0.0-20190918030150-5ebdc2278ffe
	github.com/dgraph-io/badger => github.com/stackrox/badger v1.6.1-0.20191025195058-f2b50b9f079c

	// Due to github.com/stackrox/rox dependency.
	// BE SURE TO KEEP THIS UP-TO-DATE.
	github.com/docker/distribution => github.com/docker/distribution v0.0.0-20191216044856-a8371794149d
	github.com/docker/docker => github.com/moby/moby v17.12.0-ce-rc1.0.20200618181300-9dc6525e6118+incompatible

	github.com/facebookincubator/nvdtools => github.com/stackrox/nvdtools v0.0.0-20210326191554-5daeb6395b56
	github.com/fullsailor/pkcs7 => github.com/misberner/pkcs7 v0.0.0-20190417093538-a48bf0f78dea
	github.com/go-resty/resty => gopkg.in/resty.v1 v1.11.0
	github.com/gogo/protobuf => github.com/connorgorman/protobuf v1.2.2-0.20210115205927-b892c1b298f7
	github.com/heroku/docker-registry-client => github.com/stackrox/docker-registry-client v0.0.0-20210302165330-43446b0a41b5
	github.com/mattn/goveralls => github.com/viswajithiii/goveralls v0.0.3-0.20190917224517-4dd02c532775
	github.com/nilslice/protolock => github.com/viswajithiii/protolock v0.10.1-0.20190117180626-43bb8a9ba4e8
	go.uber.org/zap => github.com/stackrox/zap v1.15.1-0.20200720133746-810fd602fd0f
	k8s.io/client-go => k8s.io/client-go v0.20.4
)
