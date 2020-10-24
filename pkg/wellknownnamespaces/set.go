package wellknownnamespaces

import "github.com/stackrox/rox/pkg/set"

var (
	KnownStaleNamespaces = set.NewFrozenStringSet(
		"alpine:v3.2",
		"alpine:v3.3",
		"alpine:v3.4",
		"alpine:v3.5",
		"alpine:v3.6",
		"alpine:v3.7",
		"debian:8",
		"ubuntu:12.10",
		"ubuntu:13.04",
		"ubuntu:14.10",
		"ubuntu:15.04",
		"ubuntu::15.10",
		"ubuntu::16.10",
		"ubuntu:17.04",
		"ubuntu:17.10",
		"ubuntu:18.10",
		"ubuntu:19.04",
		"ubuntu:19.10",
	)

	KnownSupportedNamespaces = set.NewFrozenStringSet(
		"alpine:v3.8",
		"alpine:v3.9",
		"alpine:v3.10",
		"alpine:v3.11",
		"alpine:v3.12",
		"amzn:2018.03",
		"amzn:2",
		"centos:5", // TODO: EOL 11/2020
		"centos:6",
		"centos:7",
		"centos:8",
		"debian:9",
		"debian:10",
		"debian:11",
		"debian:unstable",
		"oracle:5", // TODO: EOL 11/2020
		"oracle:6",
		"oracle:7",
		"oracle:8",
		"ubuntu:12.04",
		"ubuntu:14.04",
		"ubuntu:16.04",
		"ubuntu:18.04",
		"ubuntu:20.04",
		"ubuntu:20.10",
	)
)
