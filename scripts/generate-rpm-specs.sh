#!/usr/bin/env bash

# This script is to generate simple RPM spec files:
# spec => rpm files: run rpmbuild -bb *.spec
# install rpm: yum localinstall /root/rpmbuild/RPMS/x86_64/*.rpm

for ((n=1; n<=$1; n++)); do
	cat >pkg-$(printf "%03d" ${n}).spec <<EOF
Name: package_name_${n}
Summary: Package number ${n}
Version: 0
Release: 0
License: Public
Group: Applications/System
Requires: bash
%description
Package number ${n}
%files
EOF
done
