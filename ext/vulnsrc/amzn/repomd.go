// Copyright 2019 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package amzn implements a vulnerability source updater using
// ALAS (Amazon Linux Security Advisories).
package amzn

// RepoMd ALAS repo metadata.
type RepoMd struct {
	RepoList []Repo `xml:"data"`
}

// Repo ALAS repository.
type Repo struct {
	Type     string   `xml:"type,attr"`
	Location Location `xml:"location"`
}

// Location ALAs location.
type Location struct {
	Href string `xml:"href,attr"`
}
