// Copyright 2017 clair authors
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

// Package stackrox implements a vulnerability source updater using StackRox feeds
package stackrox

import (
	"context"
	"encoding/json"
	"os"
	"time"

	googleStorage "cloud.google.com/go/storage"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/database"
	"github.com/stackrox/scanner/ext/vulnsrc"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

const (
	bucketName = "stackrox-scanner-feed"

	requestTimeout = 1 * time.Minute
)

type updater struct {


	repositoryLocalPath string
}

func init() {
	vulnsrc.RegisterUpdater("stackrox", &updater{})
}

func (u *updater) listAllFeeds(handle *googleStorage.BucketHandle) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	objectIterator := handle.Objects(ctx, &googleStorage.Query{})

	var feedNames []string
	var attrs *googleStorage.ObjectAttrs
	var err error
	for attrs, err = objectIterator.Next(); err == nil; attrs, err = objectIterator.Next() {
		feedNames = append(feedNames, attrs.Name)
	}
	if err != iterator.Done {
		return nil, errors.Wrap(err, "fetching all objects from GCS bucket")
	}
	return feedNames, nil
}

func (u *updater) downloadFeed(objectHandle *googleStorage.ObjectHandle) ([]database.Vulnerability, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	reader, err := objectHandle.NewReader(ctx)
	if err != nil {
		return nil, err
	}

	var vulnerabilities []database.Vulnerability
	if err := json.NewDecoder(reader).Decode(&vulnerabilities); err != nil {
		return nil, errors.Wrapf(err, "decoding vulnerability for %s", objectHandle.ObjectName())
	}
	return vulnerabilities, nil
}

func (u *updater) Update(datastore vulnsrc.DataStore) (resp vulnsrc.UpdateResponse, err error) {
	log.WithField("package", "Stackrox").Info("Start fetching vulnerabilities")

	serviceAccount := os.Getenv("GOOGLE_SA_CIRCLECI_SCANNER")
	if serviceAccount == "" {
		return resp, errors.New("StackRox updater cannot be run without a service account")
	}

	client, err := googleStorage.NewClient(context.Background(), option.WithCredentialsJSON([]byte(serviceAccount)))
	if err != nil {
		return resp, errors.Wrap(err, "could not create GCS client")
	}
	bucketHandle := client.Bucket(bucketName)
	feeds, err := u.listAllFeeds(bucketHandle)
	if err != nil {
		return resp, err
	}

	var vulnerabilities []database.Vulnerability
	for _, feed := range feeds {
		feedVulns, err := u.downloadFeed(bucketHandle.Object(feed))
		if err != nil {
			return resp, err
		}
		vulnerabilities = append(vulnerabilities, feedVulns...)
	}

	resp.Vulnerabilities = vulnerabilities
	return
}

func (u *updater) Clean() {}
