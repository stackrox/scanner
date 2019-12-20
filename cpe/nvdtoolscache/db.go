package nvdtoolscache

import (
	"path/filepath"
	"time"

	"github.com/etcd-io/bbolt"
	"github.com/facebookincubator/nvdtools/cvefeed"
	"github.com/facebookincubator/nvdtools/cvefeed/nvd"
	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/scanner/pkg/nvdloader"
	"github.com/stackrox/scanner/pkg/wellknowndirnames"
)

var (
	// BoltPath is a temporary path for the boltDB and is expected to be backed by
	// an empty dir. Exported for localdev to be able to set it.
	// TODO: Make this injectable instead.
	BoltPath = filepath.Join(wellknowndirnames.WriteableDir, "temp.db")
)

func New() (Cache, error) {
	opts := bbolt.Options{
		NoFreelistSync: true,
		FreelistType:   bbolt.FreelistMapType,
		NoSync:         true,
	}
	db, err := bbolt.Open(BoltPath, 0600, &opts)
	if err != nil {
		return nil, err
	}
	return &cacheImpl{
		DB: db,
	}, nil
}

type cacheImpl struct {
	*bbolt.DB

	updatedTime time.Time
}

func (c *cacheImpl) addProductToCVE(vuln cvefeed.Vuln, cve *schema.NVDCVEFeedJSON10DefCVEItem) error {
	bytes, err := nvdloader.MarshalNVDFeedCVEItem(cve)
	if err != nil {
		return err
	}
	return c.Update(func(tx *bbolt.Tx) error {
		for _, a := range vuln.Config() {
			product := []byte(a.Product)
			bucket, err := tx.CreateBucketIfNotExists(product)
			if err != nil {
				return err
			}
			if bucket.Get([]byte(cve.CVE.CVEDataMeta.ID)) != nil {
				continue
			}
			if err := bucket.Put([]byte(cve.CVE.CVEDataMeta.ID), bytes); err != nil {
				return err
			}
		}
		return nil
	})
}

func (c *cacheImpl) GetVulnsForProducts(products []string) ([]cvefeed.Vuln, error) {
	vulnSet := set.NewStringSet()
	var vulns []cvefeed.Vuln
	err := c.View(func(tx *bbolt.Tx) error {
		for _, product := range products {
			bucket := tx.Bucket([]byte(product))
			if bucket == nil {
				continue
			}
			err := bucket.ForEach(func(k, v []byte) error {
				if !vulnSet.Add(string(k)) {
					return nil
				}
				vuln, err := nvdloader.UnmarshalNVDFeedCVEItem(v)
				if err != nil {
					return errors.Wrapf(err, "unmarshaling vuln %s", string(k))
				}
				vulns = append(vulns, nvd.ToVuln(vuln))
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	return vulns, err
}

func (c *cacheImpl) GetLastUpdate() time.Time {
	return c.updatedTime
}

func (c *cacheImpl) SetLastUpdate(t time.Time) {
	c.updatedTime = t
}

func (c *cacheImpl) sync() error {
	return c.DB.Sync()
}
