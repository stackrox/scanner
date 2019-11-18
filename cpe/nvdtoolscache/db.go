package nvdtoolscache

import (
	"github.com/etcd-io/bbolt"
	"github.com/facebookincubator/nvdtools/cvefeed"
	"github.com/facebookincubator/nvdtools/cvefeed/nvd"
	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/mailru/easyjson"
	"github.com/stackrox/rox/pkg/set"
)

// This is a temporary path for the boltDB and is expected to be backed by
// an empty dir
const boltPath = "/var/lib/stackrox/temp.db"

func New() (Cache, error) {
	opts := bbolt.Options{
		NoFreelistSync: true,
		FreelistType:   bbolt.FreelistMapType,
		NoSync:         true,
	}
	db, err := bbolt.Open(boltPath, 0600, &opts)
	if err != nil {
		return nil, err
	}
	return &cacheImpl{
		DB: db,
	}, nil
}

type cacheImpl struct {
	*bbolt.DB
}

func (c *cacheImpl) addProductToCVE(vuln cvefeed.Vuln, cve *schema.NVDCVEFeedJSON10DefCVEItem) error {
	bytes, err := easyjson.Marshal((*itemWrapper)(cve))
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
				var itemW itemWrapper
				if err := easyjson.Unmarshal(v, &itemW); err != nil {
					return err
				}
				vulns = append(vulns, nvd.ToVuln((*schema.NVDCVEFeedJSON10DefCVEItem)(&itemW)))
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

func (c *cacheImpl) sync() error {
	return c.DB.Sync()
}
