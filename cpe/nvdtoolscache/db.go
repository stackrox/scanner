package nvdtoolscache

import (
	"encoding/json"

	"github.com/etcd-io/bbolt"
	"github.com/facebookincubator/nvdtools/cvefeed"
	"github.com/facebookincubator/nvdtools/cvefeed/nvd"
	"github.com/facebookincubator/nvdtools/cvefeed/nvd/schema"
	"github.com/facebookincubator/nvdtools/wfn"
	"github.com/mailru/easyjson"
	"github.com/stackrox/rox/pkg/set"
)

func New() (Cache, error) {
	opts := bbolt.Options{
		NoFreelistSync: true,
		FreelistType:   bbolt.FreelistMapType,
		NoSync:         true,
	}
	db, err := bbolt.Open("/tmp/temp.db", 0777, &opts)
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
	bytes, err := easyjson.Marshal(itemWrapper(*cve))
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

func (c *cacheImpl) GetVulnsForAttributes(attributes []*wfn.Attributes) ([]cvefeed.Vuln, error) {
	products := set.NewStringSet()
	for _, a := range attributes {
		if a.Product != "" {
			products.Add(a.Product)
		}
	}

	vulnSet := set.NewStringSet()
	var vulns []cvefeed.Vuln
	err := c.View(func(tx *bbolt.Tx) error {
		for product := range products {
			bucket := tx.Bucket([]byte(product))
			if bucket == nil {
				continue
			}
			return bucket.ForEach(func(k, v []byte) error {
				if !vulnSet.Add(string(k)) {
					return nil
				}
				var itemW itemWrapper
				if err := json.Unmarshal(v, &itemW); err != nil {
					return err
				}
				item := schema.NVDCVEFeedJSON10DefCVEItem(itemW)

				vulns = append(vulns, nvd.ToVuln(&item))
				return nil
			})
		}
		return nil
	})
	return vulns, err
}

func (c *cacheImpl) sync() error {
	return c.DB.Sync()
}
