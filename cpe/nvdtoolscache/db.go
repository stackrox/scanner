package nvdtoolscache

import (
	"path/filepath"
	"sync"
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

	cveToProductBucket = []byte("stackrox-cve-to-product")
)

func newWithDB(db *bbolt.DB) Cache {
	return &cacheImpl{DB: db}
}

func initializeDB(db *bbolt.DB) error {
	return db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucket(cveToProductBucket)
		return err
	})
}

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
	if err := initializeDB(db); err != nil {
		return nil, err
	}
	return newWithDB(db), nil
}

type cacheImpl struct {
	*bbolt.DB

	updateLock      sync.Mutex
	lastUpdatedTime time.Time
}

func (c *cacheImpl) addProductToCVE(vuln cvefeed.Vuln, cve *schema.NVDCVEFeedJSON10DefCVEItem) error {
	bytes, err := nvdloader.MarshalNVDFeedCVEItem(cve)
	if err != nil {
		return err
	}
	// Track the products that are associated with this CVE.
	productAlreadyWritten := set.NewStringSet()
	// Track the products that are no longer associated with this CVE.
	productsToDelete := set.NewStringSet()
	return c.Update(func(tx *bbolt.Tx) error {
		// Get the CVE to product mapping.
		cveBucket := tx.Bucket(cveToProductBucket)
		productBytes := cveBucket.Get([]byte(cve.CVE.CVEDataMeta.ID))
		if productBytes != nil {
			products, err := nvdloader.UnmarshalStringSlice(productBytes)
			if err != nil {
				return err
			}
			productsToDelete.AddAll(products...)
		}

		// Update the associated product buckets with the CVE.
		for _, a := range vuln.Config() {
			if !productAlreadyWritten.Add(a.Product) {
				continue
			}
			productsToDelete.Remove(a.Product)

			product := []byte(a.Product)
			bucket, err := tx.CreateBucketIfNotExists(product)
			if err != nil {
				return err
			}
			if err := bucket.Put([]byte(cve.CVE.CVEDataMeta.ID), bytes); err != nil {
				return err
			}
		}

		// Update the CVE bucket with the latest products.
		productBytes, err = nvdloader.MarshalStringSlice(productAlreadyWritten.AsSlice())
		if err != nil {
			return err
		}
		if err := cveBucket.Put([]byte(cve.CVE.CVEDataMeta.ID), productBytes); err != nil {
			return err
		}

		for product := range productsToDelete {
			bucket := tx.Bucket([]byte(product))
			if err := bucket.Delete([]byte(cve.CVE.CVEDataMeta.ID)); err != nil {
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
	c.updateLock.Lock()
	defer c.updateLock.Unlock()

	return c.lastUpdatedTime
}

func (c *cacheImpl) SetLastUpdate(t time.Time) {
	c.updateLock.Lock()
	defer c.updateLock.Unlock()

	c.lastUpdatedTime = t
}

func (c *cacheImpl) sync() error {
	return c.DB.Sync()
}
