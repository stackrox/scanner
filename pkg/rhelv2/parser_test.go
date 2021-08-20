package rhelv2

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stackrox/scanner/database"
)

func TestT(t *testing.T) {
	resp, err := http.Get(securityDataURL + "/" + "CVE-2020-8002")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()


	fmt.Println(resp.Status)

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(data))

	securityData := &database.SecurityData{}
	if err := json.NewDecoder(resp.Body).Decode(securityData); err != nil {
		panic(err)
	}

}


