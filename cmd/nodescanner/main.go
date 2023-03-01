package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/utils"
)

var (
	scanner  = &NodeInventoryCollector{}
	nodeName = "FIXME"
)

// NEED: env var Node name
// NEED: /cache mounted as EmptyDir
func main() {
	log.Infof("Using NodeInventoryCollector")

	http.HandleFunc("/", handleHTTPRequest)
	utils.CrashOnError(http.ListenAndServe(":8080", nil))
}

func handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	// first scan should happen on start
	inventory, err := scanner.Scan(nodeName) // FIXME
	if err != nil {
		log.Errorf("error running cachedScanNode: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte("Internal scanner error"))
		utils.CrashOnError(err)
	} else {

		//cmetrics.ObserveInventoryProtobufMessage(msg)
		fmt.Println(inventory)
		js, err := json.Marshal(inventory)
		if err != nil {
			log.Warnf("Encountered error marshalling message. Err: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			_, err = w.Write([]byte("Internal scanner error"))
			utils.CrashOnError(err)
		}
		_, err = w.Write(js)
		utils.CrashOnError(err)
	}
}
