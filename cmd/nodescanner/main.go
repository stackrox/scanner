package main

import (
	"encoding/json"
	"github.com/stackrox/scanner/cmd/nodescanner/inventory"
	"net"
	"net/http"

	log "github.com/sirupsen/logrus"
	"github.com/stackrox/rox/pkg/utils"
)

var (
	scanner = &inventory.NodeInventoryCollector{}
)

func main() {
	log.Infof("Using NodeInventoryCollector")

	http.HandleFunc("/", getNodeInventoryHandler)

	serverAddr := net.JoinHostPort("", nodeScannerHTTPPort.Value())
	utils.CrashOnError(http.ListenAndServe(serverAddr, nil))
}

func getNodeInventoryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		_, err := w.Write([]byte("Only GET HTTP method supported"))
		utils.CrashOnError(err)
	}

	inventoryScan, err := scanner.Scan(nodeName.Value())
	if err != nil {
		log.Errorf("Error running cachedScanNode: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte("Internal scanner error"))
		utils.CrashOnError(err)
	} else {
		log.Debugf("InventoryScan: %+v", inventoryScan)
		js, err := json.Marshal(inventoryScan)
		if err != nil {
			log.Errorf("Encountered error marshalling message. Err: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			_, err = w.Write([]byte("Internal scanner error"))
			utils.CrashOnError(err)
		}
		_, err = w.Write(js)
		utils.CrashOnError(err)
	}
}
