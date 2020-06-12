package client

import "errors"

var (
	// ErrorScanNotFound allows for external libraries to act upon the lack of a scan
	ErrorScanNotFound = errors.New("error scan not found")

	// ErrorUnsupportedOS tells the caller that this OS could not be scanned
	ErrorUnsupportedOS = errors.New("namespace could not be determined or scanned")
)
