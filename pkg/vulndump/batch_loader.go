package vulndump

import (
	"encoding/json"
	"io"

	"github.com/stackrox/scanner/database"
)

const defaultBatchSize = 10_000

// osLoader batch loads OS-level vulnerabilities into a buffer.
type osLoader struct {
	rc io.ReadCloser

	dec *json.Decoder

	batchSize int
	buf       []database.Vulnerability
	done      bool
	err       error
}

func newOSLoader(source io.ReadCloser) (*osLoader, error) {
	// See https://pkg.go.dev/encoding/json#example-Decoder.Decode-Stream
	// for an example of how this decoder will be used.
	dec := json.NewDecoder(source)
	// Read the initial token, "[".
	_, err := dec.Token()
	if err != nil {
		return nil, err
	}

	return &osLoader{
		rc:        source,
		dec:       dec,
		batchSize: defaultBatchSize,
		buf:       make([]database.Vulnerability, 0, defaultBatchSize),
	}, nil
}

// Next loads the next batch of vulnerabilities and returns
// whether it was successful or not.
func (l *osLoader) Next() bool {
	if l.done || l.err != nil {
		return false
	}

	l.buf = l.buf[:0]
	for i := 0; i < l.batchSize; i++ {
		if !l.dec.More() {
			// JSON array has no more values.
			l.done = true
			return true
		}
		l.buf = append(l.buf, database.Vulnerability{})
		if err := l.dec.Decode(&l.buf[i]); err != nil {
			l.err = err
			return false
		}
	}

	return true
}

// Vulns returns the "next" bath of vulnerabilities.
// It is expected to be called once for each successful call to Next.
func (l *osLoader) Vulns() []database.Vulnerability {
	return l.buf
}

// Err returns the error associated with loading vulnerabilities.
// It is expected to be non-nil upon an unsuccessful call to Next.
func (l *osLoader) Err() error {
	return l.err
}

// Close closes the loader.
func (l *osLoader) Close() error {
	l.buf = nil // hint to GC to clean this.
	// Don't bother reading the final token, "]",
	// as it is possible there was a failure reading
	// the JSON array. Just close the file.
	return l.rc.Close()
}
