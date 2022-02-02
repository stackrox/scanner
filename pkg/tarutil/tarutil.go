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

// Package tarutil implements some tar utility functions.
package tarutil

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"io"
	"os/exec"
	"path"
	"strings"
	"sync"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stackrox/scanner/pkg/elf"
	"github.com/stackrox/scanner/pkg/ioutils"
	"github.com/stackrox/scanner/pkg/matcher"
	"github.com/stackrox/scanner/pkg/metrics"
)

const (
	// DefaultMaxExtractableFileSizeMB is the default value for the max extractable file size.
	DefaultMaxExtractableFileSizeMB = 200
)

var (
	// maxExtractableFileSize enforces the maximum size of a single file within a
	// tarball that will be extracted. This protects against malicious files that
	// may used in an attempt to perform a Denial of Service attack.
	maxExtractableFileSize int64 = DefaultMaxExtractableFileSizeMB * 1024 * 1024

	readLen     = 6 // max bytes to sniff
	gzipHeader  = []byte{0x1f, 0x8b}
	bzip2Header = []byte{0x42, 0x5a, 0x68}
	xzHeader    = []byte{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00}
)

// SetMaxExtractableFileSize sets the max extractable file size.
// It is NOT thread-safe, and callers must ensure that it is called
// only when no scans are in progress (ex: during initialization).
// See comments on the maxExtractableFileSize variable for
// more details on its purpose.
func SetMaxExtractableFileSize(val int64) {
	a := new(sync.Pool)
	a.Get()
	maxExtractableFileSize = val
}

// ExtractFiles decompresses and extracts only the specified files from an
// io.Reader representing an archive.
func ExtractFiles(r io.Reader, filenameMatcher matcher.Matcher) (LayerFiles, error) {
	files := CreateNewLayerFiles(nil)

	// executableMatcher indicates if the given file is executable
	// for the FileData struct.
	executableMatcher := matcher.NewExecutableMatcher()

	// Decompress the archive.
	tr, err := NewTarReadCloser(r)
	if err != nil {
		return files, errors.Wrap(err, "could not extract tar archive")
	}
	defer tr.Close()

	// Telemetry variables.
	var numFiles, numMatchedFiles, numExtractedContentBytes int

	var prevLazyReader ioutils.LazyReaderAt

	// For each element in the archive
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return files, errors.Wrap(err, "could not advance in the tar archive")
		}
		numFiles++

		// Get element filename
		filename := strings.TrimPrefix(hdr.Name, "./")

		var contents io.ReaderAt
		if hdr.FileInfo().Mode().IsRegular() {
			// Recycle the buffer, if possible.
			var buf []byte
			if prevLazyReader != nil {
				buf = prevLazyReader.StealBuffer()
			}
			prevLazyReader = ioutils.NewLazyReaderAtWithBuffer(tr, hdr.Size, buf)
			contents = prevLazyReader
		} else {
			contents = bytes.NewReader(nil)
		}

		match, extractContents := filenameMatcher.Match(filename, hdr.FileInfo(), contents)
		if !match {
			continue
		}
		numMatchedFiles++

		// File size limit
		if extractContents && hdr.Size > maxExtractableFileSize {
			log.Errorf("Skipping file %q (%d bytes) because it was greater than the configured maxExtractableFileSizeMB of %d", filename, hdr.Size, maxExtractableFileSize)
			continue
		}

		// Extract the element
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeLink:
			var fileData FileData

			fileData.ELFMetadata, err = elf.GetExecutableMetadata(contents)
			if err != nil {
				log.Errorf("Failed to get dependencies for %s: %v", filename, err)
			}

			executable, _ := executableMatcher.Match(filename, hdr.FileInfo(), contents)

			if extractContents {
				if hdr.Typeflag == tar.TypeLink {
					// A hard-link necessarily points to a previous absolute path in the
					// archive which we look if it was already extracted.
					linkedFile, ok := files.data[hdr.Linkname]
					if ok {
						fileData.Contents = linkedFile.Contents
					}
				} else {
					d := make([]byte, hdr.Size)
					if nRead, err := contents.ReadAt(d, 0); err != nil {
						log.Errorf("error reading %q: %v", hdr.Name, err)
						d = d[:nRead]
					}

					// Put the file directly
					fileData.Contents = d
					numExtractedContentBytes += len(d)
				}
			}
			fileData.Executable = executable
			files.data[filename] = fileData
		case tar.TypeSymlink:
			files.links[filename] = path.Clean(path.Join(path.Dir(filename), hdr.Linkname))
		case tar.TypeDir:
			// Do not bother saving the contents,
			// and directories are NOT considered executable.
			// However, add to the map, so the entry will exist.
			files.data[filename] = FileData{}
		}
	}
	files.detectRemovedFiles()

	metrics.ObserveFileCount(numFiles)
	metrics.ObserveMatchedFileCount(numMatchedFiles)
	metrics.ObserveExtractedContentBytes(numExtractedContentBytes)

	return files, nil
}

// XzReader implements io.ReadCloser for data compressed via `xz`.
type XzReader struct {
	io.ReadCloser
	cmd     *exec.Cmd
	closech chan error
}

// NewXzReader returns an io.ReadCloser by executing a command line `xz`
// executable to decompress the provided io.Reader.
//
// It is the caller's responsibility to call Close on the XzReader when done.
func NewXzReader(r io.Reader) (*XzReader, error) {
	rpipe, wpipe := io.Pipe()
	ex, err := exec.LookPath("xz")
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(ex, "--decompress", "--stdout")

	closech := make(chan error)

	cmd.Stdin = r
	cmd.Stdout = wpipe

	go func() {
		err := cmd.Run()
		wpipe.CloseWithError(err)
		closech <- err
	}()

	return &XzReader{rpipe, cmd, closech}, nil
}

// Close cleans up the resources used by an XzReader.
func (r *XzReader) Close() error {
	r.ReadCloser.Close()
	r.cmd.Process.Kill()
	return <-r.closech
}

// TarReadCloser embeds a *tar.Reader and the related io.Closer
// It is the caller's responsibility to call Close on TarReadCloser when
// done.
type TarReadCloser struct {
	*tar.Reader
	io.Closer
}

// Close cleans up the resources used by a TarReadCloser.
func (r *TarReadCloser) Close() error {
	return r.Closer.Close()
}

// NewTarReadCloser attempts to detect the compression algorithm for an
// io.Reader and returns a TarReadCloser wrapping the Reader to transparently
// decompress the contents.
//
// Gzip/Bzip2/XZ detection is done by using the magic numbers:
// Gzip: the first two bytes should be 0x1f and 0x8b. Defined in the RFC1952.
// Bzip2: the first three bytes should be 0x42, 0x5a and 0x68. No RFC.
// XZ: the first three bytes should be 0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00. No RFC.
func NewTarReadCloser(r io.Reader) (*TarReadCloser, error) {
	br := bufio.NewReader(r)
	header, err := br.Peek(readLen)
	if err == nil {
		switch {
		case bytes.HasPrefix(header, gzipHeader):
			gr, err := gzip.NewReader(br)
			if err != nil {
				return nil, err
			}
			return &TarReadCloser{tar.NewReader(gr), gr}, nil
		case bytes.HasPrefix(header, bzip2Header):
			bzip2r := io.NopCloser(bzip2.NewReader(br))
			return &TarReadCloser{tar.NewReader(bzip2r), bzip2r}, nil
		case bytes.HasPrefix(header, xzHeader):
			xzr, err := NewXzReader(br)
			if err != nil {
				return nil, err
			}
			return &TarReadCloser{tar.NewReader(xzr), xzr}, nil
		}
	}

	dr := io.NopCloser(br)
	return &TarReadCloser{tar.NewReader(dr), dr}, nil
}
