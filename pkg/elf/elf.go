package elf

import (
	"debug/elf"
	"io"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/utils"
)

var (
	allowedELFTypeList = set.NewFrozenIntSet(int(elf.ET_EXEC), int(elf.ET_DYN))
	// NumElfExecutables xxx
	NumElfExecutables = 0
	// MaxDistToEnd xxx
	MaxDistToEnd int64 = 1024 * 1024
	// Sizes xx
	Sizes StatSizes
	m     int64 = 1024 * 1024
)

// StatSizes xxx
type StatSizes struct {
	lessThan100M int
	f100To200M   int
	f200To300M   int
	f300To500M   int
	morethan500M int
}

// Metadata contains the exacted metadata from ELF file
type Metadata struct {
	// Sonames contains provided sonames for shared objects
	Sonames           []string
	ImportedLibraries []string
}

// GetExecutableMetadata extracts and returns Metadata if the input is an executable ELF binary.
// It is **not** an error if the passed in io.ReaderAt is not an ELF binary.
func GetExecutableMetadata(r io.ReaderAt, size int64) (*Metadata, error) {
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return nil, nil
	}
	defer utils.IgnoreError(elfFile.Close)

	// Exclude core and other unknown ELF file.
	if !allowedELFTypeList.Contains(int(elfFile.Type)) {
		return nil, nil
	}
	switch {
	case size < 100*m:
		Sizes.lessThan100M++
	case size < 200*m:
		Sizes.f100To200M++
	case size < 300*m:
		Sizes.f200To300M++
	case size < 500*m:
		Sizes.f300To500M++
	default:
		Sizes.morethan500M++
	}
	NumElfExecutables++
	ds := elfFile.SectionByType(elf.SHT_DYNAMIC)
	if size-int64(ds.Addr) > MaxDistToEnd {
		MaxDistToEnd = size - int64(ds.Addr)
	}

	sonames, err := elfFile.DynString(elf.DT_SONAME)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get sonames from ELF executable")
	}
	libraries, err := elfFile.ImportedLibraries()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get imported libraries from ELF executable")
	}
	return &Metadata{
		Sonames:           sonames,
		ImportedLibraries: libraries,
	}, nil
}
