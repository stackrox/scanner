package elf

import (
	"debug/elf"
	"io"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/set"
)

var (
	allowedELFTypeList = set.NewFrozenIntSet(int(elf.ET_EXEC), int(elf.ET_DYN))
)

// Metadata contains the exacted metadata from ELF file
type Metadata struct {
	// Sonames contains provided sonames for shared objects
	Sonames           []string
	ImportedLibraries []string
}

// OpenIfELFExecutable returns an ELF file if the data is in ELF format
func OpenIfELFExecutable(r io.ReaderAt) *elf.File {
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return nil
	}

	// Exclude core and other unknown elf file.
	if allowedELFTypeList.Contains(int(elfFile.Type)) {
		return elfFile
	}
	return nil
}

// GetELFMetadata extracts and returns ELF metadata
func GetELFMetadata(elfFile *elf.File) (*Metadata, error) {
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
