package elf

import (
	"debug/elf"
	"github.com/stackrox/rox/pkg/utils"
	"io"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/set"
)

var (
	allowedELFTypeList = set.NewFrozenIntSet(elf.ET_EXEC, elf.ET_DYN)
)

// Metadata contains the exacted metadata from ELF file
type Metadata struct {
	// Sonames contains provided sonames for shared objects
	Sonames           []string
	ImportedLibraries []string
}

// GetMetadata extracts and returns ELF Metadata if the input is in ELF format.
func GetMetadata(r io.ReaderAt) (*Metadata, error) {
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return nil, nil
	}
	defer utils.IgnoreError(elfFile.Close)

	// Exclude core and other unknown ELF file.
	if !allowedELFTypeList.Contains(elfFile.Type) {
		return nil, nil
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
