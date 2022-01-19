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

// GetMetadataIfELFExecutable extracts and returns ELF metadata if the input
// is an executable in ELF format.
func GetMetadataIfELFExecutable(r io.ReaderAt) (*Metadata, error) {
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return nil, nil
	}
	defer elfFile.Close()

	// Exclude core and other unknown elf file.
	if !allowedELFTypeList.Contains(int(elfFile.Type)) {
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
