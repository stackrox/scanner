package elf

import (
	"debug/elf"
	"io"

	"github.com/stackrox/rox/pkg/set"
)

// Metadata contains the exacted metadata from ELF file
type Metadata struct {
	// SoNames contains provided sonames for shared objects
	SoNames           []string
	ImportedLibraries []string
}

// IsElfExecutable tests if the data is in ELF format
func IsElfExecutable(r io.ReaderAt) bool {
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return false
	}

	// Exclude core and other unknown elf file.
	return set.NewFrozenIntSet(int(elf.ET_EXEC), int(elf.ET_DYN)).Contains(int(elfFile.Type))
}

// GetElfMetadata extracts and returns ELF metadata
func GetElfMetadata(r io.ReaderAt) (*Metadata, error) {
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	soName, err := elfFile.DynString(elf.DT_SONAME)
	if err != nil {
		return nil, err
	}
	libraries, err := elfFile.ImportedLibraries()
	if err != nil {
		return nil, err
	}
	return &Metadata{
		SoNames:           soName,
		ImportedLibraries: libraries,
	}, nil
}
