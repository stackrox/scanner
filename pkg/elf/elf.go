package elf

import (
	"bytes"
	"debug/elf"
	"io"

	"github.com/stackrox/rox/pkg/set"
)

// MetaData contains the exacted metadata from ELF file
type MetaData struct {
	SoNames           []string
	ImportedLibraries []string
}

// IsElfExecutable tests if the data is in ELF format
func IsElfExecutable(r io.ReaderAt) bool {
	var elfBytes = make([]byte, len(elf.ELFMAG))

	_, err := r.ReadAt(elfBytes, 0)
	if err != nil || !bytes.Equal(elfBytes, []byte(elf.ELFMAG)) {
		return false
	}
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return false
	}

	// Exclude core and other unknown elf file.
	return set.NewIntSet(int(elf.ET_EXEC), int(elf.ET_DYN), int(elf.ET_REL)).Contains(int(elfFile.Type))
}

// GetElfMetadataData extracts and returns ELF metadata
func GetElfMetadataData(r io.ReaderAt) (*MetaData, error) {
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
	return &MetaData{
		SoNames:           soName,
		ImportedLibraries: libraries,
	}, nil
}
