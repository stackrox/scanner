package elf

import (
	"debug/elf"
	"io"

	"github.com/pkg/errors"
	"github.com/stackrox/rox/pkg/set"
	"github.com/stackrox/rox/pkg/utils"
)

const df1PIE = 0x08000000

var (
	allowedELFTypeList = set.NewFrozenIntSet(int(elf.ET_EXEC), int(elf.ET_DYN))
)

// Metadata contains the exacted metadata from ELF file
type Metadata struct {
	// Sonames contains provided sonames for shared objects
	Sonames           []string
	ImportedLibraries []string
	SharedObject      bool
}

func isSharedObject(elfFile *elf.File) (bool, error) {
	if elfFile.Type != elf.ET_DYN {
		return false, nil
	}
	ds := elfFile.SectionByType(elf.SHT_DYNAMIC)
	if ds == nil {
		return true, nil
	}
	d, err := ds.Data()
	if err != nil {
		return false, err
	}
	for len(d) > 0 {
		var t elf.DynTag
		var v uint64
		switch elfFile.Class {
		case elf.ELFCLASS32:
			t = elf.DynTag(elfFile.ByteOrder.Uint32(d[0:4]))
			v = uint64(elfFile.ByteOrder.Uint32(d[4:8]))
			d = d[8:]
		case elf.ELFCLASS64:
			t = elf.DynTag(elfFile.ByteOrder.Uint64(d[0:8]))
			v = elfFile.ByteOrder.Uint64(d[8:16])
			d = d[16:]
		}
		if t == elf.DT_FLAGS_1 {
			return v != df1PIE, nil
		}
	}
	return true, nil
}

// GetExecutableMetadata extracts and returns Metadata if the input is an executable ELF binary.
// It is **not** an error if the passed in io.ReaderAt is not an ELF binary.
func GetExecutableMetadata(r io.ReaderAt) (*Metadata, error) {
	elfFile, err := elf.NewFile(r)
	if err != nil {
		// Do not return error if it is not in ELF format.
		if _, isFormatError := err.(*elf.FormatError); isFormatError {
			err = nil
		}
		return nil, err
	}
	defer utils.IgnoreError(elfFile.Close)

	// Exclude core and other unknown ELF file.
	if !allowedELFTypeList.Contains(int(elfFile.Type)) {
		return nil, nil
	}

	sharedObject, err := isSharedObject(elfFile)
	if err != nil {
		return nil, err
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
		SharedObject:      sharedObject,
	}, nil
}
