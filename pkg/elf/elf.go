package elf

import (
	"bytes"
	"debug/elf"
	"github.com/stackrox/rox/pkg/set"
	"io"
)

type ElfData struct {
	Sonames            []string
	Dependencies       []string
	SupportExecutables set.StringSet
}

func IsKnownExecutable(r io.ReaderAt) bool {
	var elfBytes = make([]byte, len(elf.ELFMAG))

	numByte, err := r.ReadAt(elfBytes, 0)
	if err != nil || numByte < len(elf.ELFMAG) || bytes.Compare(elfBytes, []byte(elf.ELFMAG)) != 0 {
		return false
	}
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return false
	}

	// Exclude core and other unknown elf file.
	return set.NewIntSet(int(elf.ET_EXEC), int(elf.ET_DYN), int(elf.ET_REL)).Contains(int(elfFile.Type))
}

func GetElfData(r io.ReaderAt)(*ElfData, error) {
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	soname, err := elfFile.DynString(elf.DT_SONAME)
	dependencies, err := elfFile.ImportedLibraries()
	if err != nil {
		return nil, err
	}
	return &ElfData{
		Sonames: soname,
		Dependencies: dependencies,
	}, nil
}
