package elf

import (
	"bytes"
	"debug/elf"
	"github.com/stackrox/rox/pkg/set"
	"io"
)

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

func GetNeededLibraries(r io.ReaderAt)([]string, error) {
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	return elfFile.ImportedLibraries()
}