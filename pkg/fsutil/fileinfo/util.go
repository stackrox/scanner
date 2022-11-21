package fileinfo

import "io/fs"

// IsFileExecutable returns true if the file is an executable regular file.
func IsFileExecutable(fileInfo fs.FileInfo) bool {
	return fileInfo.Mode().IsRegular() && fileInfo.Mode()&0111 != 0
}

// IsFileSymlink returns true if fileInfo represents a symlink.
func IsFileSymlink(fileInfo fs.FileInfo) bool {
	return fileInfo.Mode().Type()&fs.ModeSymlink != 0
}
