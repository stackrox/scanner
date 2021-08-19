// Files with ":" in the name are not valid files to put in a ZIP.
// Because of this, adding the Scanner module to Rox does not work properly.
// To alleviate this, we have an empty module here, so these files are ignored.
// See https://github.com/golang/go/issues/41402 for more information.
module github.com/stackrox/scanner/ignore
