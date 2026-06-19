//go:build windows

package sqlite

import "os"

// TODO: implement strict ACL validation for Windows.
func ValidateDirPermissions(path string, info os.FileInfo) error {
	return nil
}

// TODO: implement strict ACL validation for Windows.
func ValidateFilePermissions(path string, info os.FileInfo) error {
	return nil
}
