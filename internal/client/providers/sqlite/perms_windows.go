//go:build windows

package sqlite

import "os"

// TODO: implement strict ACL validation for Windows.
func validateDirPermissions(path string, info os.FileInfo) error {
	return nil
}

// TODO: implement strict ACL validation for Windows.
func validateFilePermissions(path string, info os.FileInfo) error {
	return nil
}
