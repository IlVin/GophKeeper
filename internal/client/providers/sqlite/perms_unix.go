//go:build unix

package sqlite

import (
	"fmt"
	"os"
)

func ValidateDirPermissions(path string, info os.FileInfo) error {
	mode := info.Mode().Perm()
	if mode != 0o700 {
		return fmt.Errorf("%w: %s has mode %o, want 700", ErrParentDirInsecurePermissions, path, mode)
	}
	return nil
}

func ValidateFilePermissions(path string, info os.FileInfo) error {
	mode := info.Mode().Perm()
	if mode != 0o600 {
		return fmt.Errorf("%w: %s has mode %o, want 600", ErrDatabaseFileInsecurePermissions, path, mode)
	}
	return nil
}
