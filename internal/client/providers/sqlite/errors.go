package sqlite

import "errors"

var (
	ErrEmptyPath                       = errors.New("sqlite path is empty")
	ErrParentDirNotDirectory           = errors.New("parent path is not a directory")
	ErrParentDirInsecurePermissions    = errors.New("parent directory has insecure permissions")
	ErrDatabaseFileNotRegular          = errors.New("database path is not a regular file")
	ErrDatabaseFileInsecurePermissions = errors.New("database file has insecure permissions")
)
