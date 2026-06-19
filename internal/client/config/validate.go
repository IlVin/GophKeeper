package config

import "strings"

func (c Config) Validate() error {
	if strings.TrimSpace(c.Storage.SQLitePath) == "" {
		return ErrSQLitePathNotSet
	}

	return nil
}
