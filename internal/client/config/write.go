package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func WriteDefaultConfigFile(path string, cfg Config) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory %q: %w", dir, err)
	}

	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat config file %q: %w", path, err)
	}

	content := []byte(fmt.Sprintf(
		"app:\n  config_file: %s\nstorage:\n  sqlite_path: %s\n",
		cfg.App.ConfigFile,
		cfg.Storage.SQLitePath,
	))

	if err := os.WriteFile(path, content, 0o600); err != nil {
		return fmt.Errorf("write config file %q: %w", path, err)
	}

	return nil
}
