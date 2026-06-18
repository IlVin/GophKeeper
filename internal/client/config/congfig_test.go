package config

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_StructureAndTags(t *testing.T) {
	t.Parallel()

	cfgType := reflect.TypeOf(Config{})

	appField, hasApp := cfgType.FieldByName("App")
	require.True(t, hasApp)
	assert.Equal(t, "app", appField.Tag.Get("mapstructure"))

	sshField, hasSSH := cfgType.FieldByName("SSHAgent")
	require.True(t, hasSSH)
	assert.Equal(t, "ssh_agent", sshField.Tag.Get("mapstructure"))

	storageField, hasStorage := cfgType.FieldByName("Storage")
	require.True(t, hasStorage)
	assert.Equal(t, "storage", storageField.Tag.Get("mapstructure"))
}
