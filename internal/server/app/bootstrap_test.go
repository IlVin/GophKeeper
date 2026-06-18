package app_test

import (
	"context"
	"testing"

	"gophkeeper/internal/server/app"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestBootstrap_InvalidConfigError(t *testing.T) {
	ctx := context.Background()
	v := viper.New()
	v.Set("server.config_file", "non_existent_file_path.yaml")

	_, application, err := app.Bootstrap(ctx, v)
	assert.Error(t, err)
	assert.Nil(t, application)
}
