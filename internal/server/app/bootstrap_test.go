package app

import (
	"context"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// TestBootstrap_WithEmptyViper_ShouldSourceError проверяет срабатывание Fail-Fast
// барьера лоадера, если в метод инициализации передан пустой объект Viper без DSN.
func TestBootstrap_WithEmptyViper_ShouldSourceError(t *testing.T) {
	ctx := context.Background()
	emptyViper := viper.New()

	ctxResult, application, err := Bootstrap(ctx, emptyViper)
	assert.Error(t, err)
	assert.Nil(t, application)
	assert.NotNil(t, ctxResult)
}
