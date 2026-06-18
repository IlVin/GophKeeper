package commands

import (
	"context"
	serverapp "gophkeeper/internal/server/app"
	"gophkeeper/internal/server/config"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestAppFromCommand_Success(t *testing.T) {
	var cfg config.Config
	application := serverapp.NewApp(cfg, nil, nil, nil)

	ctx := context.Background()
	ctx = serverapp.WithApp(ctx, application)

	cmd := &cobra.Command{
		Use: "test",
		Run: func(cmd *cobra.Command, args []string) {},
	}
	cmd.SetContext(ctx)

	extracted, err := AppFromCommand(cmd)
	assert.NoError(t, err)
	assert.Equal(t, application, extracted)
}

func TestAppFromCommand_FailureWhenMissing(t *testing.T) {
	cmd := &cobra.Command{
		Use: "test",
		Run: func(cmd *cobra.Command, args []string) {},
	}
	cmd.SetContext(context.Background())

	extracted, err := AppFromCommand(cmd)
	assert.Error(t, err)
	assert.Nil(t, extracted)
	assert.ErrorContains(t, err, "server app is missing in context")
}
