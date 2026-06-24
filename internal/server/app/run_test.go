package app_test

import (
	"testing"

	"gophkeeper/internal/server/app"

	"github.com/stretchr/testify/assert"
)

// TestApp_Run_FailsIfNil Fail-Fast security barrier: startup on nil objects must
// сразу возвращать ошибку рантайма, предотвращая неконтролируемые паники.
func TestApp_Run_FailsIfNil(t *testing.T) {
	dummyApp := &app.App{
		GRPCServer:   nil,
		Listener:     nil,
		AcmeListener: nil,
		Pool:         nil,
	}

	err := dummyApp.Run()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "grpc server or listener not initialized")
}

// TestApp_Shutdown_ShouldNotPanicПроверяет устойчивость деструктора к очистке пустых полей.
func TestApp_Shutdown_ShouldNotPanic(t *testing.T) {
	dummyApp := &app.App{
		GRPCServer:   nil,
		Listener:     nil,
		AcmeListener: nil,
		Pool:         nil,
	}

	assert.NotPanics(t, func() {
		err := dummyApp.Shutdown()
		assert.NoError(t, err)
	}, "Destructor must safely handle nil resource fields")
}
