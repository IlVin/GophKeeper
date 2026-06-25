// Package commands координирует разворачивание дерева CLI-команд Cobra
// и оркестрирует инициализацию серверного рантайма GophKeeper.
package commands

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"

	serverapp "gophkeeper/internal/server/app"

	"github.com/spf13/viper"
)

// ServerCLI управляет жизненным циклом и ленивой инициализацией
// центрального контейнера ресурсов серверной части приложения.
type ServerCLI struct {
	v *viper.Viper

	appMu  sync.Mutex
	app    *serverapp.App
	appErr error
}

// NewServerCLI конструирует новый экземпляр управляющего контекста ServerCLI.
func NewServerCLI(v *viper.Viper) *ServerCLI {
	return &ServerCLI{v: v}
}

// App лениво инициализирует, валидирует и бутстрапит серверный контейнер.
//
// Метод потокобезопасен и кэширует как успешный результат аллокации пулов,
// так и фатальные ошибки инициализации для исключения повторных тяжелых сетевых вызовов.
func (c *ServerCLI) App(ctx context.Context) (*serverapp.App, error) {
	c.appMu.Lock()
	defer c.appMu.Unlock()

	// Если контейнер уже успешно развернут — отдаем его из RAM
	if c.app != nil {
		return c.app, nil
	}

	// Защита от циклической инициализации при фатальных сбоях
	if c.appErr != nil {
		slog.Warn("Repeated init request rejected: cached fatal startup failure status")
		return nil, c.appErr
	}

	slog.Info("Starting lazy initialization of cloud server resource container")
	_, app, err := serverapp.Bootstrap(ctx, c.v)
	if err != nil {
		c.appErr = fmt.Errorf("server initialization failed: %w", err)
		return nil, c.appErr
	}

	c.app = app
	c.appErr = nil
	return c.app, nil
}

// Close гарантирует каскадный запуск Graceful Shutdown всех пулов СУБД и gRPC-серверов.
func (c *ServerCLI) Close() error {
	c.appMu.Lock()
	defer c.appMu.Unlock()

	if c.app == nil {
		slog.Debug("Destructor request skipped: server container not initialized")
		return nil
	}

	slog.Info("Initiating forced CLI context shutdown and pool finalization")
	err := c.app.Shutdown()

	// Полностью очищаем ссылки для помощи сборщику мусора (RAM Hygiene)
	c.app = nil
	c.appErr = nil
	return err
}

// PrintResult выполняет централизованный вывод успешных результатов сессии.
func (c *ServerCLI) PrintResult(out io.Writer, payload interface{}, textRender func()) {
	textRender()
}

// PrintError выполняет централизованную обработку, логирование и форматирование сбоев.
func (c *ServerCLI) PrintError(out io.Writer, err error, contextMessage string) error {
	if err == nil {
		return nil
	}

	fullErr := fmt.Errorf("%s: %w", contextMessage, err)
	slog.ErrorContext(context.Background(), "Registering system command runtime failure",
		slog.String("context", contextMessage),
		slog.Any("error", err),
	)

	return fullErr
}
