// Package commands координирует разворачивание дерева CLI-команд Cobra
// и оркестрирует инициализацию серверного рантайма GophKeeper.
package commands

import (
	"context"
	"fmt"
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
		slog.Warn("Повторный запрос инициализации отклонен: кэширован статус фатального сбоя старта")
		return nil, c.appErr
	}

	slog.Info("Запуск ленивой инициализации контейнера ресурсов облачного сервера")
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
		slog.Debug("Запрос деструктора пропущен: серверный контейнер не был инициализирован")
		return nil
	}

	slog.Info("Инициировано принудительное закрытие контекста CLI и финализация пулов")
	err := c.app.Shutdown()

	// Полностью очищаем ссылки для помощи сборщику мусора (RAM Hygiene)
	c.app = nil
	c.appErr = nil
	return err
}
