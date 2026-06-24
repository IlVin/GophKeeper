// Package app предоставляет контейнер времени выполнения (runtime) для клиентского приложения GophKeeper.
//
// Контейнер инкапсулирует конфигурацию сессии и пул соединений с локальной СУБД SQLite,
// обеспечивая контролируемый доступ к ресурсам из CLI-команд и сервисов.
package app

import (
	"database/sql"
	"errors"

	"gophkeeper/internal/client/config"
)

var (
	// ErrNilDatabase Connection возвращается, если в конструктор передана пустая ссылка на СУБД.
	ErrNilDatabase = errors.New("database connection pool cannot be nil")
)

// App представляет собой изолированный рантайм-контейнер ресурсов приложения.
//
// Все поля структуры являются приватными для предотвращения неконтролируемой
// модификации конфигурации или дескрипторов СУБД в процессе работы CLI-команд.
type App struct {
	config config.Config
	db     *sql.DB
}

// NewApp конструирует и валидирует новый экземпляр контейнера приложения App.
//
// Возвращает заполненную структуру, если все зависимости удовлетворяют
// критериям надежности, или ошибку, если передан некорректный пул СУБД.
func NewApp(cfg config.Config, db *sql.DB) (*App, error) {
	if db == nil {
		return nil, ErrNilDatabase
	}

	return &App{
		config: cfg,
		db:     db,
	}, nil
}

// DB возвращает потокобезопасный пул соединений с базой данных SQLite.
func (a *App) DB() *sql.DB {
	return a.db
}

// Config возвращает слепок текущей конфигурации приложения, активной в рамках сессии.
func (a *App) Config() config.Config {
	return a.config
}
