// Package config описывает структуры данных конфигурации клиентского приложения GophKeeper.
//
// Пакет инкапсулирует настройки расположения локального крипто-контейнера,
// параметры логирования и сетевые адреса синхронизации, предоставляя к ним
// безопасный, неизменяемый доступ.
package config

import "errors"

var (
	// ErrSQLitePathNotSet возвращается, если в конфигурации не указан путь к базе данных SQLite.
	ErrSQLitePathNotSet = errors.New("путь к базе данных sqlite (sqlite_path) не задан")
)

// Config является корневым контейнером конфигурации приложения.
// Все поля инкапсулированы для обеспечения потокобезопасности рантайма.
type Config struct {
	app     AppConfig
	storage StorageConfig
	logging LoggingConfig
}

// AppConfig инкапсулирует глобальные системные настройки CLI-клиента.
type AppConfig struct {
	configFile    string
	defaultServer string
}

// NewAppConfig конструирует объект AppConfig с приватными полями.
func NewAppConfig(configFile, defaultServer string) AppConfig {
	return AppConfig{
		configFile:    configFile,
		defaultServer: defaultServer,
	}
}

// StorageConfig инкапсулирует параметры локального криптографического хранилища.
type StorageConfig struct {
	sqlitePath string
}

// NewStorageConfig конструирует объект StorageConfig с приватными полями.
func NewStorageConfig(sqlitePath string) StorageConfig {
	return StorageConfig{
		sqlitePath: sqlitePath,
	}
}

// LoggingConfig инкапсулирует параметры подсистемы логирования.
type LoggingConfig struct {
	logFile string
	level   string
	format  string
}

// NewLoggingConfig конструирует объект LoggingConfig с приватными полями.
func NewLoggingConfig(logFile, level, format string) LoggingConfig {
	return LoggingConfig{
		logFile: logFile,
		level:   level,
		format:  format,
	}
}

// NewConfig конструирует валидированный и неизменяемый объект Config.
func NewConfig(app AppConfig, storage StorageConfig, logging LoggingConfig) Config {
	return Config{
		app:     app,
		storage: storage,
		logging: logging,
	}
}

// App возвращает параметры системных настроек CLI-клиента.
func (c Config) App() AppConfig { return c.app }

// Storage returns параметры локального хранилища СУБД.
func (c Config) Storage() StorageConfig { return c.storage }

// Logging returns параметры подсистемы логирования.
func (c Config) Logging() LoggingConfig { return c.logging }

// ConfigFile возвращает абсолютный путь к текущему YAML-файлу конфигурации на диске.
func (a AppConfig) ConfigFile() string { return a.configFile }

// DefaultServer возвращает адрес gRPC-сервера по умолчанию для регистрации и синхронизации.
func (a AppConfig) DefaultServer() string { return a.defaultServer }

// SQLitePath возвращает путь к файлу зашифрованного контейнера SQLite.
func (s StorageConfig) SQLitePath() string { return s.sqlitePath }

// LogFile возвращает путь к файлу, в который перенаправлен поток slog.
func (l LoggingConfig) LogFile() string { return l.logFile }

// Level возвращает текущий текстовый уровень фильтрации логов (debug, info, warn, error).
func (l LoggingConfig) Level() string { return l.level }

// Format возвращает целевой формат сериализации логов (text или json).
func (l LoggingConfig) Format() string { return l.format }
