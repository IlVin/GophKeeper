// Package config предоставляет инструменты для верификации и валидации
// доменных инвариантов конфигурации утилиты GophKeeper.
package config

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrInvalidLogLevel возвращается при передаче неподдерживаемого уровня логирования.
	ErrInvalidLogLevel = errors.New("неподдерживаемый уровень логирования: допустимы debug, info, warn, error")
	// ErrInvalidLogFormat возвращается при передаче неподдерживаемого формата вывода логов.
	ErrInvalidLogFormat = errors.New("неподдерживаемый формат логирования: допустимы text, json")
)

// Validate осуществляет комплексную проверку всех параметров конфигурации.
//
// Функция реализует паттерн Fail-Fast, проверяя обязательность заполнения
// пути к СУБД, а также соответствие настроек логирования допустимым стандартам ИБ.
func (c Config) Validate() error {
	// 1. Контроль обязательного наличия пути к зашифрованному контейнеру
	if strings.TrimSpace(c.Storage().SQLitePath()) == "" {
		return ErrSQLitePathNotSet
	}

	// 2. Валидация доменного уровня логирования
	level := strings.ToLower(strings.TrimSpace(c.Logging().Level()))
	switch level {
	case "debug", "info", "warn", "error":
		// Уровень валиден
	default:
		return fmt.Errorf("%w: %q", ErrInvalidLogLevel, level)
	}

	// 3. Валидация формата сериализации структурированных логов
	format := strings.ToLower(strings.TrimSpace(c.Logging().Format()))
	switch format {
	case "text", "json":
		// Формат валиден
	default:
		return fmt.Errorf("%w: %q", ErrInvalidLogFormat, format)
	}

	return nil
}
