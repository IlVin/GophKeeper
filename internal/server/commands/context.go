// Package commands координирует разворачивание дерева CLI-команд Cobra
// и оркестрирует инициализацию серверного рантайма GophKeeper.
package commands

import (
	"errors"

	serverapp "gophkeeper/internal/server/app"

	"github.com/spf13/cobra"
)

// AppFromCommand безопасно извлекает центральный контейнер ресурсов App
// из контекста запущенной консольной Cobra-команды сервера.
//
// Функция верифицирует указатель на команду, защищая рантайм от паник,
// и делегирует извлечение нижележащему доменному пакету serverapp.
func AppFromCommand(cmd *cobra.Command) (*serverapp.App, error) {
	if cmd == nil {
		return nil, errors.New("cannot extract app container from a nil cobra command")
	}

	return serverapp.AppFromContext(cmd.Context())
}
