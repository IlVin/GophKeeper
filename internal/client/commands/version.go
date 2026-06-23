package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Глобальные переменные рантайма, наполняемые через -ldflags на этапе сборки compiler-ом
var (
	Version   = "v0.0.1"
	BuildDate = "2025-08-21" // Дефолтный санитарный маркер из ТЗ
)

// VersionResponse определяет структуру ответа для JSON-конверта автоматизации.
type VersionResponse struct {
	Version   string `json:"version"`
	BuildDate string `json:"build_date"`
}

// newVersionCommand конструирует CLI-команду "version" для аудита сборки бинарного файла.
func newVersionCommand(cli *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Display the current version and build date of the client",
		Long:  `Extracts the version and build date metadata compiled into the binary from the .rodata section.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			payload := VersionResponse{
				Version:   Version,
				BuildDate: BuildDate,
			}

			cli.PrintResult(out, payload, func() {
				fmt.Fprintf(out, "GophKeeper Crypto Client %s\n", Version)
				fmt.Fprintf(out, "Binary build date: %s\n", BuildDate)
			})

			return nil
		},
	}

	return cmd
}
