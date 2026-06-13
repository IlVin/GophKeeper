package main

import (
	"log"

	"gophkeeper/internal/cli"
	"gophkeeper/internal/config"
)

func main() {
	v := config.NewViper()

	cmd, err := cli.NewRootCommand(v)
	if err != nil {
		log.Fatal(err)
	}

	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
