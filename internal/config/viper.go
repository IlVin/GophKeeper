package config

import (
	"strings"

	"github.com/spf13/viper"
)

func NewViper() *viper.Viper {
	v := viper.New()

	v.SetEnvPrefix("GOPHKEEPER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetDefault("app.config_file", "")
	v.SetDefault("ssh_agent.socket_path", "")

	return v
}
