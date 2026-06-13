var (
	vp         = viper.New()
	configFile string
	rootCmd    = &cobra.Command{
		Use: "gophkeeper",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if configFile != "" {
				vp.SetConfigFile(configFile)
				if err := vp.ReadInConfig(); err != nil {
					return err
				}
			}

			cfg, err := config.LoadFromViper(vp)
			if err != nil {
				return err
			}

			_ = cfg // сохранить куда нужно
			return nil
		},
	}
)

func init() {
	vp.SetEnvPrefix("GOPHKEEPER")
	vp.AutomaticEnv()
	vp.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "path to config file")
	rootCmd.PersistentFlags().String("ssh-agent-sock", "", "path to SSH agent socket")

	_ = vp.BindPFlag("app.config_file", rootCmd.PersistentFlags().Lookup("config"))
	_ = vp.BindPFlag("ssh_agent.socket_path", rootCmd.PersistentFlags().Lookup("ssh-agent-sock"))
}