package config

func (c Config) Validate() error {
	if c.SSHAgent.SocketPath == "" {
		return ErrSSHAgentSocketPathNotSet
	}

	return nil
}
