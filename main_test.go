package main

import (
	"reflect"
	"testing"
)

func TestGetConfig(t *testing.T) {
	configPath := "test/test_config.yaml"
	cfg := YamlConfig{}
	cfg.getconfig(configPath)

	expectedConfig := YamlConfig{
		Remotes: []Remote{
			{
				Server:     "1.1.1.1",
				RemotePort: 22,
				LocalPort:  1339,
				LocalHost:  "127.0.0.1",
				SshServer: SshServer{
					Host:       "55.55.55.55",
					Port:       22022,
					User:       "user1",
					KeyPath:    "ssh-key-1",
					UseKeyPass: false,
					KeyPass:    "",
				},
			},
			{
				Server:     "2.2.2.2",
				RemotePort: 23,
				LocalPort:  1340,
				LocalHost:  "127.0.0.2",
				SshServer: SshServer{
					Host:       "66.66.66.66",
					Port:       1339,
					User:       "user2",
					KeyPath:    "embedKey",
					UseKeyPass: false,
					KeyPass:    "",
				},
			},
		},
	}

	if !reflect.DeepEqual(expectedConfig, cfg) {
		t.Fatal()
	}

}
