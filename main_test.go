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
		Version: "0.2",
		Configs: []ItemConfig{
			{
				Name: "server_name_0",
				Local: Local{
					Host: "127.0.0.1",
					Port: 8080,
				},
				Remote: Remote{
					Host: "1.1.1.1",
					Port: 7777,
				},
				SshServer: SshServer{
					Host:         "55.55.55.55",
					User:         "user0",
					KeyPath:      "",
					KeyPass:      "",
					UseKeyPass:   false,
					Port:         22,
					UserPassword: "1",
				},
			},
			{
				Name: "server_name_1",
				Local: Local{
					Host: "127.0.0.1",
					Port: 8888,
				},
				Remote: Remote{
					Host: "2.2.2.2",
					Port: 44444,
				},
				SshServer: SshServer{
					Host:         "66.66.66.66",
					User:         "user1",
					Port:         22,
					KeyPath:      "/home/user1/.ssh/ssh.key",
					UseKeyPass:   false,
					KeyPass:      "",
					UserPassword: "",
				},
			},
			{
				Name: "server_name_2",
				Local: Local{
					Host: "127.0.0.1",
					Port: 8888,
				},
				Remote: Remote{
					Host: "3.3.3.3",
					Port: 55555,
				},
				SshServer: SshServer{
					Host:         "77.77.77.77",
					User:         "user2",
					Port:         22,
					KeyPath:      "embedKey",
					UseKeyPass:   false,
					KeyPass:      "",
					UserPassword: "",
				},
			},
		},
	}

	if !reflect.DeepEqual(expectedConfig, cfg) {
		t.Fatal()
	}

}
