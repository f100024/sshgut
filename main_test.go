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
		Version: "2",
		Configs: []ItemConfig{
			{
				Name: "server_name_1",
				Local: Local{
					Host: "127.0.0.1",
					Port: 8080,
				},
				Remote: Remote{
					Host: "1.1.1.1",
					Port: 11111,
				},
				SSH: SSH{
					Host: "11.11.11.11",
					User: "user1",
					Port: 22,
					Auth: Auth{
						Method:   "password",
						Password: "1",
						Key: Key{
							Path:     "",
							Password: "",
						},
					},
				},
			},
			{
				Name: "server_name_2",
				Local: Local{
					Host: "127.0.0.1",
					Port: 8080,
				},
				Remote: Remote{
					Host: "2.2.2.2",
					Port: 22222,
				},
				SSH: SSH{
					Host: "22.22.22.22",
					User: "user2",
					Port: 22,
					Auth: Auth{
						Method:   "key",
						Password: "",
						Key: Key{
							Path:     "/home/user2/.ssh/ssh.key",
							Password: "",
						},
					},
				},
			},
			{
				Name: "server_name_3",
				Local: Local{
					Host: "127.0.0.1",
					Port: 8888,
				},
				Remote: Remote{
					Host: "3.3.3.3",
					Port: 33333,
				},
				SSH: SSH{
					Host: "33.33.33.33",
					User: "user3",
					Port: 22,
					Auth: Auth{
						Method:   "embedKey",
						Password: "",
						Key: Key{
							Path:     "",
							Password: "",
						},
					},
				},
			},
			{
				Name: "server_name_4",
				Local: Local{
					Host: "127.0.0.1",
					Port: 8888,
				},
				Remote: Remote{
					Host: "4.4.4.4",
					Port: 44444,
				},
				SSH: SSH{
					Host: "44.44.44.44",
					User: "user4",
					Port: 22,
					Auth: Auth{
						Method:   "key-encrypted",
						Password: "",
						Key: Key{
							Path:     "/home/user4/.ssh/ssh.key",
							Password: "1234",
						},
					},
				},
			},
			{
				Name: "server_name_5",
				Local: Local{
					Host: "127.0.0.1",
					Port: 8888,
				},
				Remote: Remote{
					Host: "5.5.5.5",
					Port: 55555,
				},
				SSH: SSH{
					Host: "55.55.55.55",
					User: "user5",
					Port: 22,
					Auth: Auth{
						Method:   "embedKey-encrypted",
						Password: "",
						Key: Key{
							Path:     "/home/user5/.ssh/ssh.key",
							Password: "1234",
						},
					},
				},
			},
		},
	}

	if !reflect.DeepEqual(expectedConfig, cfg) {
		t.Fatal()
	}

}
