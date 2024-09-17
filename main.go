package main

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"time"

	"os"
	"sync"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
	"github.com/rgzr/sshtun"
	"github.com/rs/zerolog/log"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

var Version = "0.2.0"
var wg sync.WaitGroup

//go:embed embedKey.ssh
var embedKey []byte

var (
	configPath = kingpin.Flag("config", "Path to the configuration file").Default("config.yaml").ExistingFile()
)

type SshServer struct {
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	User         string `yaml:"user"`
	KeyPath      string `yaml:"keyPath"`
	UseKeyPass   bool   `yaml:"useKeyPass"`
	KeyPass      string `yaml:"keyPass"`
	UserPassword string `yaml:"userPassword"`
}

type Remote struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type Local struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type ItemConfig struct {
	Name      string    `yaml:"name"`
	Local     Local     `yaml:"local"`
	Remote    Remote    `yaml:"remote"`
	SshServer SshServer `yaml:"sshServer"`
}

type YamlConfig struct {
	Version string       `yaml:"version"`
	Configs []ItemConfig `yaml:"configs"`
}

func (cfg *YamlConfig) getconfig(configPath string) {
	configData, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatal().Str("status", "not started").Msgf("Can not read file: %v", err)
	}
	err = yaml.Unmarshal(configData, &cfg)
	if err != nil {
		log.Fatal().Str("status", "not started").Msgf("Can not unmarshal yaml config: %v", err)
	}

	for index, remote := range cfg.Configs {
		// Ask passphrase for encrypted ssh key
		if remote.SshServer.UseKeyPass && remote.SshServer.KeyPass == "" {
			fmt.Println("Enter password for encrypted ssh key")
			bytepw, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				log.Fatal().Str("status", "not started").Msgf("Can not read password input: %v", err)
			}
			cfg.Configs[index].SshServer.KeyPass = string(bytepw)
		}
	}
}

func createConnection(item *ItemConfig, waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()

	// We make available remoteHostConfig.Server which uses port remoteHostConfig.RemotePort
	// on localhost with port remoteHostConfig.LocalPort via sshConfig.Host using user sshConfig.User
	// and port sshConfig.Port to connect to it.
	sshTun := sshtun.New(item.Local.Port, item.SshServer.Host, item.Remote.Port)
	sshTun.SetRemoteHost(item.Remote.Host)
	sshTun.SetUser(item.SshServer.User)
	sshTun.SetPort(item.SshServer.Port)

	// Bind tunnel in the most obvious way and cover cases where `localHost` is not set in the remote config
	if item.Local.Host != "" {
		sshTun.SetLocalHost(item.Local.Host)
	} else {
		item.Local.Host = "127.0.0.1"
		sshTun.SetLocalHost(item.Local.Host)
	}
	if item.SshServer.KeyPath != "" {
		// When using embed key without encryption
		if item.SshServer.KeyPath == "embedKey" && !item.SshServer.UseKeyPass && len(embedKey) > 0 {
			sshTun.SetKeyReader(bytes.NewBuffer(embedKey))
			// When using embed key with encryption
		} else if item.SshServer.KeyPath == "embedKey" && item.SshServer.UseKeyPass && len(embedKey) > 0 {
			sshTun.SetEncryptedKeyReader(bytes.NewBuffer(embedKey), item.SshServer.KeyPass)
			// When using encrypted key from disk
		} else if item.SshServer.UseKeyPass {
			sshTun.SetEncryptedKeyFile(item.SshServer.KeyPath, item.SshServer.KeyPass)
			// When using ssh key from disk without encryption
		} else {
			sshTun.SetKeyFile(item.SshServer.KeyPath)
		}
	}
	if item.SshServer.UserPassword != "" {
		sshTun.SetPassword(item.SshServer.UserPassword)
	}

	// We print each tunneled state to see the connections status
	sshTun.SetTunneledConnState(func(tun *sshtun.SSHTun, state *sshtun.TunneledConnState) {
		log.Info().Str("status", "ok").Msgf("%+v", state)
	})

	// We set a callback to know when the tunnel is ready
	sshTun.SetConnState(func(tun *sshtun.SSHTun, state sshtun.ConnState) {
		switch state {
		case sshtun.StateStarting:
			log.Info().Str("status", "starting").Msgf("Host %v port %v available on %v:%v",
				item.Remote.Host, item.Remote.Port, item.Local.Host, item.Local.Port)
		case sshtun.StateStarted:
			log.Info().Str("status", "started").Msgf("Host %v port %v available on %v:%v",
				item.Remote.Host, item.Remote.Port, item.Local.Host, item.Local.Port)
		case sshtun.StateStopped:
			log.Info().Str("status", "stopped").Msgf("Host %v port %v available on %v:%v",
				item.Remote.Host, item.Remote.Port, item.Local.Host, item.Local.Port)
		}
	})

	// We start the tunnel (and restart it every time it is stopped)
	for {
		if err := sshTun.Start(context.Background()); err != nil {
			log.Error().Msgf("SSH tunnel error: %v", err)
			time.Sleep(time.Second)
		}
	}
}

func main() {
	kingpin.Version(Version)
	kingpin.Parse()

	cfg := YamlConfig{}
	cfg.getconfig(*configPath)

	wg.Add(len(cfg.Configs))
	for _, remote := range cfg.Configs {
		go createConnection(&remote, &wg)
	}
	wg.Wait()
}
