package main

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"

	"os"
	"sync"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/rgzr/sshtun"
	"github.com/rs/zerolog/log"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

var Version = "0.0.0"
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
	Server     string    `yaml:"server"`
	RemotePort int       `yaml:"remotePort"`
	LocalPort  int       `yaml:"localPort"`
	LocalHost  string    `yaml:"localHost"`
	SshServer  SshServer `yaml:"sshServer"`
}

type YamlConfig struct {
	Remotes []Remote `yaml:"remotes"`
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

	for index, remote := range cfg.Remotes {
		// Ask passphrase for encrypted ssh key
		if remote.SshServer.UseKeyPass && remote.SshServer.KeyPass == "" {
			fmt.Println("Enter password for encrypted ssh key")
			bytepw, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				log.Fatal().Str("status", "not started").Msgf("Can not read password input: %v", err)
			}
			cfg.Remotes[index].SshServer.KeyPass = string(bytepw)
		}
	}
}

func createConnection(sshConfig *SshServer, remoteHostConfig Remote, waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()

	// We make available remoteHostConfig.Server which uses port remoteHostConfig.RemotePort
	// on localhost with port remoteHostConfig.LocalPort via sshConfig.Host using user sshConfig.User
	// and port sshConfig.Port to connect to it.
	sshTun := sshtun.New(remoteHostConfig.LocalPort, sshConfig.Host, remoteHostConfig.RemotePort)
	sshTun.SetRemoteHost(remoteHostConfig.Server)
	sshTun.SetUser(sshConfig.User)
	sshTun.SetPort(sshConfig.Port)

	// Bind tunnel in the most obvious way and cover cases where `localHost` is not set in the remote config
	if remoteHostConfig.LocalHost != "" {
		sshTun.SetLocalHost(remoteHostConfig.LocalHost)
	} else {
		remoteHostConfig.LocalHost = "127.0.0.1"
		sshTun.SetLocalHost(remoteHostConfig.LocalHost)
	}
	if sshConfig.KeyPath != "" {
		// When using embed key without encryption
		if sshConfig.KeyPath == "embedKey" && !sshConfig.UseKeyPass && len(embedKey) > 0 {
			sshTun.SetKeyReader(bytes.NewBuffer(embedKey))
			// When using embed key with encryption
		} else if sshConfig.KeyPath == "embedKey" && sshConfig.UseKeyPass && len(embedKey) > 0 {
			sshTun.SetEncryptedKeyReader(bytes.NewBuffer(embedKey), sshConfig.KeyPass)
			// When using encrypted key from disk
		} else if sshConfig.UseKeyPass {
			sshTun.SetEncryptedKeyFile(sshConfig.KeyPath, sshConfig.KeyPass)
			// When using ssh key from disk without encryption
		} else {
			sshTun.SetKeyFile(sshConfig.KeyPath)
		}
	}
	if sshConfig.UserPassword != "" {
		sshTun.SetPassword(sshConfig.UserPassword)
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
				remoteHostConfig.Server, remoteHostConfig.RemotePort, remoteHostConfig.LocalHost, remoteHostConfig.LocalPort)
		case sshtun.StateStarted:
			log.Info().Str("status", "started").Msgf("Host %v port %v available on %v:%v",
				remoteHostConfig.Server, remoteHostConfig.RemotePort, remoteHostConfig.LocalHost, remoteHostConfig.LocalPort)
		case sshtun.StateStopped:
			log.Info().Str("status", "stopped").Msgf("Host %v port %v available on %v:%v",
				remoteHostConfig.Server, remoteHostConfig.RemotePort, remoteHostConfig.LocalHost, remoteHostConfig.LocalPort)
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

	wg.Add(len(cfg.Remotes))
	for _, remote := range cfg.Remotes {
		go createConnection(&remote.SshServer, remote, &wg)
	}
	wg.Wait()
}
