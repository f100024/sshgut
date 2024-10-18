package main

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"slices"
	"strings"
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

var Version = "0.0.0"
var ConfigVersion = "2"
var wg sync.WaitGroup

//go:embed embedKey.ssh
var embedKey []byte

var (
	debugMode       = kingpin.Flag("debug", "Add debug logs").Bool()
	configPath      = kingpin.Flag("config", "Path to the configuration file").Default("config.yaml").ExistingFile()
	configShow      = kingpin.Flag("config-show", "Show configuration file").Bool()
	configShowNames = kingpin.Flag("config-show-names", "Show names from configuration file").Bool()
	runCustomNames  = kingpin.Flag("run-custom-names", "Establish connection to custom names from config. Delimiter:','").String()
)

type Key struct {
	Path     string `yaml:"path"`
	Password string `yaml:"password"`
}

type Auth struct {
	Method   string `yaml:"method"`
	Password string `yaml:"password"`
	Key      Key    `yaml:"key"`
}

type Ssh struct {
	ForwardType string `yaml:"forward_type"`
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	User        string `yaml:"user"`
	Auth        Auth   `yaml:"auth"`
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
	Name   string `yaml:"name"`
	Local  Local  `yaml:"local"`
	Remote Remote `yaml:"remote"`
	Ssh    Ssh    `yaml:"ssh"`
}

type YamlConfig struct {
	Version string       `yaml:"version"`
	Configs []ItemConfig `yaml:"configs"`
}

func getPassword() string {
	fmt.Println("Enter password")
	bytepwd, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal().Str("status", "not started").Msgf("Can not read password input: %v", err)
	}
	strpwd := string(bytepwd)
	return strpwd
}

func (configData *YamlConfig) showConfig() {
	data, err := yaml.Marshal(configData)
	if err != nil {
		log.Fatal().Str("status", "error").Msgf("Can not marshal config data: %v", err)
	}
	fmt.Println(string(data))
}

func (configData *YamlConfig) showConfigNames() {
	for _, config := range configData.Configs {
		fmt.Println(config.Name)
	}
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

	if ConfigVersion != cfg.Version {
		log.Fatal().Str("status", "not started").
			Msgf("Configuration version %s is not supported. Current config version is %s.", cfg.Version, ConfigVersion)
	}

	for index, remote := range cfg.Configs {
		// Ask all passwords before start connection if any
		authMethod := remote.Ssh.Auth.Method
		authPassword := remote.Ssh.Auth.Password
		authKeyPassword := remote.Ssh.Auth.Key.Password
		switch {
		case authMethod == "password" && authPassword == "":
			cfg.Configs[index].Ssh.Auth.Password = getPassword()
		case (authMethod == "key-encrypted" || authMethod == "embedKey-encrypted") && authKeyPassword == "":
			cfg.Configs[index].Ssh.Auth.Key.Password = getPassword()
		}
	}

}

func createConnection(item *ItemConfig, waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()

	// We make available remoteHostConfig.Server which uses port remoteHostConfig.RemotePort
	// on localhost with port remoteHostConfig.LocalPort via sshConfig.Host using user sshConfig.User
	// and port sshConfig.Port to connect to it.
	sshTun := sshtun.New(item.Local.Port, item.Ssh.Host, item.Remote.Port)
	sshTun.SetRemoteHost(item.Remote.Host)
	sshTun.SetUser(item.Ssh.User)
	sshTun.SetPort(item.Ssh.Port)

	// Bind tunnel in the most obvious way and cover cases where `localHost` is not set in the remote config
	if item.Local.Host != "" {
		sshTun.SetLocalHost(item.Local.Host)
	} else {
		item.Local.Host = "127.0.0.1"
		sshTun.SetLocalHost(item.Local.Host)
	}

	if item.Ssh.ForwardType == "remote" {
		sshTun.SetForwardType(1)
	}

	switch sshAuthMethod := item.Ssh.Auth.Method; sshAuthMethod {
	case "password":
		sshTun.SetPassword(item.Ssh.Auth.Password)
	case "key":
		sshTun.SetKeyFile(item.Ssh.Auth.Key.Path)
	case "key-encrypted":
		sshTun.SetEncryptedKeyFile(item.Ssh.Auth.Key.Path, item.Ssh.Auth.Key.Password)
	case "embedKey":
		sshTun.SetKeyReader(bytes.NewBuffer(embedKey))
	case "embedKey-encrypted":
		sshTun.SetEncryptedKeyReader(bytes.NewBuffer(embedKey), item.Ssh.Auth.Key.Password)
	}

	// We print each tunneled state to see the connections status
	sshTun.SetTunneledConnState(func(tun *sshtun.SSHTun, state *sshtun.TunneledConnState) {
		if *debugMode {
			log.Debug().Str("status", "ok").Str("name", item.Name).Msgf("%+v", state)
		}
	})

	// We set a callback to know when the tunnel is ready
	sshTun.SetConnState(func(tun *sshtun.SSHTun, state sshtun.ConnState) {
		switch state {
		case sshtun.StateStarting:
			log.Info().Str("status", "starting").Str("name", item.Name).Msgf("Host %v port %v available on %v:%v",
				item.Remote.Host, item.Remote.Port, item.Local.Host, item.Local.Port)
		case sshtun.StateStarted:
			log.Info().Str("status", "started").Str("name", item.Name).Msgf("Host %v port %v available on %v:%v",
				item.Remote.Host, item.Remote.Port, item.Local.Host, item.Local.Port)
		case sshtun.StateStopped:
			log.Info().Str("status", "stopped").Str("name", item.Name).Msgf("Host %v port %v available on %v:%v",
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
	finalConfigs := cfg.Configs

	switch {
	case *configShow:
		cfg.showConfig()
		os.Exit(0)
	case *configShowNames:
		cfg.showConfigNames()
		os.Exit(0)
	case len(*runCustomNames) > 0:
		finalConfigs = func() []ItemConfig {
			customConfigs := []ItemConfig{}
			parsedNames := strings.Split(*runCustomNames, ",")
			for _, item := range finalConfigs {
				if slices.Contains(parsedNames, item.Name) {
					customConfigs = append(customConfigs, item)
				}
			}
			return customConfigs
		}()
	}

	wg.Add(len(cfg.Configs))
	for _, remote := range finalConfigs {
		go createConnection(&remote, &wg)
	}
	wg.Wait()
}
