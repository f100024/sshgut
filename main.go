// Package main is a build entry point of sshgut.
package main

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"os"
	"sync"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rgzr/sshtun"
	"github.com/rs/zerolog/log"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

// Version is sshgut current version.
var Version = "0.0.0"

// ConfigVersion is a version of supported configuration files.
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
	metricsAddr     = kingpin.Flag("metrics-addr", "Address for Prometheus metrics endpoint (e.g. :9090). Disabled if empty.").Default("").String()
)

var (
	tunnelState = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sshgut_tunnel_state",
		Help: "Current state of SSH tunnel (1 = active, 0 = inactive). States: starting, started, stopped.",
	}, []string{"name", "state"})

	tunnelStateTransitions = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sshgut_tunnel_state_transitions_total",
		Help: "Total number of tunnel state transitions.",
	}, []string{"name", "state"})

	tunneledConnectionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sshgut_tunneled_connections_total",
		Help: "Total number of tunneled connections established.",
	}, []string{"name"})

	tunneledConnectionsActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sshgut_tunneled_connections_active",
		Help: "Number of currently active tunneled connections.",
	}, []string{"name"})

	tunneledConnectionErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sshgut_tunneled_connection_errors_total",
		Help: "Total number of tunneled connection errors.",
	}, []string{"name"})

	tunnelErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sshgut_tunnel_errors_total",
		Help: "Total number of SSH tunnel start errors.",
	}, []string{"name"})

	tunnelRestarts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sshgut_tunnel_restarts_total",
		Help: "Total number of tunnel restart attempts.",
	}, []string{"name"})
)

// Key is a struct with data about ssh key.
type Key struct {
	Path     string `yaml:"path"`
	Password string `yaml:"password"`
}

// Auth is a struct containing authorization data.
type Auth struct {
	Method   string `yaml:"method"`
	Password string `yaml:"password"`
	Key      Key    `yaml:"key"`
}

// SSH is a struct with ssh connection properties.
type SSH struct {
	ForwardType  string   `yaml:"forward_type"`
	KeyExchanges []string `yaml:"key_exchanges"`
	Ciphers      []string `yaml:"ciphers"`
	MACs         []string `yaml:"macs"`
	Host         string   `yaml:"host"`
	Port         int      `yaml:"port"`
	User         string   `yaml:"user"`
	Auth         Auth     `yaml:"auth"`
}

// Remote is a struct containing the remote `Host' and `Port' should be mapped locally.
type Remote struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

// Local is a struct containing the local `Host` and `Port` where will be mapped to the local host.
type Local struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

// ItemConfig struct describes `item` in the configuration file.
type ItemConfig struct {
	Name   string `yaml:"name"`
	Local  Local  `yaml:"local"`
	Remote Remote `yaml:"remote"`
	SSH    SSH    `yaml:"ssh"`
}

// YamlConfig describes version and configuration of the connection
type YamlConfig struct {
	Version string       `yaml:"version"`
	Configs []ItemConfig `yaml:"configs"`
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func getPassword() string {
	fmt.Println("Enter password")
	bytepwd, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal().Str("status", "not started").Msgf("Can not read password input: %v", err)
	}
	strpwd := string(bytepwd)
	clearBytes(bytepwd)
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

func (configData *YamlConfig) getconfig(configPath string) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatal().Str("status", "not started").Msgf("Can not read file: %v", err)
	}
	err = yaml.Unmarshal(data, &configData)
	if err != nil {
		log.Fatal().Str("status", "not started").Msgf("Can not unmarshal yaml config: %v", err)
	}

	if ConfigVersion != configData.Version {
		log.Fatal().Str("status", "not started").
			Msgf("Configuration version %s is not supported. Current config version is %s.", configData.Version, ConfigVersion)
	}

	for index, remote := range configData.Configs {
		// Ask all passwords before start connection if any
		authMethod := remote.SSH.Auth.Method
		authPassword := remote.SSH.Auth.Password
		authKeyPassword := remote.SSH.Auth.Key.Password
		switch {
		case authMethod == "password" && authPassword == "":
			configData.Configs[index].SSH.Auth.Password = getPassword()
		case (authMethod == "key-encrypted" || authMethod == "embedKey-encrypted") && authKeyPassword == "":
			configData.Configs[index].SSH.Auth.Key.Password = getPassword()
		}
	}

}

func createConnection(item *ItemConfig, waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()

	// We make available remoteHostConfig.Server which uses port remoteHostConfig.RemotePort
	// on localhost with port remoteHostConfig.LocalPort via sshConfig.Host using user sshConfig.User
	// and port sshConfig.Port to connect to it.
	sshTun := sshtun.New(item.Local.Port, item.SSH.Host, item.Remote.Port)
	sshTun.SetRemoteHost(item.Remote.Host)
	sshTun.SetUser(item.SSH.User)
	sshTun.SetPort(item.SSH.Port)

	// Bind tunnel in the most obvious way and cover cases where `localHost` is not set in the remote config
	if item.Local.Host != "" {
		sshTun.SetLocalHost(item.Local.Host)
	} else {
		item.Local.Host = "127.0.0.1"
		sshTun.SetLocalHost(item.Local.Host)
	}

	if item.SSH.ForwardType == "remote" {
		sshTun.SetForwardType(1)
	}

	// Supported, forbidden and preferred values
	// are in https://pkg.go.dev/golang.org/x/crypto/ssh#Config
	sshTun.SetKeyExchanges(item.SSH.KeyExchanges)
	sshTun.SetCiphers(item.SSH.Ciphers)
	sshTun.SetMACs(item.SSH.MACs)

	switch sshAuthMethod := item.SSH.Auth.Method; sshAuthMethod {
	case "password":
		sshTun.SetPassword(item.SSH.Auth.Password)
	case "key":
		sshTun.SetKeyFile(item.SSH.Auth.Key.Path)
	case "key-encrypted":
		sshTun.SetEncryptedKeyFile(item.SSH.Auth.Key.Path, item.SSH.Auth.Key.Password)
	case "embedKey":
		sshTun.SetKeyReader(bytes.NewBuffer(embedKey))
	case "embedKey-encrypted":
		sshTun.SetEncryptedKeyReader(bytes.NewBuffer(embedKey), item.SSH.Auth.Key.Password)
	}

	// We print each tunneled state to see the connections status
	sshTun.SetTunneledConnState(func(tun *sshtun.SSHTun, state *sshtun.TunneledConnState) {
		if *debugMode {
			log.Debug().Str("status", "ok").Str("name", item.Name).Msgf("%+v", state)
		}
		if state.Ready {
			tunneledConnectionsTotal.WithLabelValues(item.Name).Inc()
			tunneledConnectionsActive.WithLabelValues(item.Name).Inc()
		}
		if state.Closed {
			tunneledConnectionsActive.WithLabelValues(item.Name).Dec()
		}
		if state.Error != nil {
			tunneledConnectionErrors.WithLabelValues(item.Name).Inc()
		}
	})

	// We set a callback to know when the tunnel is ready
	sshTun.SetConnState(func(tun *sshtun.SSHTun, state sshtun.ConnState) {
		switch state {
		case sshtun.StateStarting:
			log.Info().Str("status", "starting").Str("name", item.Name).Msgf("Host %v port %v available on %v:%v",
				item.Remote.Host, item.Remote.Port, item.Local.Host, item.Local.Port)
			tunnelState.WithLabelValues(item.Name, "starting").Set(1)
			tunnelState.WithLabelValues(item.Name, "started").Set(0)
			tunnelState.WithLabelValues(item.Name, "stopped").Set(0)
			tunnelStateTransitions.WithLabelValues(item.Name, "starting").Inc()
		case sshtun.StateStarted:
			log.Info().Str("status", "started").Str("name", item.Name).Msgf("Host %v port %v available on %v:%v",
				item.Remote.Host, item.Remote.Port, item.Local.Host, item.Local.Port)
			tunnelState.WithLabelValues(item.Name, "starting").Set(0)
			tunnelState.WithLabelValues(item.Name, "started").Set(1)
			tunnelState.WithLabelValues(item.Name, "stopped").Set(0)
			tunnelStateTransitions.WithLabelValues(item.Name, "started").Inc()
		case sshtun.StateStopped:
			log.Info().Str("status", "stopped").Str("name", item.Name).Msgf("Host %v port %v available on %v:%v",
				item.Remote.Host, item.Remote.Port, item.Local.Host, item.Local.Port)
			tunnelState.WithLabelValues(item.Name, "starting").Set(0)
			tunnelState.WithLabelValues(item.Name, "started").Set(0)
			tunnelState.WithLabelValues(item.Name, "stopped").Set(1)
			tunnelStateTransitions.WithLabelValues(item.Name, "stopped").Inc()
		}
	})

	// We start the tunnel (and restart it every time it is stopped)
	for {
		tunnelRestarts.WithLabelValues(item.Name).Inc()
		if err := sshTun.Start(context.Background()); err != nil {
			log.Error().Msgf("SSH tunnel error: %v", err)
			tunnelErrors.WithLabelValues(item.Name).Inc()
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

	if *metricsAddr != "" {
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())
			log.Info().Msgf("Starting metrics server on %s", *metricsAddr)
			if err := http.ListenAndServe(*metricsAddr, mux); err != nil {
				log.Fatal().Msgf("Metrics server error: %v", err)
			}
		}()
	}

	wg.Add(len(cfg.Configs))
	for _, remote := range finalConfigs {
		go createConnection(&remote, &wg)
	}
	wg.Wait()
}
