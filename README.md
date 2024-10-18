# SSHGUT

The project is used to set up ssh tunnels and is essentially a wrapper around https://github.com/rgzr/sshtun.


## Configuration
Example of the configuration file `config.yaml.example`

```
---
version: "2"
configs:
  - name: server_name_1 # Server name id
    local: 
      host: 127.0.0.1 # Local interface for mapping
      port: 8080 # Local port for mapping
    remote:
      host: 1.1.1.1 # Remote host for the mapping to the local host
      port: 11111 # Remote port for the mapping to the local host
    ssh:
      host: 11.11.11.11
      user: user1
      port: 22
      auth:
        # Auth method. Allowed values password | key | key-encrypted | embedKey | embedKey-encrypted. If set *encrypted or password, but password was not set, it will asked.
        method: password 
        password: 1
        key:
          path:
          password:  
```
## How to use
```
./sshgut --help
usage: sshgut [<flags>]

Flags:
  --[no-]help               Show context-sensitive help (also try --help-long and --help-man).
  --[no-]debug              Add debug logs
  --config=config.yaml      Path to the configuration file
  --[no-]config-show        Show configuration file
  --[no-]config-show-names  Show names from configuration file
  --run-custom-names=RUN-CUSTOM-NAMES  
                            Establish connection to custom names from config. Delimiter:','
  --[no-]version            Show application version.

```