# SSHGUT

The project is used to set up ssh tunnels and is essentially a wrapper around https://github.com/rgzr/sshtun.


## Configuration
Example of the configuration file `config.yaml.example`

```
---
version: "2"
configs:
  # Server name id
  - name: server_name_1
    local: 
      # Local interface for mapping
      host: 127.0.0.1
      # Local port for mapping
      port: 8080
    remote:
      # Remote host for the mapping to the local host
      host: 1.1.1.1
      # Remote port for the mapping to the local host
      port: 11111
    ssh:
      # Forward type. Allowed values local | remote, default: local.
      forward_type: local
      key_exchanges: # Optional
        - kexAlgoCurve25519SHA256
        - kexAlgoCurve25519SHA256LibSSH
      ciphers: # Optional
        # - chacha20Poly1305ID4321
        - aes256-ctr
        - aes256-cbc
      macs: # Optional
        - hmac-sha2-256-etm@openssh.com
        - hmac-sha2-512-etm@openssh.com
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
### Docker
Add configuration file to the container.

```bash
$ docker run -it \
-v ${PWD}/config.yaml:/app/config.yaml \
-v ./ssh-key:/app/ssh-key \
-p 127.0.0.1:8080:8080 f100024/sshgut:latest
```

docker-compose.yaml
```yaml
---
version: '2'
services:
  sshgut:
    image: f100024/sshgut:latest
    ports:
      - 127.0.0.1:8080:8080
    volumes:
      - ./config.yaml:/app/config.yaml
      - ./ssh-key:/app/ssh-key 
```