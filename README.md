# SSHGUT

The project is used to set up ssh tunnels and is essentially a wrapper around https://github.com/rgzr/sshtun.


## Configuration
Example of the configuration file `config.yaml.example`

```
---
remotes:
  - server: server1 # remote server that should be available on the localhost via `sshServer.host`
    remotePort: 80  # server's remote port that should be available on `localPort`
    localPort: 38081 # port on the localhost which
    localHost: 1.1.1.1 # bind tunnel to ip (default: 127.0.0.1) 
    sshServer:
      host: server # SSH server is used to establish connection
      port: 22 # SSH port of the `host`
      user: user # SSH user
      keyPath: id_rsa # path to the ssh key file; allowed values [path to key] or `embedKey` in the second case, the key from the embedKey.ssh file will be added at build time.
      useKeyPass: false # Passphrase for decryption ssh key, passphrase is prompted at startup

  - server: server2
    remotePort: 80
    localPort: 38082
    sshServer:
      host: server
      port: 22
      user: user
      keyPath: id_rsa 
      useKeyPass: false

  - server: server3
    remotePort: 80
    localPort: 38083
    sshServer:
      host: server
      port: 22 
      user: user
      keyPath: id_rsa
      useKeyPass: false 
```

## How to run

Put config.yaml with sshgut and run it or set the path to the configuration file as below:
```
$ ./sshgut 
or
$ ./sshgut --config your_config.yaml
```