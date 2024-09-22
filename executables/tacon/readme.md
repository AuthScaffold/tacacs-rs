## Command Examples 


### Without TLS

```bash
cargo run -p tacon -- --obfuscation-key tac_plus_key -s tacacsserver.local:49 --user test --port 1 --rem-addr 1.1.1.1 accounting test
```

### With TLS

```bash
cargo run -p tacon -- --use-tls --client-certificate ~/workspace/tacacs-rs/libraries/tacacsrs_networking/examples/samples/client.crt --client-key ~/workspace/tacacs-rs/libraries/tacacsrs_networking/examples/samples/client.key -s tacacsserver.local:449 --user test --port 1 --rem-addr 1.1.1.1 accounting test
```