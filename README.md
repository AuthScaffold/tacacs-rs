# TACACS-rs

`tacacs-rs` is a reference implementation of the TACACS+ protocol, designed to provide a robust and efficient solution for authentication, authorization, and accounting (AAA) services.


## Demo

**Demo 1: Existing (Legacy) TACACS+ with Obfuscation**

```powershell
clear
cargo run -p tacon -- `
    --obfuscation-key tac_plus_key `
    -s tacacsserver.local:49 `
    --user test `
    --port 1 `
    --rem-addr 1.1.1.1 `
    -vvv `
    accounting test
```

**Demo 2: Upcoming TACACS+ with TLS 1.3**

```powershell
clear
$client_certificate = Join-Path -Path $(pwd) -ChildPath libraries tacacsrs_networking examples samples client.crt
$client_key = Join-Path -Path $(pwd) -ChildPath libraries tacacsrs_networking examples samples client.key
cargo run -p tacon -- `
    --use-tls `
    --client-certificate $client_certificate `
    --client-key $client_key `
    -s tacacsserver.local:449 `
    --user test `
    --port 1 `
    --rem-addr 1.1.1.1 `
    -vvv `
    accounting test
```


## TACACS+ server for Local Testing

Local testing uses Docker, and we have prepared a compose file in the `lde/containers` folder. You can simply run `docker compose up -d` and have a working TACACS+ server on port 49 for non-TLS and 449 for TLS (will change the default in the future when IANA assigns a well known port number to TACACS with TLS).
