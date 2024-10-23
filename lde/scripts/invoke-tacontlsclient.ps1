clear
$git_directory = git rev-parse --show-toplevel
$client_certificate = Join-Path -Path $git_directory -ChildPath libraries tacacsrs_networking examples samples client.crt
$client_key = Join-Path -Path $git_directory -ChildPath libraries tacacsrs_networking examples samples client.key
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