# tacacsrs-config

`tacacsrs-config` provides TACACS+ configuration support using the RFC 7951 JSON encoding of the `ietf-system-tacacs-plus` YANG module.

## What this crate contains

- Generated Rust types in `src/generated.rs` that mirror the expanded YANG tree
- Validation logic for YANG-specific constraints that must hold after deserialization
- Credential-reference resolution helpers
- Mapping from parsed YANG config into runtime `ServerConnectionConfig` values

## Parsing API

```rust
use tacacsrs_config::{parse_yang_json, parse_yang_json_file, to_connection_configs};

let config = parse_yang_json_file(std::path::Path::new("tacacs.json"))?;
let servers = to_connection_configs(&config)?;
# anyhow::Ok::<(), anyhow::Error>(())
```

The primary entry points are:

- `parse_yang_json(&str)` — parse, resolve credential references, and validate a JSON string
- `parse_yang_json_file(&Path)` — file-based wrapper around `parse_yang_json`
- `to_connection_configs(&TacacsPlus)` — map validated YANG data into runtime connection configs

## Example config

```json
{
  "ietf-system-tacacs-plus:tacacs-plus": {
    "server": [
      {
        "name": "primary",
        "server-type": "authentication authorization accounting",
        "address": "192.0.2.2",
        "port": 49,
        "shared-secret": "QaEfThUkO198010075460923+h3TbE8n",
        "timeout": 10
      }
    ]
  }
}
```

## Code generation workflow

The generated Rust types come from the checked-in YANG tooling under `yang/`:

- `yang/yang2rust.py` — custom `pyang` plugin that emits Rust structs/enums/bitflags
- `yang/expand_yang_tree.py` — helper used to refresh the fully expanded tree reference
- `yang/generated_types.rs` — checked-in generator output copied into `src/generated.rs`

To regenerate after YANG module updates:

```bash
python -m pip install pyang
cd libraries/tacacsrs_config/yang
python expand_yang_tree.py > expanded-tree.txt
pyang \
  -f rust \
  --plugindir . \
  ietf-system-tacacs-plus.yang \
  ietf-keystore.yang \
  ietf-truststore.yang \
  ietf-crypto-types.yang \
  ietf-tls-common.yang \
  > generated_types.rs
cp generated_types.rs ../src/generated.rs
```

Run the normal workspace formatting, clippy, build, and test commands after regeneration.
