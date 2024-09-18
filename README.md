# TACACS-rs

`tacacs-rs` is a reference implementation of the TACACS+ protocol, designed to provide a robust and efficient solution for authentication, authorization, and accounting (AAA) services.


## Local Testing

Local testing uses Docker, and we need to set up Docker with the following steps:

1. Prepare Workspace

```bash
mkdir tac_plus
cd tac_plus
git clone https://github.com/lfkeitel/docker-tacacs-plus.git
```

2. Create Docker Compose file

Docker Compose should be created as `compose.yml` in the `tac_plus` folder

```compose
services:
  app:
    build:
      context: ./docker-tacacs-plus
      args:
        SRC_VERSION: '202104181633'
        SRC_HASH: 'F2695A7CC908E03BAB8FFB0A84603A0AD103B4532CC84900624899CC1C32E4AB'
    image: 'tac_plus:ubuntu'
    restart: unless-stopped
    environment:
      - TZ=Australia/Brisbane
      - TAC_PLUS_ADDITIONAL_ARGS="-d 1"
    ports:
      - '49:49'
    volumes:
      - ./tac_plus.cfg:/etc/tac_plus/tac_plus.cfg
```

3. Create tac_plus config

The configuration of the TACACS+ server should be placed in the `tac_plus` folder alongside the `compose.yml` file

```text
id = spawnd {
    listen = { port = 49 }
    spawn = {
        instances min = 1
        instances max = 10
    }
    background = no
}

id = tac_plus {
    debug = PACKET AUTHEN AUTHOR

    log = stdout {
        destination = /proc/1/fd/1
    }

    authorization log group = yes
    authentication log = stdout
    authorization log = stdout
    accounting log = stdout

    host = world {
        address = 0.0.0.0/0
        enable = clear enable
        key = tac_plus_key
    }

    group = admin {
        default service = permit
        enable = permit
        service = shell {
            default command = permit
            default attribute = permit
            set priv-lvl = 15
        }
    }

    user = $enable$ {
        login = clear enable
    }

    user = admin {
        password = clear admin
        member = admin
    }
}
```


