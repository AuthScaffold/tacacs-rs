# Running tacacsrs-agentd as a SONiC Docker container

`tacacsrs-agentd` can run on SONiC as a container while reading TACACS+
configuration directly from SONiC CONFIG_DB. This is useful for development,
image validation, and deployment experiments before packaging the agent as a
native SONiC service.

This guide assumes an agent image is already available. For image build commands,
see [Building for SONiC](sonic-build-guide.md). For CONFIG_DB schema mapping,
Redis notification behavior, and local Redis smoke tests, see
[SONiC ConfigDB Integration](sonic-configdb-integration.md).

The container needs access to the SONiC Redis socket and to the same outbound
network path that the host uses to reach upstream TACACS+ servers. On SONiC,
the built-in service containers commonly use Docker host networking, and that
is the recommended mode for this agent.

## Run the container

```bash
docker run --rm --network host \
    -v /var/run/redis/redis.sock:/var/run/redis/redis.sock \
    -p 127.0.0.1:49:49 \
    ghcr.io/authscaffold/tacacsrs-agentd:2026.706.1 \
    --sonic \
    --service-mode both \
    --proxy-endpoint 127.0.0.1:49 \
    -vv
```

The flags mean:

| Flag | Purpose |
|------|---------|
| `--network host` | Share the SONiC host network namespace. Outbound TACACS+ connections use the host route table instead of Docker bridge NAT. |
| `-v /var/run/redis/redis.sock:/var/run/redis/redis.sock` | Let the agent read SONiC CONFIG_DB through the Redis Unix socket. |
| `-p 127.0.0.1:49:49` | Harmless with host networking, but ignored by Docker because there is no separate container network namespace to publish from. |
| `--sonic` | Load TACACS+ server configuration from SONiC CONFIG_DB, database `4`. |
| `--service-mode both` | Run both the local client API and the raw TACACS+ proxy service. |
| `--proxy-endpoint 127.0.0.1:49` | Bind the proxy on loopback only, so local SONiC clients can connect without exposing port `49` on external interfaces. |
| `-vv` | Enable info-level logging. |

Because `-p` is ignored in host networking mode, the command can also be written
without the publish flag:

```bash
docker run --rm --network host \
    -v /var/run/redis/redis.sock:/var/run/redis/redis.sock \
    ghcr.io/authscaffold/tacacsrs-agentd:2026.706.1 \
    --sonic \
    --service-mode both \
    --proxy-endpoint 127.0.0.1:49 \
    -vv
```

## Security and exposure

With `--network host`, the container shares the host network namespace. Exposure
is controlled by the address that `tacacsrs-agentd` binds and by SONiC firewall
policy.

The proxy endpoint in the example is loopback-only:

```bash
--proxy-endpoint 127.0.0.1:49
```

That means the proxy is reachable from local processes on the SONiC host, but
not from remote hosts through the management or front-panel interfaces. You can
confirm the bind after startup:

```bash
sudo netstat -tlpn | grep ':49'
nc -vz 127.0.0.1 49
nc -vz "$(hostname -I | awk '{print $1}')" 49
```

The expected result is that `127.0.0.1:49` connects and the host interface
address refuses or times out. Do not use `--proxy-endpoint 0.0.0.0:49` unless
you intentionally want the proxy to listen on all host interfaces and have
reviewed the surrounding firewall policy.

## Why host networking is recommended on SONiC

Docker bridge networking relies on a private container subnet and normally uses
NAT rules in the host `nat` table to let containers reach external addresses. If
SONiC's Docker bridge has no masquerade rule, packets can leave the host with
the container bridge source address. Upstream devices often do not have a return
route for that address, so TCP connections time out even when the SONiC host can
connect directly.

Host networking avoids that failure mode. The agent's outbound TACACS+
connections use the same source address and routing behavior as commands run on
the SONiC host.

To diagnose a bridge networking failure, compare the host route and packet
source address:

```bash
ip route get <tacacs-server-ip>
sudo iptables-save -t nat
sudo tcpdump -ni any 'host <tacacs-server-ip> and tcp port 49'
```

If `tcpdump` shows traffic leaving an external interface with a Docker bridge
source address, for example `240.127.1.2`, then the bridge path needs NAT or an
explicit return route. Use host networking for the agent unless the deployment
has a SONiC-supported bridge NAT and firewall design.

## CONFIG_DB requirements

The `--sonic` mode reads `TACPLUS|global` and `TACPLUS_SERVER|*` from CONFIG_DB.
At least one `TACPLUS_SERVER` row must be present for upstream TACACS+ traffic.
For the schema mapping and Redis notification details, see
[SONiC ConfigDB Integration](sonic-configdb-integration.md).

The startup log should include lines similar to:

```text
Configured SONiC ConfigDB datastore: url='unix:///var/run/redis/redis.sock?db=4', db=4
Initial configuration loaded from datastore 'sonic-configdb'
Upstream servers: 1 configured, probe interval: 30s
TACACS+ proxy endpoint: Tcp(127.0.0.1:49)
```

If CONFIG_DB changes should be picked up live, enable Redis keyspace
notifications as described in the ConfigDB integration guide.