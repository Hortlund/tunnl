# tunnl

Fast, reliable, self-hosted tunnels for exposing local HTTP services to the internet.

`tunnl` is the client your users install. `tunnld` is the server daemon you host. They are separate binaries built from one Go codebase and communicate over encrypted, multiplexed QUIC streams.

> [!IMPORTANT]
> This repository is an early working foundation. HTTP forwarding is implemented. Raw TCP forwarding and a WebSocket fallback transport are on the roadmap and are not yet available.

## Why tunnl

- Stable custom subdomains remain reserved across disconnects and server restarts.
- Random subdomains are saved locally and reused automatically.
- Independent QUIC streams prevent one slow request from blocking other requests.
- Automatic reconnect uses exponential backoff and jitter.
- HTTP bodies and responses are streamed with backpressure.
- SQLite keeps deployment to one server container and one persistent volume.
- One server supports multiple clients with separate authentication tokens.
- The base domain, listeners, certificates, and public port are configurable.

## Client usage

```bash
export TUNNL_TOKEN='the-token-issued-by-the-server-owner'

# Expose localhost:3001 using an automatically allocated stable subdomain.
tunnl --port 3001

# Reserve and use geph.tunnl.at.
tunnl --port 3001 --domain geph

# Forward to another host or service on the client's network.
tunnl --to http://192.168.1.50:8080 --domain dashboard

# Override the Host header received by the local service.
tunnl --port 3001 --domain app --host-header localhost:3001
```

The client persists automatically allocated names in the operating system's user configuration directory. A requested name is permanently associated with the client's token in the server database.

## Run locally

Build both programs:

```bash
make build
```

Start a local service on port 3001, then start the server with a development certificate:

```bash
TUNNL_AUTH_TOKENS=local-development-token \
  ./bin/tunnld \
  --base-domain tunnl.test \
  --database .data/tunnl.db \
  --http-addr 127.0.0.1:18080 \
  --https-addr 127.0.0.1:18443 \
  --quic-addr 127.0.0.1:18443 \
  --public-port 18443
```

Connect the client. `--insecure` is required only because the development certificate is self-signed:

```bash
TUNNL_TOKEN=local-development-token \
  ./bin/tunnl \
  --server localhost:18443 \
  --insecure \
  --port 3001 \
  --domain demo
```

Send a request through the plain HTTP ingress:

```bash
curl -H 'Host: demo.tunnl.test' http://127.0.0.1:18080
```

TCP and UDP can share the same numeric port, so production maps both HTTPS/TCP and QUIC/UDP to port 443.

## Production deployment

The server is published as `ghcr.io/hortlund/tunnl-server`. Client release archives contain only the `tunnl` client.

```bash
cd deploy
mkdir -p certs
export TUNNL_AUTH_TOKENS='token-for-andy,token-for-another-user'
export TUNNL_BASE_DOMAIN='tunnl.at'
docker compose up -d
```

Place a publicly trusted wildcard certificate in:

```text
deploy/certs/fullchain.pem
deploy/certs/privkey.pem
```

A wildcard certificate from Let's Encrypt using a DNS-01 challenge is suitable. The direct `relay.tunnl.at` QUIC endpoint must use a certificate trusted by client operating systems; a Cloudflare Origin CA certificate alone is not sufficient for that endpoint.

### Cloudflare DNS

Once the domain is owned, the initial records should be:

| Type | Name | Target | Proxy |
| --- | --- | --- | --- |
| A/AAAA | `*` | server address | Proxied |
| A/AAAA | `relay` | server address | DNS only |
| A/AAAA | `@` | server address | Optional |

The wildcard means starting or stopping a tunnel never requires a Cloudflare API request. Domain ownership is managed transactionally inside tunnl instead.

Open these firewall ports:

- TCP 80 for HTTP and certificate redirects/challenges.
- TCP 443 for public HTTPS traffic.
- UDP 443 for direct QUIC client connections.

Back up the `tunnl-data` Docker volume. SQLite uses WAL mode with full synchronous durability.

## Optional admin panel

The admin panel is embedded in `tunnld` and has no separate frontend runtime. It is disabled unless an admin address is configured. Generate a dedicated admin token and bind the panel to loopback:

```bash
export TUNNL_ADMIN_TOKEN="$(tunnld generate-admin-token)"
tunnld --admin-addr 127.0.0.1:9090 --admin-token "$TUNNL_ADMIN_TOKEN"
```

Open `http://127.0.0.1:9090` and sign in with the admin token. The panel shows live tunnel and request metrics, active connections, durable reservations, managed client tokens, and DNS settings. Metrics counters reset when the server restarts.

Every panel operation is also available through the server CLI:

```bash
export TUNNL_ADMIN_URL=http://127.0.0.1:9090

tunnld admin status
tunnld admin tokens list
tunnld admin tokens create --label andy-laptop
tunnld admin tokens revoke --id TOKEN_ID
tunnld admin dns show
tunnld admin dns set --provider manual
```

Generated client secrets are displayed once and stored only as hashes. Revoking one immediately closes its active tunnels. Tokens supplied through `TUNNL_AUTH_TOKENS` remain bootstrap credentials and are intentionally not manageable through the panel.

The admin listener rejects non-loopback binds by default. For remote operation, put it behind an SSH tunnel or a TLS-authenticated reverse proxy. Do not send the admin token over unencrypted public HTTP. `--admin-allow-remote` is available for explicitly protected networks and container port mappings.

For Docker Compose, the admin port is mapped only to the host's loopback interface. Enable the listener inside the container with:

```bash
export TUNNL_ADMIN_ADDR=:9090
export TUNNL_ADMIN_ALLOW_REMOTE=true
export TUNNL_ADMIN_TOKEN="$(tunnld generate-admin-token)"
docker compose up -d
```

### Cloudflare DNS reconciliation

Manual wildcard DNS remains the default and has no provider API dependency. To let tunnl manage the baseline Cloudflare records, give the server a scoped API token with **Zone Read** and **DNS Write** access, then save and reconcile the provider configuration:

```bash
export TUNNL_CLOUDFLARE_API_TOKEN='scoped-cloudflare-token'

tunnld admin dns set \
  --provider cloudflare \
  --zone tunnl.at \
  --target 203.0.113.10
tunnld admin dns reconcile
```

Reconciliation creates or updates `*.tunnl.at` as a proxied record and `relay.tunnl.at` as DNS-only. tunnl marks its records and refuses to overwrite records it does not own. The Cloudflare token stays in server memory and is never written to SQLite or returned to the panel.

## Configuration

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `TUNNL_AUTH_TOKENS` | empty | Comma-separated bootstrap client tokens accepted by `tunnld` |
| `TUNNL_BASE_DOMAIN` | `tunnl.at` | Public wildcard domain |
| `TUNNL_DATABASE` | `.data/tunnl.db` | SQLite database path |
| `TUNNL_HTTP_ADDR` | `:8080` | Public HTTP listener |
| `TUNNL_HTTPS_ADDR` | `:8443` | Public HTTPS listener |
| `TUNNL_QUIC_ADDR` | `:8443` | QUIC/UDP relay listener |
| `TUNNL_PUBLIC_PORT` | `8443` | Port included in generated URLs |
| `TUNNL_TLS_CERT` | empty | TLS certificate; ephemeral development certificate when omitted |
| `TUNNL_TLS_KEY` | empty | TLS private key |
| `TUNNL_SERVER` | `relay.tunnl.at:443` | Client relay address |
| `TUNNL_TOKEN` | required | Client authentication token |
| `TUNNL_RESPONSE_HEADER_TIMEOUT` | `0` | Maximum wait for local response headers; zero disables it |
| `TUNNL_TRUST_PROXY_HEADERS` | `false` | Preserve forwarding headers from a trusted ingress proxy |
| `TUNNL_HEARTBEAT_TIMEOUT` | `40s` | Maximum delay between client heartbeats before disconnecting |
| `TUNNL_ADMIN_ADDR` | empty | Optional admin UI/API listener; empty disables it |
| `TUNNL_ADMIN_TOKEN` | required with admin | Admin UI/API authentication token of at least 32 characters |
| `TUNNL_ADMIN_ALLOW_REMOTE` | `false` | Permit an explicitly protected non-loopback admin bind |
| `TUNNL_ADMIN_URL` | `http://127.0.0.1:9090` | Admin API URL used by `tunnld admin` commands |
| `TUNNL_CLOUDFLARE_API_TOKEN` | empty | Optional scoped credential used only for DNS reconciliation |

Generate separate high-entropy tokens for each person. A domain reservation belongs to the SHA-256 hash of the token that created it, so another client token cannot claim it.

Leave `TUNNL_TRUST_PROXY_HEADERS` disabled unless direct access to the origin is restricted to a trusted proxy. Enabling it on a publicly reachable origin allows callers to spoof forwarding metadata.

## Reliability model

- QUIC keepalives and application heartbeats detect dead sessions.
- The server expires clients that stop sending heartbeats.
- A reconnect with the same token atomically replaces an older connection.
- Reservations survive disconnects and process restarts.
- The proxy does not buffer whole request or response bodies.
- Shutdown drains HTTP listeners before the server exits.
- Release builds embed protocol and application versions.

## Roadmap

1. WebSocket-over-TLS fallback for networks that block UDP.
2. Raw TCP forwarding using allocated public ports.
3. WebSocket upgrade tunneling and expanded HTTP integration tests.
4. Rate limiting, Prometheus export, and abuse controls.
5. User-owned custom domains and automated validation.
6. PostgreSQL and multi-node routing if horizontal scaling becomes necessary.

See [the architecture decision record](docs/architecture/0001-foundation.md) for the protocol and deployment rationale.

## Development

```bash
make test
make test-race
make lint
```

Releases are published from GitHub's **Releases** page using a `v`-prefixed semantic version tag such as `v0.1.0`. Publishing the release triggers GoReleaser to attach cross-platform client binaries and publishes the multi-architecture server image as `ghcr.io/hortlund/tunnl-server:0.1.0`. The `v` prefix is reserved for the Git tag, so both `tunnl --version` and `tunnld --version` report `0.1.0`; stable releases also update the `latest` image tag.

## License

MIT
