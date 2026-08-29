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

## Configuration

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `TUNNL_AUTH_TOKENS` | required | Comma-separated client tokens accepted by `tunnld` |
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
4. Account-scoped token administration and token rotation.
5. Rate limiting, Prometheus metrics, and abuse controls.
6. User-owned custom domains and automated validation.
7. PostgreSQL and multi-node routing if horizontal scaling becomes necessary.

See [the architecture decision record](docs/architecture/0001-foundation.md) for the protocol and deployment rationale.

## Development

```bash
make test
make test-race
make lint
```

Releases are published from GitHub's **Releases** page using a `v`-prefixed semantic version tag such as `v0.1.0`. Publishing the release triggers GoReleaser to attach cross-platform client binaries and publishes the multi-architecture server image as `ghcr.io/hortlund/tunnl-server:v0.1.0`. The exact release tag is embedded in both `tunnl --version` and `tunnld --version`; stable releases also update the `latest` image tag.

## License

MIT
