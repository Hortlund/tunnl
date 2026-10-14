# Deploy tunnl

This is the path for one VPS with a public IP and one laptop running the client. The server terminates public HTTP and HTTPS, accepts client tunnels on QUIC, and gives each client a stable name under your domain.

You still have to supply the domain, DNS, the VPS, and the DNS provider credential. tunnl cannot create those for you.

## What you run

| Piece | Where | Default listen |
| --- | --- | --- |
| `tunnld` | VPS | TCP 8080 (HTTP), TCP 8443 (HTTPS), UDP 8443 (QUIC) |
| Admin UI | VPS loopback | TCP 9090 |
| Metrics, health, readiness | VPS loopback | TCP 9091 |
| `tunnl` | Laptop | outbound QUIC, or WebSocket on TCP 443 when UDP is blocked |

Put a firewall or Docker port map in front so the public ports are 80, 443/tcp, and 443/udp. Leave 9090 and 9091 on loopback. Open the TCP forwarding range only after you set `TUNNL_TCP_PORT_MIN` and `TUNNL_TCP_PORT_MAX`.

## 1. DNS

Create these records at the DNS host for your domain. The examples use `example.com` and the VPS address `203.0.113.10`.

| Name | Type | Value | Proxy |
| --- | --- | --- | --- |
| `example.com` | A and/or AAAA | VPS address | Proxied is fine for HTTP |
| `*.example.com` | A and/or AAAA | VPS address | Proxied is fine for HTTP |
| `relay.example.com` | A and/or AAAA | VPS address | DNS only |

`relay` is the QUIC listener and the WebSocket fallback endpoint. A proxied record, including Cloudflare's orange cloud, terminates UDP and QUIC cannot connect. The client then uses WebSocket on TCP 443, which a proxied record can also intercept, so keep `relay` DNS-only. Public websites use the wildcard. The relay name itself is not a tunnel.

Let's Encrypt wildcard certificates need DNS-01. tunnl does that through Cloudflare. The token needs, on the zone you are issuing for:

- Zone / Zone / Read
- Zone / DNS / Edit

Put that token in `TUNNL_CLOUDFLARE_API_TOKEN`. Also set `TUNNL_ACME_EMAIL` to an address Let's Encrypt can use for expiry notices. The same token is what optional DNS reconciliation uses.

Start with `TUNNL_ACME_STAGING=true`. Staging certificates are not trusted by browsers. When HTTP-01 is irrelevant here: wildcard issuance is DNS-01 only. After a staging certificate is issued and a client connects with `--insecure`, set `TUNNL_ACME_STAGING=false`, delete the staging files under the ACME storage directory, and restart so production Let's Encrypt can issue.

To bring your own certificate instead, set `TUNNL_ACME=false`, `TUNNL_TLS_CERT`, and `TUNNL_TLS_KEY`. The certificate must cover `*.example.com` and `example.com` if you serve the apex.

## 2. Firewall

Allow:

- TCP 80, forwarded to `tunnld` HTTP (`:8080` in the container)
- TCP 443, forwarded to `tunnld` HTTPS (`:8443`)
- UDP 443, forwarded to `tunnld` QUIC (`:8443`)
- the TCP port range, if you enable raw TCP forwarding, forwarded to the same ports on `tunnld`

TCP 443 has to reach `tunnld` for HTTPS and for the WebSocket fallback. UDP 443 is the preferred tunnel transport. Do not publish the admin or metrics ports on the public address. Use SSH port forwarding when you need them:

If the server logs that it could not raise the UDP receive buffer, set `net.core.rmem_max` and `net.core.wmem_max` to at least 7500000. The tunnel still runs without that; the larger buffers matter under load.

```bash
ssh -L 9090:127.0.0.1:9090 -L 9091:127.0.0.1:9091 user@203.0.113.10
```

## 3. Configure

Precedence is the command-line flag, then the environment variable, then the JSON config file, then the built-in default. Invalid values fail startup. A JSON file rejects unknown fields.

```json
{
  "base_domain": "example.com",
  "public_port": 443,
  "database": "/var/lib/tunnl/tunnl.db",
  "acme": true,
  "acme_email": "you@example.com",
  "acme_storage": "/var/lib/tunnl/acme",
  "admin_addr": "127.0.0.1:9090",
  "metrics_addr": "127.0.0.1:9091",
  "log_level": "info",
  "max_request_body": 33554432,
  "max_response_body": 33554432,
  "request_timeout": "2m",
  "accept_limit": 30,
  "handshake_failure_limit": 20,
  "tcp_bind": "0.0.0.0",
  "tcp_port_min": 20000,
  "tcp_port_max": 20050,
  "tcp_public_host": "example.com",
  "max_tcp_per_token": 4,
  "max_tcp_connections": 64,
  "tcp_accept_limit": 60
}
```

Pass it with `--config /etc/tunnl/tunnld.json` or `TUNNL_CONFIG`. Secrets fit better in the environment file than in the JSON file.

`accept_limit` is QUIC accepts per remote IP per minute (default 30). `handshake_failure_limit` is failed handshakes per remote IP per minute (default 20). Set either to `-1` to disable that limiter. Admin login attempts are limited to 10 per minute per remote IP. Body limits default to 32 MiB. The public request timeout defaults to 2 minutes. Header read stays at 10 seconds and keep-alive idle at 90 seconds.

An empty `--metrics-addr` disables the metrics listener. The CLI default is `127.0.0.1:9091`.

Leave `tcp_port_min` and `tcp_port_max` at `0` to keep raw TCP forwarding off. When both are set, each client token can hold `max_tcp_per_token` public ports (default 4). A port stays reserved for that token and local address across disconnects. `tcp_accept_limit` is public TCP accepts per remote IP per minute. `disable_websocket` turns off `GET /_tunnl/ws`. The fallback is enabled unless that flag or `TUNNL_DISABLE_WEBSOCKET=true` is set.

Docker cannot publish an arbitrary port range as easily as a firewall rule. Run TCP forwarding on the systemd install, or publish the exact host ports you configured.

## 4. Install on a VPS

### systemd

```bash
sudo useradd --system --home /var/lib/tunnl --shell /usr/sbin/nologin tunnl
sudo install -d -o tunnl -g tunnl -m 0750 /var/lib/tunnl /etc/tunnl
sudo install -m 0755 tunnld /usr/local/bin/tunnld
sudo install -m 0644 deploy/tunnld.service /etc/systemd/system/tunnld.service
sudo install -m 0640 deploy/tunnld.env.example /etc/tunnl/tunnld.env
sudoedit /etc/tunnl/tunnld.env
sudo systemctl daemon-reload
sudo systemctl enable --now tunnld
sudo systemctl status tunnld
curl -fsS http://127.0.0.1:8080/_tunnl/ready
curl -fsS http://127.0.0.1:9091/metrics | head
```

`tunnld` is in the release archive `tunnld_<version>_linux_amd64.tar.gz` (or arm64) after you push a `v*` tag. A local build is `CGO_ENABLED=0 go build -trimpath -o tunnld ./cmd/tunnld`.

### Docker

`deploy/docker-compose.yml` publishes host `80`, `443/tcp`, and `443/udp` and keeps metrics on the host loopback. Inside the container, metrics listen on `:9091` because a process bound to container loopback is not reachable through a published port. Do the same for admin when you enable it:

```bash
export TUNNL_AUTH_TOKENS='bootstrap-token'
export TUNNL_BASE_DOMAIN='example.com'
export TUNNL_ACME_EMAIL='you@example.com'
export TUNNL_CLOUDFLARE_API_TOKEN='scoped-cloudflare-token'
export TUNNL_ADMIN_ADDR=':9090'
export TUNNL_ADMIN_TOKEN="$(docker compose -f deploy/docker-compose.yml run --rm --entrypoint tunnld tunnld generate-admin-token)"
docker compose -f deploy/docker-compose.yml up -d
```

The image runs as uid 65532, reads a root filesystem, and stores SQLite plus ACME state in the `tunnl-data` volume. `tunnld healthcheck` probes `/_tunnl/ready`, which checks the process and SQLite.

## 5. Issue a client token

Generate the admin token on the server and keep it out of the public environment:

```bash
tunnld generate-admin-token
```

With the admin listener on loopback:

```bash
export TUNNL_ADMIN_URL=http://127.0.0.1:9090
export TUNNL_ADMIN_TOKEN='the-token-you-just-generated'
tunnld admin tokens create --label laptop
tunnld admin tokens rotate --id <token-id>
```

The create and rotate commands print a secret once. It is stored only as a SHA-256 hash. Rotate creates a second token with the same label and leaves the old token active, so connected clients stay up until you point them at the new secret and run `tunnld admin tokens revoke --id <old-id>`. Revoke disconnects that token's HTTP and TCP sessions and deletes its TCP port reservations. You can also create, replace, and revoke tokens in the browser at `http://127.0.0.1:9090`.

A server may start with no `TUNNL_AUTH_TOKENS` when `--admin-addr` is set, including on a later restart after a managed token exists. Bootstrap tokens in `TUNNL_AUTH_TOKENS` stay valid until you remove them. They are not listed or revoked by the admin API.

## 6. Run the client

On the laptop, after the wildcard certificate is publicly trusted:

```bash
export TUNNL_TOKEN='tnl_...'
tunnl --server relay.example.com:443 --port 3000 --domain app
```

The printed public URL is `https://app.example.com`. While you are still on the Let's Encrypt staging certificate, add `--insecure` so the client accepts the untrusted relay certificate. Browsers will keep warning until you switch off staging.

Publish a local TCP service after the server port range and firewall rule exist:

```bash
tunnl tcp --server relay.example.com:443 --port 5432
```

The client prints `tcp://example.com:<port>`. Set `TUNNL_TCP_PUBLIC_HOST` when that name should not be the base domain. The client dials only the local address you configured.

The client reconnects with backoff. If QUIC does not connect within `--quic-timeout` (default 5s), it retries the same session over WebSocket on TCP 443 and prefers that transport next time. Authentication and configuration errors stop the retry loop and name the token to check. Logs default to text on stderr. `--log-format json` and `--log-level debug` are available.

## 7. Upgrade

Back up the database and ACME directory first (below). Then replace the binary or image and restart. Schema changes in this tree are applied with `CREATE TABLE IF NOT EXISTS` on startup.

```bash
sudo systemctl restart tunnld
```

```bash
docker compose -f deploy/docker-compose.yml pull
docker compose -f deploy/docker-compose.yml up -d
```

Pushing a tag such as `v0.1.0` to GitHub builds client and server archives with GoReleaser and publishes `ghcr.io/<owner>/tunnl-server:0.1.0`. Tags without a hyphen also move the `latest` image tag. The workflow creates the GitHub Release. Do that from a commit you intend to ship.

Package the image as public or grant the VPS `read:packages` if the GHCR package is private. The repository owner in the image name is taken from the GitHub repository.

## 8. Back up SQLite

The database is WAL mode. Copying the `.db` file alone while the process is running can drop the latest commits. Use SQLite's online backup, and copy the ACME directory as well. Both are required to restore names, token hashes, and the Let's Encrypt account.

```bash
sudo sqlite3 /var/lib/tunnl/tunnl.db ".backup /var/backups/tunnl-$(date -u +%Y%m%d).db"
sudo tar -C /var/lib/tunnl -czf /var/backups/tunnl-acme-$(date -u +%Y%m%d).tar.gz acme
```

For Docker, the files live in the `tunnl-data` volume (`/data/tunnl.db` and `/data/acme`):

```bash
docker run --rm -v <volume>:/data -v "$PWD":/backup alpine \
  sh -c 'apk add --no-cache sqlite && sqlite3 /data/tunnl.db ".backup /backup/tunnl.db" && tar -C /data -czf /backup/acme.tar.gz acme'
```

The volume name depends on the Compose project. `docker volume ls` shows it. Restore by stopping `tunnld`, replacing the database and ACME directory, fixing ownership (`tunnl` or uid 65532), and starting again.

## 9. Observe

- Liveness: `GET /_tunnl/health` on the public HTTP port when the Host is localhost, `127.0.0.1`, `::1`, or `status.<base-domain>`. Any other host is proxied, so a tunnel can serve that path.
- Readiness: `GET /_tunnl/ready` with the same host rule. It pings SQLite.
- Prometheus: `GET /metrics` on the metrics listener. The same listener serves `/health` and `/ready` without the host rule.

Server logs are JSON on stdout. Each public request logs host, method, path, status, bytes, duration, and the remote address.

Shutdown on SIGINT or SIGTERM stops new QUIC accepts, closes active tunnels, drains HTTP listeners, and waits up to 15 seconds.

## Still outside this deploy

Raw TCP forwarding and a WebSocket fallback for networks that block UDP are not implemented. Clients need a path that can send UDP to the relay. One server and one SQLite file are the supported production shape.
