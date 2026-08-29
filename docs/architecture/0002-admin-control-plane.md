# ADR 0002: Embedded optional admin control plane

- Status: accepted
- Date: 2026-08-29

## Context

Operators need lightweight visibility and routine controls without adding a separate deployment, frontend runtime, or database. Every operation must remain scriptable. The public tunnel ingress is intentionally exposed to untrusted traffic, so administrative routes must not share that listener.

## Decision

`tunnld` can start an independent admin listener when `--admin-addr` is set. It is disabled by default and restricted to loopback unless the operator explicitly allows a remote bind. The listener serves a small Go-embedded HTML, CSS, and JavaScript interface plus a versioned JSON API. Browser access uses an in-memory, HTTP-only, SameSite session and CSRF token after admin-token login. CLI access uses the same admin token as a bearer credential.

The `tunnld admin` CLI calls the same API used by the panel. Business operations live behind a shared Go backend rather than in UI handlers.

Managed client token secrets are generated with the operating system's cryptographic random source, returned once, and stored only as SHA-256 hashes in SQLite. Revocation removes the token and closes its active QUIC sessions. Environment-provided client tokens remain available as bootstrap credentials and are never exposed through the admin API.

Metrics are process-local counters plus durable counts from SQLite. They do not participate in request forwarding.

DNS remains provider-agnostic. Manual wildcard DNS is the default. The optional Cloudflare provider reconciles only the wildcard public record and DNS-only relay record, marks owned records with a comment, and refuses to overwrite records it did not create. The Cloudflare credential is supplied at server startup and is never persisted or returned by the API.

## Consequences

- The admin panel adds no runtime service and no JavaScript build chain.
- Admin availability does not affect public forwarding.
- Process-local counters reset when `tunnld` restarts.
- Browser sessions reset on restart and expire after 12 hours.
- Remote administration requires an operator-provided secure transport such as an SSH tunnel or TLS reverse proxy.
- Cloudflare reconciliation is explicit rather than part of tunnel connection handling, so provider outages cannot disconnect or block tunnels.
