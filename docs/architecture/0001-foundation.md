# ADR 0001: Initial tunnl architecture

- Status: accepted
- Date: 2026-08-29

## Context

tunnl must reliably expose services reachable by a client to public HTTP users. Many clients connect to one self-hosted server. Requested names must remain stable through reconnects, and operating the first production server should not require a distributed database or separate control-plane services.

## Decision

The project ships two commands from one Go module:

- `tunnl` is the user-facing client.
- `tunnld` is the operator-hosted server daemon.

Clients establish an outbound TLS 1.3 QUIC connection to the server. The first bidirectional stream carries a versioned JSON handshake and heartbeats. The server opens a new independent bidirectional stream for each public HTTP request. HTTP/1.1 wire encoding is used inside each QUIC stream, which preserves streaming semantics without inventing a body framing protocol.

Request upload and response download use the two directions of a QUIC stream concurrently. This allows a local service to reject or answer a request before the public caller finishes uploading its body. A heartbeat failure closes the whole QUIC connection so the client can reconnect rather than remaining attached to an unregistered session.

The server routes requests by the first label of the HTTP Host header. A wildcard DNS record directs every name under the configured base domain to the server. Starting and stopping tunnels changes only the in-memory connection registry; it does not mutate DNS.

SQLite stores durable name-to-token reservations. It does not participate in request forwarding. The active connection registry remains in memory. SQLite WAL mode, full synchronous durability, a busy timeout, and a single database writer connection give predictable behavior for the single-node server.

Authentication initially uses operator-issued high-entropy bearer tokens. Only token hashes are persisted. Each person receives a separate token, making domain ownership distinct even though the allowlist is supplied through server configuration.

Forwarding headers from public requests are untrusted by default and are replaced with the direct peer address. Operators may preserve an ingress proxy's forwarding chain only when direct origin access is separately restricted to that proxy.

## Consequences

- QUIC streams isolate concurrent requests from transport-level head-of-line blocking.
- UDP 443 must be reachable from clients.
- A fallback transport is needed for networks that block QUIC.
- One SQLite-backed server is intentionally not horizontally scalable.
- Wildcard DNS removes Cloudflare API availability from the tunnel lifecycle.
- Raw TCP requires an allocated public port or a protocol-aware routing mechanism and is therefore a separate tunnel mode.
- HTTP WebSocket upgrades need explicit bidirectional proxy handling beyond normal request/response forwarding.

## Compatibility

The handshake contains an integer protocol version. Incompatible peers fail before registering a route. Future compatible fields may be added to the JSON control messages. Data-stream framing changes require a new negotiated protocol version.
