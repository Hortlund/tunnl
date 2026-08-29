# ADR 0003: Automatic wildcard TLS with Let's Encrypt

- Status: accepted
- Date: 2026-08-29

## Context

Every allocated tunnel hostname and the direct QUIC relay need publicly trusted TLS. A certificate issued by Cloudflare Origin CA is trusted only on the Cloudflare-to-origin leg and cannot authenticate the DNS-only QUIC endpoint to ordinary clients. Manually copying and renewing certificates also creates avoidable operational risk.

## Decision

When explicitly enabled, `tunnld` obtains and renews one `*.<base-domain>` certificate from Let's Encrypt through an ACME DNS-01 challenge. The wildcard covers both tunnel hostnames and the `relay` hostname. The apex is intentionally omitted because tunnl does not currently serve it.

Cloudflare is the first DNS-01 provider. Its scoped API token remains in process memory and is used to create and remove temporary ACME TXT records. CertMagic manages issuance, renewal, in-memory certificate replacement, and persistent ACME state. HTTPS and QUIC TLS configurations use the same managed certificate source, so renewals require no restart.

Automatic ACME is opt-in. Development continues to use an ephemeral self-signed certificate, while operators may still supply a manual PEM certificate and key. Manual PEM and automatic ACME modes cannot be enabled together. The Let's Encrypt staging endpoint is available for deployment testing.

## Consequences

- The server requires outbound HTTPS and Cloudflare API access during issuance and renewal.
- ACME state must live on persistent storage and be included in server backups.
- The Cloudflare token needs Zone Read and DNS Write only for the base-domain zone.
- A DNS provider outage does not affect an already loaded certificate or active tunnels, but can delay renewal.
- Address records remain independent of certificate automation and can be managed manually or by the admin DNS reconciler.
