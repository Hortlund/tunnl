# Security policy

## Supported versions

tunnl is pre-1.0. Security fixes are applied to the latest release.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's security advisory interface rather than opening a public issue.

## Operator guidance

- Generate a distinct high-entropy client token for each person.
- Provide certificates and private keys through read-only mounts or a secret manager.
- Never use `--insecure` outside local development.
- Restrict the server firewall to required ingress ports.
- Keep the optional admin listener on loopback. Use an SSH tunnel or a TLS-authenticated reverse proxy for remote access, and never transmit the admin token over public plaintext HTTP.
- Keep `TUNNL_ADMIN_TOKEN` separate from client tokens and generate it with `tunnld generate-admin-token`.
- Scope `TUNNL_CLOUDFLARE_API_TOKEN` to Zone Read and DNS Write for only the managed zone.
- Back up the SQLite database and its associated WAL state using a SQLite-aware snapshot procedure.
- Apply request limits and upstream abuse protection before operating a public anonymous service.

Bootstrap and admin-managed client tokens are appropriate for a small trusted deployment. A public multi-tenant deployment still needs user-facing account management, rate limiting, quotas, persistent audit tooling, and abuse response controls before accepting untrusted users.
