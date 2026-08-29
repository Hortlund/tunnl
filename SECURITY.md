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
- Back up the SQLite database and its associated WAL state using a SQLite-aware snapshot procedure.
- Apply request limits and upstream abuse protection before operating a public anonymous service.

The initial token allowlist is appropriate for a small trusted deployment. A public multi-tenant deployment needs account management, token rotation, rate limiting, quotas, audit tooling, and abuse response controls before accepting untrusted users.
