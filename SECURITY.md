# Security policy

## Supported version

Security fixes are applied to the current `main` branch.

## Reporting a vulnerability

Please do **not** open a public issue for a suspected vulnerability, exposed secret, authentication bypass, tenant-isolation concern, or unsafe automation path.

Instead, contact the repository owner privately with:

- A clear description of the issue
- Affected file, endpoint, or feature
- Safe reproduction steps
- Expected and observed behavior
- Impact assessment, if known

Do not include customer data, live credentials, private keys, access tokens, or destructive proof-of-concept payloads.

## Security expectations for contributors

- Never commit `.env` files, credentials, customer events, or production exports.
- Keep outbound TLS verification enabled. Use a trusted internal CA; do not set `verify=False` in connector code.
- Use tenant-scoped queries for customer data.
- Require authentication and permission checks for settings, cases, investigations, integrations, and response actions.
- Keep new external actions disabled or dry-run by default.
- Add tests for authentication, authorization, tenant isolation, and safe failure behavior when changing sensitive paths.
- Report dependency vulnerabilities found by CI or `pip-audit`.

## Deployment baseline

Production installations should use HTTPS, strong secrets, PostgreSQL backups, least-privilege service accounts, IP allow-lists, webhook authentication, MFA/SSO where applicable, and shadow mode before enabling any customer-approved action policy.
