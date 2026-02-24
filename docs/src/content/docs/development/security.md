---
title: Security
description: Security policy, supported versions, and vulnerability reporting.
---

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest release | ✅ |
| Previous minor | ✅ |
| Older versions | ❌ |

## Reporting vulnerabilities

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public issue
2. Email the maintainer directly or use GitHub's private vulnerability reporting feature
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to respond within 48 hours and will work with you to understand and address the issue.

## Security considerations

### RouterOS API credentials

- Use a dedicated user with minimal permissions (only `api`, `read`, `write` policies)
- Use TLS when possible (`mikrotik.tls: true`)
- Store credentials securely (environment variables or secrets management)
- Never commit credentials to version control

### CrowdSec LAPI connection

- Use TLS certificates for LAPI connections when available
- Restrict LAPI access to trusted networks
- Rotate bouncer API keys periodically

### Metrics endpoint

- The `/metrics` and `/health` endpoints do not require authentication
- Restrict access via network segmentation or firewall rules
- Do not expose the metrics port to the internet

### Docker security

- The official Docker image runs as a non-root user
- Use read-only filesystem mount where possible
- Limit container capabilities
- Use secrets management for credentials (Docker secrets, Kubernetes secrets)

### Firewall rule integrity

- The bouncer identifies its rules by structured comments — do not modify these comments manually
- Use the `comment_prefix` option to avoid conflicts with other tools
- The bouncer performs cleanup on startup and shutdown to prevent stale rules
