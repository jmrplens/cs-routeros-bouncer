# Security

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest | :material-check: |
| < latest | :material-close: |

## Reporting a Vulnerability

If you discover a security vulnerability in cs-routeros-bouncer, please report it responsibly:

1. **Do NOT open a public issue** for security vulnerabilities
2. Open a [private security advisory](https://github.com/jmrplens/cs-routeros-bouncer/security/advisories/new) on GitHub
3. **Include:**
    - Description of the vulnerability
    - Steps to reproduce
    - Potential impact
    - Suggested fix (if any)

You should receive a response within 48 hours.

## Security Considerations

This bouncer interacts with your network firewall. Keep these points in mind:

### RouterOS API credentials

- Use a **dedicated user** with minimal permissions (`read`, `write`, `api`, `sensitive`)
- Deny all unnecessary policies
- Use a strong, unique password
- Consider using TLS (port 8729) for the API connection

### CrowdSec API key

- Keep bouncer API keys secure
- Rotate them periodically with `cscli bouncers add/delete`
- Never commit API keys to source control

### Network exposure

- The **metrics endpoint** (default port 2112) should not be exposed to the internet
- Restrict API access to the bouncer host IP on the router
- Use firewall rules to protect the metrics port

### TLS

For production deployments:

```yaml
mikrotik:
  tls: true
  tls_insecure: false  # Only true for self-signed certs
```

### Docker

The container runs as a non-root user by default. Sensitive values should be passed via environment variables, not baked into the image.
