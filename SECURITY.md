# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | ✅                 |
| < latest | ❌                |

## Reporting a Vulnerability

If you discover a security vulnerability in cs-routeros-bouncer, please report it responsibly:

1. **Do NOT open a public issue** for security vulnerabilities
2. **Email:** Send details to the repository owner via GitHub private message or open a [private security advisory](https://github.com/jmrplens/cs-routeros-bouncer/security/advisories/new)
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

You should receive a response within 48 hours. We will work with you to understand and address the issue before any public disclosure.

## Security Considerations

This bouncer interacts with your network firewall. Please keep in mind:

- **RouterOS API credentials**: Use a dedicated user with minimal permissions (only `read`, `write`, `api` for firewall and address lists)
- **CrowdSec API key**: Keep bouncer API keys secure; rotate them periodically
- **Network exposure**: The metrics endpoint (default port 2112) should not be exposed to the internet
- **TLS**: Enable TLS for the RouterOS API connection in production (`mikrotik.tls: true`, port 8729)
- **Docker**: The container runs as a non-root user by default
