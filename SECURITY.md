# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email the maintainers with details of the vulnerability
3. Include steps to reproduce, potential impact, and any suggested fixes
4. Allow reasonable time for a fix before public disclosure

## Security Measures

This project implements multiple layers of security:

### Authentication & Authorization

- **OAuth 2.0 with PKCE**: All API access requires OAuth authentication
- **Token Introspection**: Real-time token validation (RFC 7662)
- **Scope-based Access Control**: Fine-grained permissions via OAuth scopes
- **Optional RFC 8707 Validation**: Strict resource parameter checking

### Code Security

Automated security scanning via GitHub Actions:

- **CodeQL**: Static analysis for security vulnerabilities
- **Bandit**: Python security linter
- **Trivy**: Vulnerability scanner for dependencies and Docker images
- **pip-audit**: Check for known vulnerabilities in Python packages
- **Safety**: Additional vulnerability database scanning

### Secret Management

- **Environment Variables**: All credentials stored in `.env` files (gitignored)
- **Secret Detection**: Pre-commit hooks scan for accidentally committed secrets
- **No Hardcoded Credentials**: All authentication uses environment variables

### Docker Security

- **Multi-stage Builds**: Minimal production images
- **Non-root User**: Containers run as non-privileged user
- **Image Scanning**: Trivy scans for vulnerabilities in base images
- **Minimal Dependencies**: Only required packages installed

### Network Security

- **HTTPS/TLS**: Production deployment requires valid SSL certificates
- **CORS Configuration**: Properly configured cross-origin headers
- **Reverse Proxy**: Nginx handles SSL termination and request filtering

## Development Security

### Pre-commit Hooks

Install pre-commit hooks to catch security issues before committing:

```bash
pip install pre-commit
pre-commit install
```

This will automatically run:
- Secret detection (detect-secrets)
- Security linting (bandit)
- Code formatting (black, isort)
- Static analysis (ruff, mypy)

### Local Security Scanning

Run security checks locally:

```bash
make security
```

This runs:
- `pip-audit` - Check for known vulnerabilities
- `safety` - Additional vulnerability scanning
- `bandit` - Security linting
- Secret detection patterns

## Best Practices

### For Contributors

1. **Never commit secrets**: Use environment variables for all credentials
2. **Run pre-commit hooks**: Ensure `pre-commit install` is set up
3. **Review dependencies**: Check security of new dependencies before adding
4. **Update regularly**: Keep dependencies up to date
5. **Test OAuth flows**: Verify authentication works correctly

### For Deployers

1. **Use strong secrets**: Generate cryptographically secure client secrets
2. **Enable HTTPS**: Always use TLS in production
3. **Restrict CORS**: Configure appropriate CORS policies for your domain
4. **Monitor logs**: Watch for suspicious authentication patterns
5. **Update regularly**: Apply security patches promptly
6. **Use `--oauth-strict`**: Enable RFC 8707 validation in production

## Known Limitations

**Educational Use**: This server is designed for educational and development purposes. While it implements OAuth 2.0 standards and security best practices, it has not undergone comprehensive security auditing or hardening for production environments handling highly sensitive data.

**In-Memory Storage**: The auth server uses in-memory token storage. For production:
- Implement persistent token storage
- Add token revocation mechanisms
- Consider using a proper OAuth server like Keycloak

**Rate Limiting**: No built-in rate limiting. For production:
- Implement rate limiting at nginx level
- Add request throttling to prevent DoS
- Monitor for abuse patterns

**Session Management**: Basic session handling. For production:
- Implement secure session storage
- Add session timeout and rotation
- Consider using Redis for distributed sessions

## Dependency Management

### Automated Updates

GitHub Actions runs weekly security scans to detect vulnerable dependencies.

### Manual Updates

Check for updates regularly:

```bash
pip list --outdated
pip-audit
safety check
```

Update dependencies:

```bash
pip install --upgrade -r requirements.txt
```

## Compliance

This project follows:
- OAuth 2.0 (RFC 6749)
- OAuth 2.0 PKCE (RFC 7636)
- Token Introspection (RFC 7662)
- Dynamic Client Registration (RFC 7591)
- OAuth 2.0 Authorization Server Metadata (RFC 8414)
- Resource Indicators for OAuth 2.0 (RFC 8707) - optional

## Security Checklist

Before deploying to production:

- [ ] All secrets in environment variables (not hardcoded)
- [ ] HTTPS enabled with valid certificates
- [ ] CORS configured for your specific domain
- [ ] OAuth client secrets are cryptographically secure
- [ ] Reverse proxy (nginx) properly configured
- [ ] Docker images scanned for vulnerabilities
- [ ] Dependencies updated to latest secure versions
- [ ] Monitoring and logging in place
- [ ] Backup and recovery plan established
- [ ] Security scanning in CI/CD pipeline
- [ ] Pre-commit hooks installed for all developers

## Contact

For security concerns, contact the project maintainers.
