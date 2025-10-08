# Security Policy

## Supported Versions

We actively support the following versions of LibHdHomerun-Docker with security updates:

| Version     | Supported          |
| ----------- | ------------------ |
| v2025.05.06+ | :white_check_mark: |
| < v2025.05.06 | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please follow these guidelines:

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please report security vulnerabilities by:

1. **Email**: Send details to [luca@ferrarotti.it](mailto:luca@ferrarotti.it)
2. **Subject Line**: Use "[SECURITY] LibHdHomerun-Docker - [Brief Description]"
3. **Encryption**: For sensitive reports, you may request our PGP key

### What to Include

Please provide as much information as possible:

- **Description**: Clear description of the vulnerability
- **Impact**: Potential impact and attack scenarios
- **Reproduction**: Step-by-step instructions to reproduce
- **Environment**: Docker version, host OS, architecture
- **Proof of Concept**: Code or commands demonstrating the issue
- **Suggested Fix**: If you have ideas for remediation

### Response Timeline

- **Initial Response**: Within 48 hours
- **Assessment**: Within 7 days
- **Fix Timeline**: Depends on severity (see below)
- **Disclosure**: Coordinated disclosure after fix is available

## Vulnerability Severity

### Critical (Fix within 24-48 hours)
- Remote code execution
- Container escape
- Privilege escalation to host
- Data exfiltration from host system

### High (Fix within 1 week)
- Local privilege escalation
- Denial of service affecting host
- Information disclosure of sensitive data

### Medium (Fix within 2 weeks)
- Limited information disclosure
- Local denial of service
- Authentication bypass

### Low (Fix in next release)
- Minor information leaks
- Configuration issues

## Security Best Practices

### For Users

1. **Keep Updated**: Always use the latest version
2. **Network Security**: Run containers in isolated networks
3. **User Permissions**: Don't run as root unless necessary
4. **Host Security**: Keep Docker and host OS updated
5. **Resource Limits**: Set appropriate CPU/memory limits

### For Contributors

1. **Dependencies**: Keep all dependencies updated
2. **Secrets**: Never commit secrets or credentials
3. **Input Validation**: Validate all user inputs
4. **Least Privilege**: Follow principle of least privilege
5. **Security Testing**: Test for common vulnerabilities

## Security Features

### Current Security Measures

- **Multi-stage Builds**: Minimal attack surface
- **Non-root User**: Container runs as non-privileged user
- **Dependency Scanning**: Automated vulnerability scanning with Docker Scout
- **Code Analysis**: SonarQube security analysis
- **Supply Chain**: Dependabot for dependency updates

### Planned Security Enhancements

- Container signing and verification
- SBOM (Software Bill of Materials) generation
- Runtime security monitoring integration
- Security policy enforcement

## Disclosure Policy

### Coordinated Disclosure

1. **Private Report**: Vulnerability reported privately
2. **Investigation**: We investigate and develop fix
3. **Fix Development**: Patch created and tested
4. **Release**: Security update released
5. **Public Disclosure**: Details published after fix is available
6. **Credit**: Reporter credited (if desired)

### Timeline

- **90 days**: Maximum time before public disclosure
- **Shorter for critical**: Critical issues may be disclosed sooner
- **Extension possible**: If fix requires significant changes

## Security Contact

- **Primary Contact**: Luca Ferrarotti
- **Email**: [luca@ferrarotti.it](mailto:luca@ferrarotti.it)
- **Response Time**: Within 48 hours
- **Timezone**: UTC+1 (CET)

## Acknowledgments

We appreciate security researchers and users who help improve our security:

- Security reports are acknowledged in release notes
- Hall of Fame for significant contributions
- Coordination with CVE assignment when applicable

---

**Last Updated**: January 2024
**Next Review**: Quarterly

*This security policy is subject to updates. Check back regularly for the latest version.*