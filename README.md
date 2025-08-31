# little-person-massive

## AAuth - Alternative Authentication System

AAuth is a lightweight, flexible authentication system designed as a generic alternative to OAuth for applications that need simpler, more direct authentication mechanisms.

### Benefits and Bonuses

**🚀 Key Advantages over OAuth:**
- **Simplified Implementation**: No complex redirect flows or token exchanges
- **Reduced Dependencies**: Minimal external service requirements
- **Direct Control**: Full control over authentication logic and user flow
- **Faster Integration**: Quick setup without extensive OAuth provider configuration
- **Privacy-First**: User data stays within your application ecosystem
- **Customizable**: Easy to adapt to specific application requirements
- **Lightweight**: Minimal overhead and resource usage
- **Self-Contained**: No reliance on external OAuth providers

**💰 Cost Benefits:**
- No OAuth provider fees or rate limits
- Reduced infrastructure complexity
- Lower maintenance overhead

**🔒 Security Features:**
- JWT-based token system
- Configurable token expiration
- Rate limiting built-in
- Password hashing with bcrypt
- Session management
- CSRF protection

### Authentication Alternatives Provided

1. **Passwordless 2FA Authentication** ⭐ **NEW**
   - No passwords required - username + email + 2FA codes only
   - Privacy-first design - data tied to username, useless without email mapping
   - Automatic 2FA code generation and delivery
   - Quantum-ready cryptography support
   - Eliminates password recovery complexity
   - Enhanced security through 2FA-only authentication

2. **API Key Authentication**
   - Simple API key-based access
   - Suitable for service-to-service communication
   - Easy to implement and manage

3. **JWT Token Authentication**
   - Stateless authentication
   - Configurable expiration times
   - Suitable for web and mobile applications

4. **Session-Based Authentication**
   - Traditional cookie-based sessions
   - Server-side session storage
   - Good for web applications

5. **Basic Authentication**
   - Username/password over HTTPS
   - Simple implementation
   - Suitable for internal tools

5. **Multi-Factor Authentication (MFA)**
   - TOTP (Time-based One-Time Password) support
   - SMS-based verification option
   - Email-based verification

6. **Social Login Integration**
   - Simplified social media authentication
   - Support for major platforms without full OAuth complexity
   - Custom provider integration

### Quick Start

```python
from aauth import AAuth, AuthMethod

# Traditional JWT Authentication
auth = AAuth(method=AuthMethod.JWT)
user = auth.register("username", "email@example.com", "password123")
token = auth.authenticate("username", "password123")
user_data = auth.verify_token(token)

# NEW: Passwordless 2FA Authentication
auth = AAuth(method=AuthMethod.PASSWORDLESS_2FA)

# Register without password
user = auth.register("username", "email@example.com")

# Authenticate - sends 2FA code to email
result = auth.authenticate("username")  # {"status": "2fa_code_sent", ...}

# Complete authentication with 2FA code
token = auth.authenticate("username", code_2fa="123456")
user_data = auth.verify_token(token)
```

### Installation

```bash
pip install aauth
```

### Configuration

```python
# aauth_config.py
AAUTH_CONFIG = {
    'secret_key': 'your-secret-key',
    'token_expiry': 3600,  # 1 hour
    'hash_rounds': 12,
    'rate_limit': 100,  # requests per minute
    'mfa_enabled': False,
    'session_timeout': 1800  # 30 minutes
}
```

### Documentation

- [Installation Guide](docs/installation.md)
- [Passwordless Authentication Guide](docs/passwordless-authentication.md) ⭐ **NEW**
- [API Reference](docs/api.md)
- [Configuration Options](docs/configuration.md)
- [Examples](examples/)
  - [Passwordless Usage Example](examples/passwordless_usage.py) ⭐ **NEW**
  - [Basic Usage Example](examples/basic_usage.py)
  - [Method Comparison](examples/method_comparison.py)
- [Migration from OAuth](docs/oauth-migration.md)

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### License

MIT License - see LICENSE file for details
