# Passwordless Authentication with AAuth

AAuth now supports **passwordless authentication**, a cutting-edge approach that eliminates passwords entirely while maintaining the highest levels of security. This system is perfect for privacy-first applications and can scale up to quantum-level cryptography.

## Overview

Passwordless authentication in AAuth uses:
- **Username** for identification
- **Email** for secure delivery
- **Time-based 2FA codes** for authentication
- **No passwords** stored or managed

## Key Benefits

### 🔐 Enhanced Security
- **No password storage** - eliminates password-related security risks
- **Automatic 2FA codes** - sent to verified email addresses
- **Quantum-ready cryptography** - JWT tokens can use quantum-safe algorithms
- **Code expiration** - 2FA codes expire automatically (default: 5 minutes)

### 🛡️ Privacy-First Design
- **Data isolation** - user data tied to username, useless without email mapping
- **Corporate protection** - data becomes meaningless to other organizations
- **Zero password recovery** - no forgotten password flows needed

### ⚡ Simplified User Experience
- **No password complexity** - users don't need to remember passwords
- **Automatic code delivery** - 2FA codes sent instantly when username is provided
- **One-step authentication** - username + email code = access

## Usage Examples

### Basic Passwordless Registration

```python
from aauth import AAuth, AuthMethod

# Initialize with passwordless 2FA
auth = AAuth(method=AuthMethod.PASSWORDLESS_2FA)

# Register user - no password required
user = auth.register(
    username="user123",
    email="user@example.com"
)
```

### Passwordless Authentication Flow

```python
# Step 1: Request 2FA code (automatic when username provided)
result = auth.authenticate("user123")
# Output: {"status": "2fa_code_sent", "message": "2FA code sent to your email"}

# Step 2: User checks email and enters code
# Complete authentication with 2FA code
token = auth.authenticate("user123", code_2fa="123456")
# Returns JWT token for authenticated session
```

### Alternative Code Request Method

```python
# Explicitly request 2FA code
result = auth.request_2fa_code("user123")
# Output: {"status": "success", "message": "2FA code sent to user@example.com"}

# Then authenticate with code
token = auth.authenticate("user123", code_2fa="123456")
```

## Implementation Features

### Automatic Code Generation
- 6-digit random codes by default
- Cryptographically secure generation
- Configurable code length

### Code Security
- Time-based expiration (5 minutes default)
- Limited attempts (3 attempts default)
- Rate limiting protection
- Automatic cleanup of expired codes

### Email Integration
- Secure code delivery to verified emails
- Mock implementation for development
- Ready for production email services

## Migration from Password-based Authentication

### For Existing Users
1. **Gradual Migration**: Keep both systems running
2. **User Choice**: Let users opt into passwordless
3. **Data Preservation**: Existing user data remains intact
4. **Rollback Support**: Can revert if needed

### Code Changes Required

#### Before (Password-based)
```python
# Registration
user = auth.register("username", "password123", "email@example.com")

# Authentication
token = auth.authenticate("username", "password123")
```

#### After (Passwordless)
```python
# Registration
user = auth.register("username", "email@example.com")

# Authentication (2-step process)
result = auth.authenticate("username")  # Sends 2FA code
token = auth.authenticate("username", code_2fa="123456")  # Complete auth
```

## Security Considerations

### Quantum-Safe Cryptography
The passwordless system is designed to support quantum-safe cryptographic algorithms:

```python
# Configure quantum-safe JWT signing
config = {
    'jwt_algorithm': 'RS256',  # Can be upgraded to quantum-safe algorithms
    'secret_key': 'quantum-safe-key'
}
auth = AAuth(method=AuthMethod.PASSWORDLESS_2FA, config=config)
```

### Rate Limiting
Built-in protection against abuse:
- Default: 100 requests per minute per identifier
- Separate limits for 2FA code requests
- Configurable thresholds

### Account Security
- Account lockout after failed attempts
- Email verification requirements
- Activity logging and monitoring

## Production Deployment

### Email Service Integration
Replace the mock email sender with a real service:

```python
def _send_2fa_code(self, email: str, code: str, method: str = "email") -> bool:
    """Send 2FA code via real email service."""
    # Integrate with your email service (SendGrid, AWS SES, etc.)
    email_service.send(
        to=email,
        subject="Your 2FA Code",
        body=f"Your authentication code is: {code}"
    )
    return True
```

### Database Storage
Replace in-memory storage with persistent database:

```python
# Use your preferred database (PostgreSQL, MongoDB, etc.)
# Store users, sessions, and pending 2FA codes
```

### Monitoring and Analytics
Track authentication patterns:
- 2FA code request rates
- Authentication success/failure rates
- User adoption of passwordless authentication

## Configuration Options

```python
passwordless_config = {
    'code_length': 6,           # Length of 2FA codes
    'code_expiry': 300,         # Code expiration in seconds (5 minutes)
    'max_code_attempts': 3,     # Maximum attempts per code
    'rate_limit': 50,           # Requests per minute
    'email_method': 'smtp'      # Email delivery method
}

auth = AAuth(
    method=AuthMethod.PASSWORDLESS_2FA,
    config=passwordless_config
)
```

## Error Handling

Common error scenarios and handling:

```python
try:
    result = auth.authenticate("username", code_2fa="123456")
except InvalidCredentialsError:
    # Invalid or expired 2FA code
    print("Code is invalid or expired. Please request a new code.")
except RateLimitError:
    # Too many requests
    print("Too many attempts. Please wait before trying again.")
except UserNotFoundError:
    # Username doesn't exist
    print("User not found. Please check the username.")
```

## Testing and Development

The passwordless system includes comprehensive testing support:

```bash
# Run passwordless authentication demo
python examples/passwordless_usage.py

# CLI demo with passwordless authentication
python aauth_cli.py --method passwordless_2fa demo

# Register passwordless user via CLI
python aauth_cli.py --method passwordless_2fa register username email@example.com
```

This passwordless authentication system provides enterprise-grade security while eliminating the complexity and security risks associated with password management.