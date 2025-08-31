# Migration from OAuth

## Why Migrate from OAuth to AAuth?

### OAuth Challenges
- Complex implementation with multiple redirect flows
- Dependency on external OAuth providers
- Rate limiting and costs from providers
- Privacy concerns with data sharing
- Vendor lock-in

### AAuth Benefits
- **Simplified Integration**: Direct authentication without redirects
- **Full Control**: Complete ownership of authentication flow
- **Cost Effective**: No external provider fees
- **Privacy First**: User data stays in your system
- **Customizable**: Adapt to your specific needs

## Migration Process

### 1. Assess Current OAuth Implementation

First, identify what OAuth features you're currently using:

```python
# Current OAuth flow (example)
def oauth_login():
    # Redirect to OAuth provider
    redirect_url = oauth_provider.get_auth_url()
    return redirect(redirect_url)

def oauth_callback():
    # Handle OAuth callback
    code = request.args.get('code')
    token = oauth_provider.exchange_code(code)
    user_info = oauth_provider.get_user_info(token)
    return create_session(user_info)
```

### 2. Replace with AAuth

```python
from aauth import AAuth, AuthMethod

# Initialize AAuth
auth = AAuth(method=AuthMethod.JWT)

def aauth_login():
    # Direct authentication
    username = request.form['username']
    password = request.form['password']
    
    try:
        token = auth.authenticate(username, password)
        return {'token': token, 'status': 'success'}
    except Exception as e:
        return {'error': str(e), 'status': 'failed'}

def aauth_register():
    # User registration
    username = request.form['username']
    password = request.form['password']
    email = request.form['email']
    
    try:
        user = auth.register(username, password, email)
        return {'user': user, 'status': 'success'}
    except Exception as e:
        return {'error': str(e), 'status': 'failed'}
```

### 3. Data Migration

If you have existing OAuth users, you can migrate them:

```python
def migrate_oauth_users():
    """Migrate existing OAuth users to AAuth."""
    
    # Get existing users from your database
    oauth_users = get_oauth_users_from_db()
    
    for oauth_user in oauth_users:
        try:
            # Create AAuth user
            # Note: You'll need to handle password creation
            # Option 1: Generate temporary password and require reset
            temp_password = generate_temp_password()
            
            user = auth.register(
                username=oauth_user['username'],
                password=temp_password,
                email=oauth_user['email'],
                # Migrate additional fields
                first_name=oauth_user.get('first_name'),
                last_name=oauth_user.get('last_name'),
                migrated_from_oauth=True
            )
            
            # Send password reset email
            send_password_reset_email(user['email'], temp_password)
            
            print(f"Migrated user: {user['username']}")
            
        except Exception as e:
            print(f"Failed to migrate {oauth_user['username']}: {e}")
```

### 4. Update Frontend

Replace OAuth buttons/flows with AAuth forms:

```html
<!-- Old OAuth -->
<a href="/oauth/login" class="oauth-button">
    Sign in with OAuth Provider
</a>

<!-- New AAuth -->
<form id="login-form" onsubmit="handleLogin(event)">
    <input type="text" name="username" placeholder="Username" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Sign In</button>
</form>

<script>
async function handleLogin(event) {
    event.preventDefault();
    const formData = new FormData(event.target);
    
    const response = await fetch('/auth/login', {
        method: 'POST',
        body: formData
    });
    
    const result = await response.json();
    
    if (result.status === 'success') {
        localStorage.setItem('auth_token', result.token);
        window.location.href = '/dashboard';
    } else {
        alert('Login failed: ' + result.error);
    }
}
</script>
```

### 5. Update API Authentication

Replace OAuth token validation with AAuth:

```python
# Old OAuth validation
def validate_oauth_token(token):
    try:
        user_info = oauth_provider.validate_token(token)
        return user_info
    except:
        return None

# New AAuth validation
def validate_aauth_token(token):
    try:
        user_data = auth.verify_token(token)
        return user_data
    except:
        return None

# Middleware update
def auth_middleware():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token:
        return {'error': 'No token provided'}, 401
    
    user_data = validate_aauth_token(token)
    if not user_data:
        return {'error': 'Invalid token'}, 401
    
    request.user = user_data
    return None
```

### 6. Configuration Mapping

Map your OAuth configuration to AAuth:

```python
# OAuth config
OAUTH_CONFIG = {
    'client_id': 'your_oauth_client_id',
    'client_secret': 'your_oauth_secret',
    'redirect_uri': 'https://yourapp.com/oauth/callback',
    'scope': 'user:email'
}

# AAuth config
AAUTH_CONFIG = {
    'secret_key': 'your_secret_key',  # Generate new secure key
    'token_expiry': 3600,  # Match your OAuth token expiry
    'password_min_length': 8,
    'mfa_enabled': False,  # Enable if you had 2FA with OAuth
    'email_verification_required': True  # If OAuth provided verified emails
}
```

### 7. Testing Migration

Test the migration thoroughly:

```python
def test_migration():
    """Test migrated authentication."""
    
    # Test registration
    user = auth.register('test_user', 'TestPass123!', 'test@example.com')
    print(f"Registration works: {user['username']}")
    
    # Test authentication
    token = auth.authenticate('test_user', 'TestPass123!')
    print(f"Authentication works: {token[:20]}...")
    
    # Test token validation
    user_data = auth.verify_token(token)
    print(f"Token validation works: {user_data['username']}")
    
    # Test password change
    auth.change_password('test_user', 'TestPass123!', 'NewPass123!')
    print("Password change works")
    
    # Test with new password
    new_token = auth.authenticate('test_user', 'NewPass123!')
    print("New password works")

test_migration()
```

### 8. Gradual Rollout

Consider a gradual migration approach:

1. **Phase 1**: Run AAuth alongside OAuth
2. **Phase 2**: Migrate internal users first
3. **Phase 3**: Migrate external users with communication
4. **Phase 4**: Deprecate OAuth endpoints
5. **Phase 5**: Remove OAuth dependencies

### Common Pitfalls

1. **Password Handling**: OAuth users don't have passwords - handle this carefully
2. **Token Format**: Ensure frontend code handles new token format
3. **Session Management**: Update session handling logic
4. **Error Handling**: OAuth and AAuth have different error patterns
5. **Rate Limiting**: Implement proper rate limiting to replace OAuth's

### Rollback Plan

Always have a rollback plan:

```python
# Feature flag for quick rollback
USE_AAUTH = os.getenv('USE_AAUTH', 'false').lower() == 'true'

def authenticate_user(username, password):
    if USE_AAUTH:
        return aauth_authenticate(username, password)
    else:
        return oauth_authenticate(username, password)
```

This allows you to quickly switch back to OAuth if issues arise during migration.