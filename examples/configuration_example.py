#!/usr/bin/env python3
"""
Configuration example showing different AAuth configurations.
"""

from aauth import AAuth, AuthMethod, AAuthConfig

def test_custom_config():
    """Test AAuth with custom configuration."""
    print("=== Custom Configuration Example ===")
    
    # Custom configuration
    custom_config = {
        'token_expiry': 7200,  # 2 hours
        'password_min_length': 10,
        'password_require_special': True,
        'max_login_attempts': 3,
        'lockout_duration': 300,  # 5 minutes
        'rate_limit': 50,  # 50 requests per minute
    }
    
    auth = AAuth(method=AuthMethod.JWT, config=custom_config)
    print("✓ AAuth initialized with custom config")
    
    # Show some config values
    print(f"Token expiry: {auth.config.get('token_expiry')} seconds")
    print(f"Password min length: {auth.config.get('password_min_length')}")
    print(f"Max login attempts: {auth.config.get('max_login_attempts')}")
    print(f"Rate limit: {auth.config.get('rate_limit')} req/min")
    
    # Test password validation with new requirements
    try:
        user = auth.register(
            username="config_user",
            password="VerySecurePass123!@#",  # Meets all requirements
            email="config@example.com"
        )
        print(f"✓ User registered with strong password: {user['username']}")
    except Exception as e:
        print(f"✗ Registration failed: {e}")
    
    # Test with weak password
    try:
        auth.register("weak_user", "weak", "weak@example.com")
    except Exception as e:
        print(f"✓ Weak password correctly rejected: {e}")
    
    print()

def test_environment_config():
    """Test loading configuration from environment variables."""
    print("=== Environment Configuration Example ===")
    
    import os
    
    # Set some environment variables
    os.environ['AAUTH_TOKEN_EXPIRY'] = '5400'  # 1.5 hours
    os.environ['AAUTH_RATE_LIMIT'] = '200'
    os.environ['AAUTH_MFA_ENABLED'] = 'true'
    
    auth = AAuth(method=AuthMethod.JWT)
    print("✓ AAuth initialized with environment config")
    
    print(f"Token expiry from env: {auth.config.get('token_expiry')} seconds")
    print(f"Rate limit from env: {auth.config.get('rate_limit')} req/min")
    print(f"MFA enabled from env: {auth.config.get('mfa_enabled')}")
    
    # Clean up environment
    del os.environ['AAUTH_TOKEN_EXPIRY']
    del os.environ['AAUTH_RATE_LIMIT']
    del os.environ['AAUTH_MFA_ENABLED']
    
    print()

def test_security_features():
    """Test security features like rate limiting and account lockout."""
    print("=== Security Features Example ===")
    
    # Configure for quick testing
    security_config = {
        'max_login_attempts': 2,
        'lockout_duration': 5,  # 5 seconds for testing
        'rate_limit': 5,  # Low limit for testing
    }
    
    auth = AAuth(method=AuthMethod.JWT, config=security_config)
    
    # Register a user
    user = auth.register("security_user", "SecurePass123!", "security@example.com")
    print(f"✓ Registered user: {user['username']}")
    
    # Test failed login attempts
    print("\nTesting account lockout...")
    for i in range(3):
        try:
            auth.authenticate("security_user", "wrongpassword")
        except Exception as e:
            print(f"Attempt {i+1}: {e}")
    
    # Try to login with correct password (should be locked)
    try:
        auth.authenticate("security_user", "SecurePass123!")
    except Exception as e:
        print(f"✓ Account correctly locked: {e}")
    
    print()

def main():
    """Run configuration examples."""
    print("=== AAuth Configuration Examples ===\n")
    
    try:
        test_custom_config()
        test_environment_config()
        test_security_features()
        
        print("=== All configuration examples completed ===")
    except Exception as e:
        print(f"Error during testing: {e}")

if __name__ == "__main__":
    main()