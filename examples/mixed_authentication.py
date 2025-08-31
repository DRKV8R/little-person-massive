#!/usr/bin/env python3
"""
Mixed authentication example - demonstrating traditional and passwordless users coexisting.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aauth import AAuth, AuthMethod

def main():
    """Demonstrate mixed authentication scenarios."""
    print("=== Mixed Authentication Example ===\n")
    
    # Test traditional JWT authentication
    print("1. Testing Traditional JWT Authentication:")
    jwt_auth = AAuth(method=AuthMethod.JWT)
    
    # Register traditional user
    user1 = jwt_auth.register("traditional_user", "user1@example.com", "SecurePass123!")
    print(f"   ✓ Traditional user registered: {user1['username']}")
    
    # Authenticate with password
    token1 = jwt_auth.authenticate("traditional_user", "SecurePass123!")
    print(f"   ✓ Traditional authentication successful")
    
    # Verify token
    verified1 = jwt_auth.verify_token(token1)
    print(f"   ✓ Token verified for: {verified1['username']}")
    
    # Test passwordless authentication
    print("\n2. Testing Passwordless 2FA Authentication:")
    passwordless_auth = AAuth(method=AuthMethod.PASSWORDLESS_2FA)
    
    # Register passwordless user
    user2 = passwordless_auth.register("passwordless_user", "user2@example.com")
    print(f"   ✓ Passwordless user registered: {user2['username']}")
    print(f"   ✓ Passwordless flag: {user2.get('passwordless', False)}")
    
    # Request 2FA code
    result = passwordless_auth.authenticate("passwordless_user")
    print(f"   ✓ 2FA code requested: {result['message']}")
    
    # Get the code (demo purposes)
    code = passwordless_auth.pending_2fa_codes["passwordless_user"]["code"]
    print(f"   📧 Demo 2FA code: {code}")
    
    # Complete authentication
    token2 = passwordless_auth.authenticate("passwordless_user", code_2fa=code)
    print(f"   ✓ Passwordless authentication successful")
    
    # Verify token
    verified2 = passwordless_auth.verify_token(token2)
    print(f"   ✓ Token verified for: {verified2['username']}")
    print(f"   ✓ Passwordless user: {verified2.get('passwordless', False)}")
    
    # Demonstrate security differences
    print("\n3. Security Feature Comparison:")
    print(f"   Traditional user has password hash: {'password_hash' in jwt_auth.users['traditional_user']}")
    print(f"   Passwordless user has password hash: {'password_hash' in passwordless_auth.users['passwordless_user']}")
    print(f"   Traditional user MFA enabled: {jwt_auth.users['traditional_user'].get('mfa_enabled', False)}")
    print(f"   Passwordless user MFA enabled: {passwordless_auth.users['passwordless_user'].get('mfa_enabled', False)}")
    
    # Test error handling
    print("\n4. Error Handling Tests:")
    
    # Try passwordless auth with password (should fail gracefully)
    try:
        passwordless_auth.register("test_user", "test@example.com", "password123")
        print("   ✗ Unexpected: Password registration allowed in passwordless mode")
    except Exception as e:
        print(f"   ✓ Correctly rejected password registration in passwordless mode")
    
    # Try traditional auth without password
    try:
        jwt_auth.register("test_user2", "test2@example.com")
        print("   ✗ Unexpected: Passwordless registration allowed in JWT mode")
    except Exception as e:
        print(f"   ✓ Correctly required password for JWT mode")
    
    print("\n=== Mixed Authentication Example Completed ===")

if __name__ == "__main__":
    main()