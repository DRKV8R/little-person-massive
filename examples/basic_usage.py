#!/usr/bin/env python3
"""
Basic usage example for AAuth.
"""

from aauth import AAuth, AuthMethod

def main():
    """Demonstrate basic AAuth usage."""
    print("=== AAuth Basic Usage Example ===\n")
    
    # Initialize AAuth with JWT method
    auth = AAuth(method=AuthMethod.JWT)
    print("✓ AAuth initialized with JWT method")
    
    # Register a new user
    try:
        user = auth.register(
            username="john_doe",
            password="SecurePass123!",
            email="john@example.com",
            first_name="John",
            last_name="Doe"
        )
        print(f"✓ User registered: {user['username']} ({user['email']})")
    except Exception as e:
        print(f"✗ Registration failed: {e}")
        return
    
    # Authenticate user
    try:
        token = auth.authenticate("john_doe", "SecurePass123!")
        print(f"✓ Authentication successful, token: {token[:20]}...")
    except Exception as e:
        print(f"✗ Authentication failed: {e}")
        return
    
    # Verify token
    try:
        user_data = auth.verify_token(token)
        print(f"✓ Token verified for user: {user_data['username']}")
    except Exception as e:
        print(f"✗ Token verification failed: {e}")
        return
    
    # Try invalid authentication
    try:
        auth.authenticate("john_doe", "wrongpassword")
    except Exception as e:
        print(f"✓ Invalid credentials correctly rejected: {e}")
    
    # Change password
    try:
        auth.change_password("john_doe", "SecurePass123!", "NewSecurePass456!")
        print("✓ Password changed successfully")
    except Exception as e:
        print(f"✗ Password change failed: {e}")
    
    # Test new password
    try:
        new_token = auth.authenticate("john_doe", "NewSecurePass456!")
        print(f"✓ Authentication with new password successful")
    except Exception as e:
        print(f"✗ Authentication with new password failed: {e}")
    
    print("\n=== Example completed ===")


if __name__ == "__main__":
    main()