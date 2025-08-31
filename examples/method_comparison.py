#!/usr/bin/env python3
"""
Comparison example showing different authentication methods.
"""

from aauth import AAuth, AuthMethod

def test_jwt_auth():
    """Test JWT authentication."""
    print("=== JWT Authentication ===")
    auth = AAuth(method=AuthMethod.JWT)
    
    # Register user
    user = auth.register("jwt_user", "Password123!", "jwt@example.com")
    print(f"Registered: {user['username']}")
    
    # Authenticate
    token = auth.authenticate("jwt_user", "Password123!")
    print(f"JWT Token: {token[:30]}...")
    
    # Verify
    user_data = auth.verify_token(token)
    print(f"Verified user: {user_data['username']}")
    print()

def test_session_auth():
    """Test session-based authentication."""
    print("=== Session Authentication ===")
    auth = AAuth(method=AuthMethod.SESSION)
    
    # Register user
    user = auth.register("session_user", "Password123!", "session@example.com")
    print(f"Registered: {user['username']}")
    
    # Authenticate
    session_id = auth.authenticate("session_user", "Password123!")
    print(f"Session ID: {session_id[:30]}...")
    
    # Verify
    user_data = auth.verify_token(session_id)
    print(f"Verified user: {user_data['username']}")
    
    # Logout
    auth.logout(session_id)
    print("Logged out successfully")
    print()

def test_api_key_auth():
    """Test API key authentication."""
    print("=== API Key Authentication ===")
    auth = AAuth(method=AuthMethod.API_KEY)
    
    # Register user
    user = auth.register("api_user", "Password123!", "api@example.com")
    print(f"Registered: {user['username']}")
    
    # Authenticate
    api_key = auth.authenticate("api_user", "Password123!")
    print(f"API Key: {api_key[:30]}...")
    
    # Verify
    user_data = auth.verify_token(api_key)
    print(f"Verified user: {user_data['username']}")
    print()

def test_basic_auth():
    """Test basic authentication."""
    print("=== Basic Authentication ===")
    auth = AAuth(method=AuthMethod.BASIC)
    
    # Register user
    user = auth.register("basic_user", "Password123!", "basic@example.com")
    print(f"Registered: {user['username']}")
    
    # Authenticate (returns user data directly)
    user_data = auth.authenticate("basic_user", "Password123!")
    print(f"Authenticated user: {user_data['username']}")
    print()

def main():
    """Run all authentication method examples."""
    print("=== AAuth Method Comparison Example ===\n")
    
    try:
        test_jwt_auth()
        test_session_auth()
        test_api_key_auth()
        test_basic_auth()
        
        print("=== All authentication methods tested successfully ===")
    except Exception as e:
        print(f"Error during testing: {e}")

if __name__ == "__main__":
    main()