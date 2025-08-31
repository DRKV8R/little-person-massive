#!/usr/bin/env python3
"""
Passwordless authentication example for AAuth.

This example demonstrates the new passwordless authentication system that uses:
- Username for identification
- Email for contact
- 2FA codes for authentication
- No passwords required

This provides enhanced security while eliminating password recovery complexity.
"""

from aauth import AAuth, AuthMethod

def main():
    """Demonstrate passwordless AAuth usage."""
    print("=== AAuth Passwordless Authentication Example ===\n")
    
    # Initialize AAuth with passwordless 2FA method
    auth = AAuth(method=AuthMethod.PASSWORDLESS_2FA)
    print("✓ AAuth initialized with passwordless 2FA method")
    
    # Register a new user (no password required)
    try:
        user = auth.register(
            username="jane_doe",
            email="jane@example.com",
            first_name="Jane",
            last_name="Doe"
        )
        print(f"✓ User registered without password: {user['username']} ({user['email']})")
        print(f"  Privacy-first: Data tied to username, useless without email verification")
    except Exception as e:
        print(f"✗ Registration failed: {e}")
        return
    
    print("\n--- Step 1: Request 2FA Code ---")
    
    # Method 1: Request 2FA code explicitly
    try:
        result = auth.request_2fa_code("jane_doe")
        print(f"✓ {result['message']}")
    except Exception as e:
        print(f"✗ 2FA code request failed: {e}")
        return
    
    # Method 2: Request 2FA code via authenticate (automatic when username provided)
    print("\n--- Step 2: Automatic 2FA Code via Authenticate ---")
    try:
        result = auth.authenticate("jane_doe")  # No password needed, just username
        print(f"✓ {result['message']}")
        print("  2FA code automatically sent when username is provided")
    except Exception as e:
        print(f"✗ Authentication failed: {e}")
        return
    
    # Simulate user entering the 2FA code (in real usage, this would come from email)
    print("\n--- Step 3: Complete Authentication with 2FA Code ---")
    
    # Get the 2FA code (in demo, we'll simulate user input)
    # In real implementation, user would check their email
    print("📧 Check your email for the 2FA code...")
    
    # For demo purposes, let's access the code directly
    # In production, user would manually enter this from their email
    if "jane_doe" in auth.pending_2fa_codes:
        demo_code = auth.pending_2fa_codes["jane_doe"]["code"]
        print(f"Demo: Using 2FA code: {demo_code}")
        
        try:
            token = auth.authenticate("jane_doe", code_2fa=demo_code)
            print(f"✓ Authentication successful! Token: {token[:20]}...")
            print("  Quantum-level cryptography can be used for token signing")
        except Exception as e:
            print(f"✗ Authentication with 2FA code failed: {e}")
            return
    else:
        print("✗ No pending 2FA code found")
        return
    
    # Verify the token
    print("\n--- Step 4: Verify Token ---")
    try:
        user_data = auth.verify_token(token)
        print(f"✓ Token verified for user: {user_data['username']}")
        print(f"  Email: {user_data['email']}")
        print(f"  Passwordless: {user_data.get('passwordless', False)}")
    except Exception as e:
        print(f"✗ Token verification failed: {e}")
        return
    
    # Demonstrate security features
    print("\n--- Security Features ---")
    print("✓ No password storage or recovery needed")
    print("✓ 2FA codes expire automatically (default: 5 minutes)")
    print("✓ Rate limiting prevents abuse")
    print("✓ Failed attempt tracking prevents brute force")
    print("✓ Data tied to username, useless to other corporations without email mapping")
    print("✓ Supports quantum-level cryptography for token signing")
    
    # Try invalid 2FA code
    print("\n--- Step 5: Test Invalid 2FA Code ---")
    try:
        # Request new code first
        auth.request_2fa_code("jane_doe")
        # Try with wrong code
        auth.authenticate("jane_doe", code_2fa="999999")
    except Exception as e:
        print(f"✓ Invalid 2FA code correctly rejected: {e}")

if __name__ == "__main__":
    main()