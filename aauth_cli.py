#!/usr/bin/env python3
"""
AAuth CLI tool for testing and demonstration.
"""

import argparse
import sys
from aauth import AAuth, AuthMethod


def create_auth(method_name):
    """Create AAuth instance with specified method."""
    try:
        method = AuthMethod(method_name.lower())
        return AAuth(method=method)
    except ValueError:
        print(f"Invalid auth method: {method_name}")
        print(f"Available methods: {[m.value for m in AuthMethod]}")
        sys.exit(1)


def cmd_register(args):
    """Handle register command."""
    auth = create_auth(args.method)
    
    try:
        if args.method.lower() == 'passwordless_2fa':
            # Passwordless registration - no password required
            user = auth.register(args.username, args.email)
            print(f"✓ Passwordless user registered successfully:")
            print(f"  Username: {user['username']}")
            print(f"  Email: {user['email']}")
            print(f"  User ID: {user['id']}")
            print(f"  Passwordless: {user.get('passwordless', False)}")
        else:
            # Traditional registration with password
            user = auth.register(args.username, args.email, args.password)
            print(f"✓ User registered successfully:")
            print(f"  Username: {user['username']}")
            print(f"  Email: {user['email']}")
            print(f"  User ID: {user['id']}")
    except Exception as e:
        print(f"✗ Registration failed: {e}")
        sys.exit(1)


def cmd_login(args):
    """Handle login command."""
    auth = create_auth(args.method)
    
    try:
        if args.method.lower() == 'passwordless_2fa':
            if hasattr(args, 'code_2fa') and getattr(args, 'code_2fa'):
                # Complete authentication with 2FA code
                token = auth.authenticate(args.username, code_2fa=getattr(args, 'code_2fa'))
                print(f"✓ Passwordless authentication successful:")
                print(f"  JWT Token: {token}")
            else:
                # Request 2FA code
                result = auth.authenticate(args.username)
                print(f"✓ 2FA code request:")
                print(f"  {result['message']}")
                print(f"  Use --code-2fa option to complete authentication")
        else:
            # Traditional password authentication
            token = auth.authenticate(args.username, args.password)
            print(f"✓ Authentication successful:")
            if args.method.lower() == 'jwt':
                print(f"  JWT Token: {token}")
            elif args.method.lower() == 'session':
                print(f"  Session ID: {token}")
            elif args.method.lower() == 'api_key':
                print(f"  API Key: {token}")
            else:
                print(f"  User Data: {token}")
    except Exception as e:
        print(f"✗ Authentication failed: {e}")
        sys.exit(1)


def cmd_verify(args):
    """Handle verify command."""
    auth = create_auth(args.method)
    
    try:
        user_data = auth.verify_token(args.token)
        print(f"✓ Token verification successful:")
        print(f"  Username: {user_data['username']}")
        print(f"  Email: {user_data['email']}")
        print(f"  Last Login: {user_data.get('last_login', 'Never')}")
    except Exception as e:
        print(f"✗ Token verification failed: {e}")
        sys.exit(1)


def cmd_demo(args):
    """Run full demo."""
    print("=== AAuth CLI Demo ===\n")
    
    auth = create_auth(args.method)
    print(f"Using authentication method: {args.method}")
    
    # Register demo user
    username = "demo_user"
    password = "DemoPass123!"
    email = "demo@example.com"
    
    try:
        print(f"\n1. Registering user '{username}'...")
        if args.method.lower() == 'passwordless_2fa':
            user = auth.register(username, email)
            print(f"   ✓ Passwordless user registered: {user['username']}")
        else:
            user = auth.register(username, email, password)
            print(f"   ✓ User registered: {user['username']}")
    except Exception as e:
        print(f"   ✗ Registration failed: {e}")
        return
    
    # Authenticate
    try:
        print(f"\n2. Authenticating user '{username}'...")
        if args.method.lower() == 'passwordless_2fa':
            # First request 2FA code
            result = auth.authenticate(username)
            print(f"   ✓ 2FA code sent: {result['message']}")
            
            # Simulate getting the code from email (in demo, access directly)
            if username in auth.pending_2fa_codes:
                demo_code = auth.pending_2fa_codes[username]["code"]
                print(f"   📧 Demo code from email: {demo_code}")
                
                # Complete authentication with 2FA code
                token = auth.authenticate(username, code_2fa=demo_code)
                print(f"   ✓ Passwordless authentication successful")
                print(f"   Token: {token[:50]}...")
            else:
                print(f"   ✗ No 2FA code found")
                return
        else:
            token = auth.authenticate(username, password)
            print(f"   ✓ Authentication successful")
            if args.method.lower() == 'jwt':
                print(f"   Token: {token[:50]}...")
            else:
                print(f"   Token: {str(token)[:50]}...")
    except Exception as e:
        print(f"   ✗ Authentication failed: {e}")
        return
    
    # Verify token
    try:
        print(f"\n3. Verifying token...")
        user_data = auth.verify_token(token)
        print(f"   ✓ Token verified for user: {user_data['username']}")
        if args.method.lower() == 'passwordless_2fa':
            print(f"   Passwordless: {user_data.get('passwordless', False)}")
    except Exception as e:
        print(f"   ✗ Token verification failed: {e}")
        return
    
    # Test invalid credentials
    try:
        print(f"\n4. Testing invalid credentials...")
        if args.method.lower() == 'passwordless_2fa':
            auth.authenticate(username, code_2fa="999999")
        else:
            auth.authenticate(username, "wrongpassword")
    except Exception as e:
        print(f"   ✓ Invalid credentials correctly rejected: {e}")
    
    print(f"\n=== Demo completed successfully ===")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="AAuth CLI Tool")
    parser.add_argument('--method', '-m', default='jwt', 
                       help='Authentication method (jwt, session, api_key, basic, passwordless_2fa)')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Register command
    register_parser = subparsers.add_parser('register', help='Register a new user')
    register_parser.add_argument('username', help='Username')
    register_parser.add_argument('email', help='Email address')
    register_parser.add_argument('password', nargs='?', help='Password (not required for passwordless_2fa)')
    
    # Login command
    login_parser = subparsers.add_parser('login', help='Authenticate user')
    login_parser.add_argument('username', help='Username')
    login_parser.add_argument('password', nargs='?', help='Password (not required for passwordless_2fa)')
    login_parser.add_argument('--code-2fa', help='2FA code for passwordless authentication')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify token')
    verify_parser.add_argument('token', help='Token to verify')
    
    # Demo command
    demo_parser = subparsers.add_parser('demo', help='Run full demo')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'register':
        cmd_register(args)
    elif args.command == 'login':
        cmd_login(args)
    elif args.command == 'verify':
        cmd_verify(args)
    elif args.command == 'demo':
        cmd_demo(args)


if __name__ == '__main__':
    main()