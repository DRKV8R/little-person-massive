"""
Core AAuth authentication system.
"""

import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Union, List
import jwt
import bcrypt
from email_validator import validate_email, EmailNotValidError

from .auth_methods import AuthMethod, TokenType, MFAMethod
from .config import AAuthConfig
from .exceptions import (
    AuthenticationError, ValidationError, UserNotFoundError,
    InvalidCredentialsError, AccountLockedError, PasswordValidationError,
    EmailValidationError, TokenError, RateLimitError
)


class AAuth:
    """Main AAuth authentication system."""
    
    def __init__(self, method: AuthMethod = AuthMethod.JWT, config: Optional[Dict[str, Any]] = None):
        """Initialize AAuth with specified authentication method and configuration."""
        self.method = method
        self.config = AAuthConfig(config)
        
        # In-memory storage for demo purposes
        # In production, this would be replaced with a proper database
        self.users: Dict[str, Dict[str, Any]] = {}
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.api_keys: Dict[str, Dict[str, Any]] = {}
        self.rate_limits: Dict[str, List[float]] = {}
        self.login_attempts: Dict[str, Dict[str, Any]] = {}
    
    def _validate_password(self, password: str) -> bool:
        """Validate password against configured requirements."""
        if len(password) < self.config.get('password_min_length', 8):
            raise PasswordValidationError("Password too short")
        
        if self.config.get('password_require_uppercase', True):
            if not any(c.isupper() for c in password):
                raise PasswordValidationError("Password must contain uppercase letter")
        
        if self.config.get('password_require_lowercase', True):
            if not any(c.islower() for c in password):
                raise PasswordValidationError("Password must contain lowercase letter")
        
        if self.config.get('password_require_digits', True):
            if not any(c.isdigit() for c in password):
                raise PasswordValidationError("Password must contain digit")
        
        if self.config.get('password_require_special', True):
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if not any(c in special_chars for c in password):
                raise PasswordValidationError("Password must contain special character")
        
        return True
    
    def _validate_email(self, email: str) -> bool:
        """Validate email format."""
        try:
            validate_email(email, check_deliverability=False)
            return True
        except EmailNotValidError:
            raise EmailValidationError("Invalid email format")
    
    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt."""
        rounds = self.config.get('hash_rounds', 12)
        salt = bcrypt.gensalt(rounds=rounds)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def _verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash."""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def _check_rate_limit(self, identifier: str) -> bool:
        """Check if rate limit is exceeded for identifier."""
        now = time.time()
        limit = self.config.get('rate_limit', 100)
        window = 60  # 1 minute window
        
        if identifier not in self.rate_limits:
            self.rate_limits[identifier] = []
        
        # Remove old entries
        self.rate_limits[identifier] = [
            ts for ts in self.rate_limits[identifier] 
            if now - ts < window
        ]
        
        if len(self.rate_limits[identifier]) >= limit:
            raise RateLimitError("Rate limit exceeded")
        
        self.rate_limits[identifier].append(now)
        return True
    
    def _check_login_attempts(self, username: str) -> bool:
        """Check if account is locked due to failed login attempts."""
        if username not in self.login_attempts:
            return True
        
        attempt_data = self.login_attempts[username]
        max_attempts = self.config.get('max_login_attempts', 5)
        lockout_duration = self.config.get('lockout_duration', 900)
        
        if attempt_data['count'] >= max_attempts:
            if time.time() - attempt_data['last_attempt'] < lockout_duration:
                raise AccountLockedError("Account locked due to too many failed attempts")
            else:
                # Reset attempts after lockout period
                self.login_attempts[username] = {'count': 0, 'last_attempt': 0}
        
        return True
    
    def _record_login_attempt(self, username: str, success: bool):
        """Record login attempt."""
        if username not in self.login_attempts:
            self.login_attempts[username] = {'count': 0, 'last_attempt': 0}
        
        if success:
            # Reset on successful login
            self.login_attempts[username] = {'count': 0, 'last_attempt': 0}
        else:
            # Increment failed attempts
            self.login_attempts[username]['count'] += 1
            self.login_attempts[username]['last_attempt'] = time.time()
    
    def _create_jwt_token(self, user_data: Dict[str, Any], token_type: TokenType = TokenType.ACCESS) -> str:
        """Create JWT token."""
        now = datetime.utcnow()
        
        if token_type == TokenType.ACCESS:
            expiry = self.config.get('token_expiry', 3600)
        elif token_type == TokenType.REFRESH:
            expiry = self.config.get('refresh_token_expiry', 86400 * 7)
        else:
            expiry = 3600  # Default 1 hour
        
        payload = {
            'user_id': user_data['id'],
            'username': user_data['username'],
            'email': user_data['email'],
            'type': token_type.value,
            'iat': now,
            'exp': now + timedelta(seconds=expiry),
            'jti': secrets.token_urlsafe(16)  # Unique token ID
        }
        
        algorithm = self.config.get('jwt_algorithm', 'HS256')
        secret_key = self.config.get('secret_key')
        
        return jwt.encode(payload, secret_key, algorithm=algorithm)
    
    def _verify_jwt_token(self, token: str) -> Dict[str, Any]:
        """Verify JWT token and return payload."""
        try:
            algorithm = self.config.get('jwt_algorithm', 'HS256')
            secret_key = self.config.get('secret_key')
            
            payload = jwt.decode(token, secret_key, algorithms=[algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            raise TokenError("Token has expired")
        except jwt.InvalidTokenError:
            raise TokenError("Invalid token")
    
    def register(self, username: str, password: str, email: str, **kwargs) -> Dict[str, Any]:
        """Register a new user."""
        # Validate inputs
        self._validate_password(password)
        self._validate_email(email)
        
        # Check if user already exists
        if username in self.users:
            raise ValidationError("Username already exists")
        
        # Check if email already exists
        for user_data in self.users.values():
            if user_data.get('email') == email:
                raise ValidationError("Email already exists")
        
        # Create user
        user_id = secrets.token_urlsafe(16)
        user_data = {
            'id': user_id,
            'username': username,
            'email': email,
            'password_hash': self._hash_password(password),
            'created_at': datetime.utcnow().isoformat(),
            'is_active': True,
            'is_verified': not self.config.get('email_verification_required', False),
            'mfa_enabled': False,
            'last_login': None,
            **kwargs
        }
        
        self.users[username] = user_data
        
        # Return safe user data (without password hash)
        safe_data = {k: v for k, v in user_data.items() if k != 'password_hash'}
        return safe_data
    
    def authenticate(self, username: str, password: str, **kwargs) -> Union[str, Dict[str, Any]]:
        """Authenticate user and return appropriate token/session."""
        # Check rate limiting
        self._check_rate_limit(f"auth:{username}")
        
        # Check login attempts
        self._check_login_attempts(username)
        
        # Find user
        if username not in self.users:
            self._record_login_attempt(username, False)
            raise UserNotFoundError("User not found")
        
        user_data = self.users[username]
        
        # Check if user is active
        if not user_data.get('is_active', True):
            self._record_login_attempt(username, False)
            raise AuthenticationError("Account is deactivated")
        
        # Verify password
        if not self._verify_password(password, user_data['password_hash']):
            self._record_login_attempt(username, False)
            raise InvalidCredentialsError("Invalid credentials")
        
        # Record successful login
        self._record_login_attempt(username, True)
        user_data['last_login'] = datetime.utcnow().isoformat()
        
        # Return based on authentication method
        if self.method == AuthMethod.JWT:
            return self._create_jwt_token(user_data)
        elif self.method == AuthMethod.SESSION:
            session_id = secrets.token_urlsafe(32)
            self.sessions[session_id] = {
                'user_id': user_data['id'],
                'username': username,
                'created_at': time.time(),
                'expires_at': time.time() + self.config.get('session_timeout', 1800)
            }
            return session_id
        elif self.method == AuthMethod.API_KEY:
            api_key = secrets.token_urlsafe(32)
            self.api_keys[api_key] = {
                'user_id': user_data['id'],
                'username': username,
                'created_at': time.time()
            }
            return api_key
        else:
            # Return user data for basic auth
            safe_data = {k: v for k, v in user_data.items() if k != 'password_hash'}
            return safe_data
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify token and return user data."""
        if self.method == AuthMethod.JWT:
            payload = self._verify_jwt_token(token)
            username = payload.get('username')
            if username in self.users:
                user_data = self.users[username]
                safe_data = {k: v for k, v in user_data.items() if k != 'password_hash'}
                return safe_data
            else:
                raise UserNotFoundError("User not found")
        
        elif self.method == AuthMethod.SESSION:
            if token not in self.sessions:
                raise TokenError("Invalid session")
            
            session = self.sessions[token]
            if time.time() > session['expires_at']:
                del self.sessions[token]
                raise TokenError("Session expired")
            
            username = session['username']
            if username in self.users:
                user_data = self.users[username]
                safe_data = {k: v for k, v in user_data.items() if k != 'password_hash'}
                return safe_data
            else:
                raise UserNotFoundError("User not found")
        
        elif self.method == AuthMethod.API_KEY:
            if token not in self.api_keys:
                raise TokenError("Invalid API key")
            
            api_key_data = self.api_keys[token]
            username = api_key_data['username']
            if username in self.users:
                user_data = self.users[username]
                safe_data = {k: v for k, v in user_data.items() if k != 'password_hash'}
                return safe_data
            else:
                raise UserNotFoundError("User not found")
        
        else:
            raise AuthenticationError("Token verification not supported for this auth method")
    
    def logout(self, token: str) -> bool:
        """Logout user by invalidating token/session."""
        if self.method == AuthMethod.SESSION:
            if token in self.sessions:
                del self.sessions[token]
                return True
        elif self.method == AuthMethod.API_KEY:
            if token in self.api_keys:
                del self.api_keys[token]
                return True
        elif self.method == AuthMethod.JWT:
            # For JWT, you would typically maintain a blacklist
            # For simplicity, we'll just return True
            return True
        
        return False
    
    def refresh_token(self, refresh_token: str) -> str:
        """Refresh access token using refresh token."""
        if self.method != AuthMethod.JWT:
            raise AuthenticationError("Token refresh only supported for JWT method")
        
        payload = self._verify_jwt_token(refresh_token)
        
        if payload.get('type') != TokenType.REFRESH.value:
            raise TokenError("Invalid token type for refresh")
        
        username = payload.get('username')
        if username not in self.users:
            raise UserNotFoundError("User not found")
        
        user_data = self.users[username]
        return self._create_jwt_token(user_data, TokenType.ACCESS)
    
    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """Change user password."""
        if username not in self.users:
            raise UserNotFoundError("User not found")
        
        user_data = self.users[username]
        
        # Verify old password
        if not self._verify_password(old_password, user_data['password_hash']):
            raise InvalidCredentialsError("Invalid current password")
        
        # Validate new password
        self._validate_password(new_password)
        
        # Update password
        user_data['password_hash'] = self._hash_password(new_password)
        return True
    
    def get_user(self, username: str) -> Dict[str, Any]:
        """Get user data (without password hash)."""
        if username not in self.users:
            raise UserNotFoundError("User not found")
        
        user_data = self.users[username]
        safe_data = {k: v for k, v in user_data.items() if k != 'password_hash'}
        return safe_data