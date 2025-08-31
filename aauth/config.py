"""
Configuration management for AAuth.
"""

from typing import Dict, Any, Optional
import os


class AAuthConfig:
    """Configuration class for AAuth settings."""
    
    # Default configuration values
    DEFAULT_CONFIG = {
        'secret_key': None,
        'token_expiry': 3600,  # 1 hour
        'refresh_token_expiry': 86400 * 7,  # 7 days
        'hash_rounds': 12,
        'rate_limit': 100,  # requests per minute
        'mfa_enabled': False,
        'session_timeout': 1800,  # 30 minutes
        'password_min_length': 8,
        'password_require_uppercase': True,
        'password_require_lowercase': True,
        'password_require_digits': True,
        'password_require_special': True,
        'max_login_attempts': 5,
        'lockout_duration': 900,  # 15 minutes
        'email_verification_required': False,
        'jwt_algorithm': 'HS256',
        'cookie_secure': True,
        'cookie_httponly': True,
        'csrf_protection': True,
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize configuration with optional custom values."""
        self.config = self.DEFAULT_CONFIG.copy()
        
        # Load from environment variables
        self._load_from_env()
        
        # Override with provided config
        if config:
            self.config.update(config)
        
        # Validate required settings
        self._validate_config()
    
    def _load_from_env(self):
        """Load configuration from environment variables."""
        env_mappings = {
            'AAUTH_SECRET_KEY': 'secret_key',
            'AAUTH_TOKEN_EXPIRY': ('token_expiry', int),
            'AAUTH_HASH_ROUNDS': ('hash_rounds', int),
            'AAUTH_RATE_LIMIT': ('rate_limit', int),
            'AAUTH_MFA_ENABLED': ('mfa_enabled', self._str_to_bool),
            'AAUTH_SESSION_TIMEOUT': ('session_timeout', int),
            'AAUTH_PASSWORD_MIN_LENGTH': ('password_min_length', int),
            'AAUTH_MAX_LOGIN_ATTEMPTS': ('max_login_attempts', int),
            'AAUTH_LOCKOUT_DURATION': ('lockout_duration', int),
        }
        
        for env_var, config_item in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                if isinstance(config_item, tuple):
                    key, converter = config_item
                    try:
                        self.config[key] = converter(value)
                    except (ValueError, TypeError):
                        pass  # Keep default value
                else:
                    self.config[config_item] = value
    
    def _str_to_bool(self, value: str) -> bool:
        """Convert string to boolean."""
        return value.lower() in ('true', '1', 'yes', 'on')
    
    def _validate_config(self):
        """Validate configuration values."""
        if not self.config['secret_key']:
            # Generate a default secret key for development
            import secrets
            self.config['secret_key'] = secrets.token_urlsafe(32)
        
        if self.config['token_expiry'] <= 0:
            raise ValueError("token_expiry must be greater than 0")
        
        if self.config['hash_rounds'] < 4:
            raise ValueError("hash_rounds must be at least 4")
        
        if self.config['password_min_length'] < 4:
            raise ValueError("password_min_length must be at least 4")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any):
        """Set configuration value."""
        self.config[key] = value
    
    def update(self, config: Dict[str, Any]):
        """Update configuration with new values."""
        self.config.update(config)
        self._validate_config()