# Installation Guide

## Requirements

- Python 3.7+
- pip

## Installation

### From Source

1. Clone the repository:
```bash
git clone https://github.com/DRKV8R/little-person-massive.git
cd little-person-massive
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Install the package:
```bash
pip install -e .
```

### From PyPI (when published)

```bash
pip install aauth
```

## Dependencies

AAuth requires the following packages:

- **bcrypt** (>=4.0.0) - For secure password hashing
- **PyJWT** (>=2.4.0) - For JWT token handling
- **cryptography** (>=3.4.8) - For cryptographic operations
- **email-validator** (>=1.1.0) - For email validation
- **pyotp** (>=2.6.0) - For TOTP/MFA support

## Verification

After installation, verify AAuth is working:

```python
from aauth import AAuth, AuthMethod

# Should not raise any errors
auth = AAuth(method=AuthMethod.JWT)
print("AAuth installed successfully!")
```

## Development Installation

For development, install with dev dependencies:

```bash
pip install -e ".[dev]"
```

This includes:
- pytest (testing)
- pytest-cov (coverage)
- black (code formatting)
- flake8 (linting)
- mypy (type checking)