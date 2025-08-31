from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="aauth",
    version="0.1.0",
    author="DRKV8R",
    author_email="contact@example.com",
    description="A lightweight, flexible authentication system as an alternative to OAuth",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/DRKV8R/little-person-massive",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.7",
    install_requires=[
        "bcrypt>=4.0.0",
        "PyJWT>=2.4.0",
        "cryptography>=3.4.8",
        "email-validator>=1.1.0",
        "pyotp>=2.6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.812",
        ],
    },
)