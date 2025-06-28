#!/usr/bin/env python3
"""
Setup script for GCP Resource Analysis Client
"""

import os
import re
from setuptools import setup, find_packages


# Read version from __init__.py or version file
def get_version():
    """Extract version from package"""
    try:
        with open(os.path.join("gcp_resource_analysis", "__init__.py"), "r") as f:
            content = f.read()
            version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", content, re.M)
            if version_match:
                return version_match.group(1)
    except FileNotFoundError:
        pass

    # Try VERSION file
    try:
        with open("VERSION", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        pass

    return "1.0.0"  # Default version


# Read long description from README
def get_long_description():
    """Read long description from README file"""
    try:
        with open("README.md", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "GCP Resource Analysis Client for querying GCP resources and analyzing security, compliance, and optimization."


# Read requirements from requirements.txt
def get_requirements():
    """Read requirements from requirements.txt"""
    requirements = []
    try:
        with open("requirements.txt", "r") as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith("#"):
                    # Skip optional dependencies for core install
                    if line.startswith("google-auth") or line.startswith("google-cloud-cli"):
                        continue  # Skip optional dependencies for core install
                    if any(dev_dep in line for dev_dep in ["pytest", "black", "flake8", "mypy", "sphinx"]):
                        continue  # Skip development dependencies
                    requirements.append(line.split()[0])  # Take first part (removes comments)
        return requirements
    except FileNotFoundError:
        return ["requests>=2.28.0"]


# Core requirements (minimal for basic functionality)
CORE_REQUIREMENTS = [
    "requests>=2.28.0,<3.0.0",
    "google-cloud-asset>=3.20.0,<4.0.0",
    "google-cloud-resource-manager>=1.10.0,<2.0.0",
    "python-dotenv>=0.19.0,<2.0.0",
    "pydantic>=2.11.7",
    "pandas>=1.5.0,<3.0.0",
    "tabulate>=0.9.0,<1.0.0"
]

# Optional requirements for enhanced functionality
EXTRAS_REQUIRE = {
    "auth": [
        "google-auth>=2.17.0,<3.0.0",
        "google-auth-oauthlib>=1.0.0,<2.0.0",
        "google-auth-httplib2>=0.1.0,<1.0.0",
    ],
    "dev": [
        "pytest>=7.0.0,<8.0.0",
        "pytest-cov>=4.0.0,<5.0.0",
        "pytest-mock>=3.10.0,<4.0.0",
        "pytest-asyncio>=0.21.0,<1.0.0",
        "black>=22.0.0,<24.0.0",
        "flake8>=5.0.0,<7.0.0",
        "mypy>=1.0.0,<2.0.0",
    ],
    "docs": [
        "sphinx>=5.0.0,<7.0.0",
        "sphinx-rtd-theme>=1.2.0,<2.0.0",
        "myst-parser>=1.0.0,<2.0.0",
    ],
    "testing": [
        "pytest>=7.0.0,<8.0.0",
        "pytest-cov>=4.0.0,<5.0.0",
        "pytest-mock>=3.10.0,<4.0.0",
        "pytest-asyncio>=0.21.0,<1.0.0",
    ],
}

# All optional dependencies
EXTRAS_REQUIRE["all"] = [
    dep for deps in EXTRAS_REQUIRE.values() for dep in deps
]

setup(
    # Package metadata
    name="gcp-resource-analysis",
    version=get_version(),
    description="Python client for GCP Resource Analysis with security, compliance & optimization insights",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",

    # Author information
    author="GCP Resource Analysis",
    author_email="ken@promptql.io",  # Update with your email
    url="https://github.com/hasura/gcp-resource-analysis",  # Update with your repo

    # License and classifiers
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration",
        "Topic :: System :: Monitoring",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
    ],

    # Package discovery
    packages=find_packages(exclude=["tests", "tests.*", "docs", "examples"]),

    # Python version requirement
    python_requires=">=3.8",

    # Dependencies
    install_requires=CORE_REQUIREMENTS,
    extras_require=EXTRAS_REQUIRE,

    # Package data
    include_package_data=True,
    package_data={
        "gcp_resource_analysis": [
            "templates/*.json",
            "templates/*.yaml",
            "queries/*.sql",
        ],
    },
    zip_safe=False,

    # Console scripts
    entry_points={
        "console_scripts": [
            "gcp-resource-analysis=gcp_resource_analysis.cli:main",
            "gcp-analysis=gcp_resource_analysis.cli:main",
        ],
    },

    # Keywords for PyPI search
    keywords=[
        "gcp",
        "google-cloud",
        "resource-analysis",
        "cloud-asset-inventory",
        "security",
        "compliance",
        "optimization",
        "governance",
        "api-client",
        "cost-optimization"
    ],

    # Project URLs
    project_urls={
        "Documentation": "https://github.com/hasura/gcp-resource-analysis/blob/main/README.md",
        "Source": "https://github.com/hasura/gcp-resource-analysis",
        "Tracker": "https://github.com/hasura/gcp-resource-analysis/issues",
        "Bug Tracker": "https://github.com/hasura/gcp-resource-analysis/issues",
    },

    # Additional metadata
    platforms=["any"],
    maintainer="GCP Resource Analysis",
    maintainer_email="ken@promptql.io",  # Update with your email
)
