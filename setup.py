#!/usr/bin/env python3
"""
Setup configuration for GCP Resource Analysis Package

This package provides comprehensive analysis of Google Cloud Platform resources
using Cloud Asset Inventory, offering security, compliance, optimization, and
governance insights equivalent to Azure Resource Graph functionality.
"""

from setuptools import setup, find_packages
import os


# Read version from VERSION file
def get_version():
    version_file = os.path.join(os.path.dirname(__file__), 'VERSION')
    if os.path.exists(version_file):
        with open(version_file, 'r') as f:
            return f.read().strip()
    return "1.0.0"


# Read long description from README
def get_long_description():
    readme_file = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_file):
        with open(readme_file, 'r', encoding='utf-8') as f:
            return f.read()
    return ""


# Read requirements from requirements.txt
def get_requirements():
    requirements_file = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(requirements_file):
        with open(requirements_file, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return []


# Read development requirements
def get_dev_requirements():
    dev_requirements_file = os.path.join(os.path.dirname(__file__), 'requirements-dev.txt')
    if os.path.exists(dev_requirements_file):
        with open(dev_requirements_file, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return []


setup(
    name="gcp-resource-analysis",
    version=get_version(),
    author="Your Name",
    author_email="your.email@company.com",
    description="GCP Resource Analysis Client - Security, Compliance & Optimization",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/gcp-resource-analysis",
    project_urls={
        "Bug Tracker": "https://github.com/your-org/gcp-resource-analysis/issues",
        "Documentation": "https://github.com/your-org/gcp-resource-analysis/docs",
        "Source Code": "https://github.com/your-org/gcp-resource-analysis",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Systems Administration",
        "Topic :: System :: Monitoring",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=get_requirements(),
    extras_require={
        "dev": get_dev_requirements(),
        "testing": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-mock>=3.10.0",
            "pytest-asyncio>=0.21.0",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.2.0",
            "myst-parser>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "gcp-resource-analysis=gcp_resource_analysis.cli:main",
            "gcp-analysis=gcp_resource_analysis.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "gcp_resource_analysis": [
            "templates/*.json",
            "templates/*.yaml",
            "queries/*.sql",
        ],
    },
    zip_safe=False,
    keywords=[
        "gcp",
        "google-cloud",
        "resource-analysis",
        "security",
        "compliance",
        "optimization",
        "cloud-asset-inventory",
        "governance",
        "cost-optimization",
        "security-analysis",
    ],
    # Additional metadata
    platforms=["any"],
    license="MIT",
    maintainer="Your Name",
    maintainer_email="your.email@company.com",

    # Testing configuration
    test_suite="tests",
    tests_require=[
        "pytest>=7.0.0",
        "pytest-cov>=4.0.0",
        "pytest-mock>=3.10.0",
    ],

    # Documentation
    command_options={
        'build_sphinx': {
            'project': ('setup.py', 'gcp-resource-analysis'),
            'version': ('setup.py', get_version()),
            'source_dir': ('setup.py', 'docs'),
            'build_dir': ('setup.py', 'docs/_build'),
        }
    },
)
