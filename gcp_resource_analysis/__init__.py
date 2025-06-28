#!/usr/bin/env python3
"""
GCP Resource Analysis Package

A comprehensive Python package for analyzing Google Cloud Platform resources
using Cloud Asset Inventory. Provides security, compliance, optimization, and
governance analysis equivalent to Azure Resource Graph functionality.

Main Components:
- GCPResourceAnalysisClient: Main client for all analysis operations
- Storage Analysis: Cloud Storage, Cloud SQL, BigQuery analysis
- Compute Analysis: Compute Engine, GKE cluster analysis
- Network Analysis: VPC, Load Balancer, Firewall analysis
- IAM Analysis: Identity and Access Management analysis
- Container Analysis: GKE, Cloud Run, App Engine analysis

Example Usage:
    from gcp_resource_analysis import GCPResourceAnalysisClient

    client = GCPResourceAnalysisClient(
        project_ids=["project-1", "project-2"],
        credentials_path="path/to/service-account.json"
    )

    # Run comprehensive analysis
    results = client.query_comprehensive_analysis()

    # Individual analysis components
    storage_results = client.query_storage_analysis()
    compute_results = client.query_compute_analysis()
    network_results = client.query_network_analysis()
"""

__version__ = "1.0.5"
__author__ = "Kenneth Stott"
__email__ = "ken@promptql.io"
__description__ = "GCP Resource Analysis Client - Security, Compliance & Optimization"

# Main client import
from .client import GCPResourceAnalysisClient

# Analysis module imports
# from .storage_analysis import StorageAnalysisQueries
# from .compute_analysis import ComputeAnalysisQueries
# from .network_analysis import NetworkAnalysisQueries
# from .iam_analysis import IAMAnalysisQueries
# from .container_workload_analysis import ContainerWorkloadAnalysisQueries

# Model imports for external use
from .models import (
    # Storage Models
    GCPStorageResource,
    GCPStorageAccessControlResult,
    GCPStorageBackupResult,
    GCPStorageOptimizationResult,
    GCPStorageComplianceSummary,

    # Compute Models
    GCPComputeResource,
    GCPComputeSecurityResult,
    GCPComputeOptimizationResult,
    GCPComputeComplianceSummary,

    # Network Models
    GCPNetworkResource,
    GCPNetworkSecurityResult,
    GCPNetworkComplianceSummary,

    # IAM Models
    GCPIAMResource,
    GCPIAMSecurityResult,
    GCPIAMComplianceSummary,

    # Container Models
    GCPContainerResource,
    GCPContainerSecurityResult,
    GCPContainerComplianceSummary,

    # General Models
    RateLimitTracker,
    GCPConfig
)

# Utility imports
from .utils import (
    setup_logging,
    export_to_csv,
    export_to_json,
    create_compliance_report,
    validate_project_ids
)

# Version and package info
__all__ = [
    # Main client
    "GCPResourceAnalysisClient",

    # Analysis query classes
    # "StorageAnalysisQueries",
    # "ComputeAnalysisQueries",
    # "NetworkAnalysisQueries",
    # "IAMAnalysisQueries",
    # "ContainerWorkloadAnalysisQueries",

    # Storage models
    "GCPStorageResource",
    "GCPStorageAccessControlResult",
    "GCPStorageBackupResult",
    "GCPStorageOptimizationResult",
    "GCPStorageComplianceSummary",

    # Compute models
    "GCPComputeResource",
    "GCPComputeSecurityResult",
    "GCPComputeOptimizationResult",
    "GCPComputeComplianceSummary",

    # Network models
    "GCPNetworkResource",
    "GCPNetworkSecurityResult",
    "GCPNetworkComplianceSummary",

    # IAM models
    "GCPIAMResource",
    "GCPIAMSecurityResult",
    "GCPIAMComplianceSummary",

    # Container models
    "GCPContainerResource",
    "GCPContainerSecurityResult",
    "GCPContainerComplianceSummary",

    # Utility models
    "RateLimitTracker",
    "GCPConfig",

    # Utility functions
    "setup_logging",
    "export_to_csv",
    "export_to_json",
    "create_compliance_report",
    "validate_project_ids",

    # Package metadata
    "__version__",
    "__author__",
    "__email__",
    "__description__"
]

# Package-level configuration
import logging

# Set up default logging
logging.getLogger(__name__).addHandler(logging.NullHandler())


# Package initialization message
def _show_package_info():
    """Display package information on import"""
    import sys
    if hasattr(sys, 'ps1'):  # Interactive mode
        print(f"""
GCP Resource Analysis Package v{__version__}
🔍 Comprehensive GCP resource analysis and compliance checking
📚 Documentation: https://github.com/your-org/gcp-resource-analysis
        """)


# Show info only in interactive mode
try:
    _show_package_info()
except:
    pass  # Silently fail if issues with display
