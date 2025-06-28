#!/usr/bin/env python3
"""
GCP Resource Analysis Models

This module exports all Pydantic models used for GCP resource analysis results.
Models are organized by analysis domain (storage, compute, container, network)
for better organization and maintainability.

Models Available:
- Storage Analysis Models
- Compute Governance Models
- Container Analysis Models
- Network Analysis Models (NEW)
- Comprehensive Analysis Models
- Utility Models
"""

from .iam_analysis import (
    GCPCustomRoleResult,
    GCPWorkloadIdentityResult,
    GCPIAMPolicyBindingResult,
    GCPServiceAccountSecurityResult,
    GCPServiceAccountKeyResult,
    GCPEnhancedIAMComplianceSummary,
    GCPIAMComplianceSummary
)
# Compute Governance Models
from .compute_governance import (
    GCPVMSecurityResult,
    GCPVMOptimizationResult,
    GCPVMConfigurationResult,
    GCPVMPatchComplianceResult,
    GCPVMGovernanceSummary,
    GCPComputeComplianceSummary
)
# Container Analysis Models
from .container_analysis import (
    GCPGKEClusterSecurityResult,
    GCPGKENodePoolResult,
    GCPArtifactRegistrySecurityResult,
    GCPCloudRunSecurityResult,
    GCPAppEngineSecurityResult,
    GCPCloudFunctionsSecurityResult,
    GCPContainerWorkloadsComplianceSummary
)
# Network Analysis Models (NEW)
from .network_analysis import (
    GCPNetworkResource,
    GCPFirewallRule,
    GCPSSLCertificateResult,
    GCPNetworkTopologyResult,
    GCPNetworkOptimizationResult,
    GCPNetworkComplianceSummary
)
# Storage Analysis Models
from .storage_analysis import (
    GCPStorageResource,
    GCPStorageAccessControlResult,
    GCPStorageBackupResult,
    GCPStorageOptimizationResult,
    GCPStorageComplianceSummary,
    GCPKMSSecurityResult,
    GCPEnhancedStorageComplianceSummary,
    GCPComprehensiveAnalysisResult,
    RateLimitTracker,
    GCPContainerResource,
    GCPContainerSecurityResult,
    GCPContainerComplianceSummary,
    GCPConfig,
    GCPComputeResource,
    GCPComputeSecurityResult,
    GCPComputeOptimizationResult,
    GCPNetworkSecurityResult,
    GCPIAMResource,
    GCPIAMSecurityResult
)

# Export all models for easy importing
__all__ = [
    # IAM Analysis
    'GCPWorkloadIdentityResult',
    'GCPIAMPolicyBindingResult',
    'GCPServiceAccountSecurityResult',
    'GCPServiceAccountKeyResult',
    'GCPEnhancedIAMComplianceSummary',
    'GCPIAMComplianceSummary',
    'GCPCustomRoleResult',

    # Storage Analysis Models
    'GCPContainerResource',
    'GCPIAMResource',
    'GCPComputeResource',
    'GCPComputeOptimizationResult',
    'GCPComputeSecurityResult',
    'GCPNetworkSecurityResult',
    'GCPIAMSecurityResult',
    'GCPContainerSecurityResult',
    'GCPContainerComplianceSummary',
    'GCPConfig',
    'GCPStorageResource',
    'GCPStorageAccessControlResult',
    'GCPStorageBackupResult',
    'GCPStorageOptimizationResult',
    'GCPStorageComplianceSummary',
    'GCPKMSSecurityResult',
    'GCPEnhancedStorageComplianceSummary',
    'GCPComprehensiveAnalysisResult',
    'RateLimitTracker',

    # Compute Governance Models
    'GCPVMSecurityResult',
    'GCPVMOptimizationResult',
    'GCPVMConfigurationResult',
    'GCPVMPatchComplianceResult',
    'GCPVMGovernanceSummary',
    'GCPComputeComplianceSummary',

    # Container Analysis Models
    'GCPGKEClusterSecurityResult',
    'GCPGKENodePoolResult',
    'GCPArtifactRegistrySecurityResult',
    'GCPCloudRunSecurityResult',
    'GCPAppEngineSecurityResult',
    'GCPCloudFunctionsSecurityResult',
    'GCPContainerWorkloadsComplianceSummary',

    # Network Analysis Models (NEW)
    'GCPNetworkResource',
    'GCPFirewallRule',
    'GCPSSLCertificateResult',
    'GCPNetworkTopologyResult',
    'GCPNetworkOptimizationResult',
    'GCPNetworkComplianceSummary',
    'GCPNetworkSecurityResult'
]
