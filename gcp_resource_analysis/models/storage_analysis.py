#!/usr/bin/env python3
"""
Consolidated GCP Models File
All GCP resource analysis models in a single file for better organization
Provides full Azure parity across all resource types
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


# =============================================================================
# BASE STORAGE MODELS (Enhanced from original)
# =============================================================================

class GCPStorageResource(BaseModel):
    """Enhanced storage resource model with comprehensive analysis"""
    application: str = Field(..., description="Application name")
    storage_resource: str = Field(..., description="Storage resource name")
    storage_type: str = Field(..., description="Type of storage resource")
    encryption_method: str = Field(..., description="Encryption method used")
    security_findings: str = Field(..., description="Security findings and configuration issues")
    compliance_risk: str = Field(..., description="Compliance risk level assessment")
    resource_group: str = Field(..., description="GCP Project ID")
    location: str = Field(..., description="GCP region/location")
    additional_details: str = Field(..., description="Additional resource configuration details")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this storage resource has high security risk"""
        return self.compliance_risk.lower().startswith('high')


class GCPStorageAccessControlResult(BaseModel):
    """Storage access control analysis results"""
    application: str = Field(..., description="Application name")
    resource_name: str = Field(..., description="Storage resource name")
    resource_type: str = Field(..., description="Type of storage resource")
    public_access: str = Field(..., description="Public access configuration")
    network_restrictions: str = Field(..., description="Network access restrictions")
    authentication_method: str = Field(..., description="Authentication method configuration")
    security_risk: str = Field(..., description="Security risk assessment")
    access_details: str = Field(..., description="Additional access control details")
    resource_group: str = Field(..., description="GCP Project ID")
    location: str = Field(..., description="GCP region/location")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this access control has high security risk"""
        return self.security_risk.lower().startswith('high')


class GCPStorageBackupResult(BaseModel):
    """Storage backup and disaster recovery analysis results"""
    application: str = Field(..., description="Application name")
    resource_name: str = Field(..., description="Storage resource name")
    resource_type: str = Field(..., description="Type of storage resource")
    backup_configuration: str = Field(..., description="Backup configuration details")
    retention_policy: str = Field(..., description="Data retention policy")
    compliance_status: str = Field(..., description="Backup compliance status")
    disaster_recovery_risk: str = Field(..., description="Disaster recovery risk level")
    resource_group: str = Field(..., description="GCP Project ID")
    location: str = Field(..., description="GCP region/location")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this backup configuration has high DR risk"""
        return self.disaster_recovery_risk.lower().startswith('high')


class GCPStorageOptimizationResult(BaseModel):
    """Enhanced storage optimization result matching Azure detail level"""
    application: str = Field(..., description="Application name")
    resource_name: str = Field(..., description="Resource name")
    optimization_type: str = Field(..., description="Type of optimization analysis")
    current_configuration: str = Field(..., description="Current resource configuration")
    utilization_status: str = Field(..., description="Resource utilization assessment")
    cost_optimization_potential: str = Field(..., description="Cost optimization potential level")
    optimization_recommendation: str = Field(..., description="Specific optimization recommendation")
    estimated_monthly_cost: str = Field(..., description="Estimated monthly cost category")
    resource_group: str = Field(..., description="GCP Project ID")
    location: str = Field(..., description="GCP region/location")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def has_high_optimization_potential(self) -> bool:
        """Check if this resource has high optimization potential"""
        return 'high' in self.cost_optimization_potential.lower()


class GCPStorageComplianceSummary(BaseModel):
    """Original storage compliance summary by application"""
    application: str = Field(..., description="Application name")
    total_storage_resources: int = Field(..., description="Total storage resources")
    storage_bucket_count: int = Field(..., description="Number of Cloud Storage buckets")
    persistent_disk_count: int = Field(..., description="Number of persistent disks")
    cloud_sql_count: int = Field(..., description="Number of Cloud SQL instances")
    bigquery_dataset_count: int = Field(..., description="Number of BigQuery datasets")
    encrypted_resources: int = Field(..., description="Number of encrypted resources")
    secure_transport_resources: int = Field(..., description="Number of resources with secure transport")
    network_secured_resources: int = Field(..., description="Number of network-secured resources")
    resources_with_issues: int = Field(..., description="Number of resources with security issues")
    compliance_score: float = Field(..., description="Overall compliance score percentage")
    compliance_status: str = Field(..., description="Overall compliance status")


class GCPEnhancedStorageComplianceSummary(BaseModel):
    """Enhanced storage compliance summary with additional services"""
    application: str = Field(..., description="Application name")
    total_storage_resources: int = Field(..., description="Total storage resources")
    storage_bucket_count: int = Field(..., description="Number of Cloud Storage buckets")
    persistent_disk_count: int = Field(..., description="Number of persistent disks")
    cloud_sql_count: int = Field(..., description="Number of Cloud SQL instances")
    bigquery_dataset_count: int = Field(..., description="Number of BigQuery datasets")
    spanner_instance_count: int = Field(default=0, description="Number of Cloud Spanner instances")
    filestore_count: int = Field(default=0, description="Number of Cloud Filestore instances")
    memorystore_count: int = Field(default=0, description="Number of Memorystore instances")
    kms_key_count: int = Field(default=0, description="Number of Cloud KMS keys")
    encrypted_resources: int = Field(..., description="Number of encrypted resources")
    secure_transport_resources: int = Field(..., description="Number of resources with secure transport")
    network_secured_resources: int = Field(..., description="Number of network-secured resources")
    resources_with_issues: int = Field(..., description="Number of resources with security issues")
    compliance_score: float = Field(..., description="Overall compliance score percentage")
    compliance_status: str = Field(..., description="Overall compliance status")


# =============================================================================
# KMS MODELS (New - Azure Key Vault Equivalent)
# =============================================================================

class GCPKMSSecurityResult(BaseModel):
    """KMS security analysis results - equivalent to Azure Key Vault"""
    application: str = Field(..., description="Application name")
    kms_resource: str = Field(..., description="KMS resource name (key or keyring)")
    resource_type: str = Field(..., description="Type of KMS resource")
    rotation_status: str = Field(..., description="Key rotation configuration")
    access_control: str = Field(..., description="Access control configuration")
    security_findings: str = Field(..., description="Security findings and configuration")
    security_risk: str = Field(..., description="Security risk level assessment")
    kms_details: str = Field(..., description="Additional KMS configuration details")
    resource_group: str = Field(..., description="GCP Project ID")
    location: str = Field(..., description="GCP region/location")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this KMS resource has high security risk"""
        return self.security_risk.lower().startswith('high')


# =============================================================================
# COMPUTE MODELS (Future Expansion)
# =============================================================================

class GCPComputeResource(BaseModel):
    """Compute resource model for security analysis"""
    application: str = Field(..., description="Application name")
    instance_name: str = Field(..., description="Compute instance name")
    instance_type: str = Field(..., description="Instance type/machine type")
    instance_state: str = Field(..., description="Instance state (running/stopped)")
    security_configuration: str = Field(..., description="Security configuration summary")
    compliance_risk: str = Field(..., description="Compliance risk assessment")
    resource_group: str = Field(..., description="GCP Project ID")
    location: str = Field(..., description="GCP zone/region")
    additional_details: str = Field(..., description="Additional instance details")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this compute resource has high security risk"""
        return self.compliance_risk.lower().startswith('high')


class GCPComputeSecurityResult(BaseModel):
    """Compute security analysis results"""
    application: str = Field(..., description="Application name")
    instance_name: str = Field(..., description="Compute instance name")
    instance_type: str = Field(..., description="Instance type/machine type")
    os_type: str = Field(..., description="Operating system type")
    security_configuration: str = Field(..., description="Security configuration details")
    encryption_status: str = Field(..., description="Disk encryption status")
    network_security: str = Field(..., description="Network security configuration")
    security_findings: str = Field(..., description="Security findings")
    security_risk: str = Field(..., description="Security risk assessment")
    instance_details: str = Field(..., description="Additional instance details")
    resource_group: str = Field(..., description="GCP Project ID")
    location: str = Field(..., description="GCP zone/region")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this instance has high security risk"""
        return self.security_risk.lower().startswith('high')


class GCPComputeOptimizationResult(BaseModel):
    """Compute optimization analysis results"""
    application: str = Field(..., description="Application name")
    instance_name: str = Field(..., description="Compute instance name")
    machine_type: str = Field(..., description="Current machine type")
    machine_type_category: str = Field(..., description="Machine type category")
    instance_state: str = Field(..., description="Instance state (running/stopped)")
    utilization_analysis: str = Field(..., description="Resource utilization analysis")
    rightsizing_recommendation: str = Field(..., description="Rightsizing recommendation")
    cost_optimization_potential: str = Field(..., description="Cost optimization potential")
    estimated_monthly_savings: str = Field(..., description="Estimated monthly savings")
    resource_group: str = Field(..., description="GCP Project ID")
    location: str = Field(..., description="GCP zone/region")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def has_high_optimization_potential(self) -> bool:
        """Check if this instance has high optimization potential"""
        return 'high' in self.cost_optimization_potential.lower()


class GCPComputeComplianceSummary(BaseModel):
    """Compute compliance summary by application"""
    application: str = Field(..., description="Application name")
    total_instances: int = Field(..., description="Total compute instances")
    running_instances: int = Field(..., description="Number of running instances")
    stopped_instances: int = Field(..., description="Number of stopped instances")
    encrypted_instances: int = Field(..., description="Number of instances with encrypted disks")
    properly_configured_instances: int = Field(..., description="Number of properly configured instances")
    instances_with_issues: int = Field(..., description="Number of instances with issues")
    security_score: float = Field(..., description="Security compliance score")
    optimization_score: float = Field(..., description="Cost optimization score")
    compliance_status: str = Field(..., description="Overall compliance status")


# =============================================================================
# NETWORK MODELS (Future Expansion)
# =============================================================================

class GCPNetworkResource(BaseModel):
    """Network resource model for security analysis"""
    application: str = Field(..., description="Application name")
    network_resource: str = Field(..., description="Network resource name")
    network_resource_type: str = Field(..., description="Network resource type")
    security_findings: str = Field(..., description="Security findings")
    compliance_risk: str = Field(..., description="Compliance risk assessment")
    resource_group: str = Field(..., description="GCP Project ID")
    location: str = Field(..., description="GCP region/location")
    additional_details: str = Field(..., description="Additional network details")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this network resource has high risk"""
        return self.compliance_risk.lower().startswith('high')


class GCPNetworkSecurityResult(BaseModel):
    """Network security analysis results"""
    application: str = Field(..., description="Application name")
    network_resource: str = Field(..., description="Network resource name")
    resource_type: str = Field(..., description="Network resource type")
    firewall_configuration: str = Field(..., description="Firewall configuration")
    public_access_configuration: str = Field(..., description="Public access configuration")
    security_findings: str = Field(..., description="Security findings")
    compliance_risk: str = Field(..., description="Compliance risk assessment")
    network_details: str = Field(..., description="Additional network details")
    resource_group: str = Field(..., description="GCP Project ID")
    location: str = Field(..., description="GCP region/location")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this network resource has high risk"""
        return self.compliance_risk.lower().startswith('high')


class GCPNetworkComplianceSummary(BaseModel):
    """Network compliance summary by application"""
    application: str = Field(..., description="Application name")
    total_network_resources: int = Field(..., description="Total network resources")
    vpc_network_count: int = Field(..., description="Number of VPC networks")
    firewall_rule_count: int = Field(..., description="Number of firewall rules")
    load_balancer_count: int = Field(..., description="Number of load balancers")
    resources_with_issues: int = Field(..., description="Number of resources with issues")
    security_score: float = Field(..., description="Network security score")
    security_status: str = Field(..., description="Security status")


# =============================================================================
# IAM MODELS (Future Expansion)
# =============================================================================

class GCPIAMResource(BaseModel):
    """IAM resource model for security analysis"""
    application: str = Field(..., description="Application name")
    iam_resource: str = Field(..., description="IAM resource identifier")
    resource_type: str = Field(..., description="IAM resource type")
    security_findings: str = Field(..., description="Security findings")
    compliance_risk: str = Field(..., description="Compliance risk assessment")
    resource_group: str = Field(..., description="GCP Project ID")
    additional_details: str = Field(..., description="Additional IAM details")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this IAM resource has high risk"""
        return self.compliance_risk.lower().startswith('high')


class GCPIAMSecurityResult(BaseModel):
    """IAM security analysis results"""
    application: str = Field(..., description="Application name")
    iam_resource: str = Field(..., description="IAM resource identifier")
    resource_type: str = Field(..., description="IAM resource type")
    access_configuration: str = Field(..., description="Access configuration details")
    privilege_level: str = Field(..., description="Privilege level assessment")
    security_findings: str = Field(..., description="Security findings")
    security_risk: str = Field(..., description="Security risk assessment")
    iam_details: str = Field(..., description="Additional IAM details")
    resource_group: str = Field(..., description="GCP Project ID")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this IAM configuration has high risk"""
        return self.security_risk.lower().startswith('high')


class GCPIAMComplianceSummary(BaseModel):
    """IAM compliance summary by application"""
    application: str = Field(..., description="Application name")
    total_iam_bindings: int = Field(..., description="Total IAM policy bindings")
    service_account_count: int = Field(..., description="Number of service accounts")
    custom_role_count: int = Field(..., description="Number of custom roles")
    high_privilege_bindings: int = Field(..., description="Number of high privilege bindings")
    bindings_with_issues: int = Field(..., description="Number of bindings with issues")
    iam_compliance_score: float = Field(..., description="IAM compliance score")
    iam_compliance_status: str = Field(..., description="IAM compliance status")


# =============================================================================
# CONTAINER MODELS (Future Expansion)
# =============================================================================

class GCPContainerResource(BaseModel):
    """Container resource model for security analysis"""
    application: str = Field(..., description="Application name")
    cluster_name: str = Field(..., description="GKE cluster name")
    resource_type: str = Field(..., description="Container resource type")
    security_findings: str = Field(..., description="Security findings")
    compliance_risk: str = Field(..., description="Compliance risk assessment")
    resource_group: str = Field(..., description="GCP Project ID")
    location: str = Field(..., description="GCP region/zone")
    additional_details: str = Field(..., description="Additional cluster details")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this container resource has high risk"""
        return self.compliance_risk.lower().startswith('high')


class GCPContainerSecurityResult(BaseModel):
    """Container security analysis results"""
    application: str = Field(..., description="Application name")
    cluster_name: str = Field(..., description="GKE cluster name")
    cluster_version: str = Field(..., description="Kubernetes version")
    security_configuration: str = Field(..., description="Security configuration")
    network_policy_status: str = Field(..., description="Network policy configuration")
    rbac_configuration: str = Field(..., description="RBAC configuration")
    security_findings: str = Field(..., description="Security findings")
    security_risk: str = Field(..., description="Security risk assessment")
    cluster_details: str = Field(..., description="Additional cluster details")
    resource_group: str = Field(..., description="GCP Project ID")
    location: str = Field(..., description="GCP region/zone")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this container resource has high risk"""
        return self.security_risk.lower().startswith('high')


class GCPContainerComplianceSummary(BaseModel):
    """Container compliance summary by application"""
    application: str = Field(..., description="Application name")
    total_clusters: int = Field(..., description="Total GKE clusters")
    secure_clusters: int = Field(..., description="Number of secure clusters")
    clusters_with_issues: int = Field(..., description="Number of clusters with issues")
    container_compliance_score: float = Field(..., description="Container compliance score")
    container_compliance_status: str = Field(..., description="Container compliance status")


# =============================================================================
# COMPREHENSIVE ANALYSIS RESULT
# =============================================================================

class GCPComprehensiveAnalysisResult(BaseModel):
    """Comprehensive analysis result across all resource types"""
    project_ids: List[str] = Field(..., description="GCP project IDs analyzed")
    analysis_timestamp: datetime = Field(default_factory=datetime.now, description="Analysis timestamp")

    # Storage analysis results
    storage_analysis: List[GCPStorageResource] = Field(default_factory=list, description="Storage security analysis")
    storage_compliance: List[GCPEnhancedStorageComplianceSummary] = Field(default_factory=list,
                                                                          description="Storage compliance summary")
    storage_optimization: List[GCPStorageOptimizationResult] = Field(default_factory=list,
                                                                     description="Storage optimization analysis")
    kms_analysis: List[GCPKMSSecurityResult] = Field(default_factory=list, description="KMS security analysis")

    # Future expansion placeholders
    compute_analysis: List[GCPComputeSecurityResult] = Field(default_factory=list,
                                                             description="Compute security analysis")
    compute_compliance: List[GCPComputeComplianceSummary] = Field(default_factory=list,
                                                                  description="Compute compliance summary")

    network_analysis: List[GCPNetworkSecurityResult] = Field(default_factory=list,
                                                             description="Network security analysis")
    network_compliance: List[GCPNetworkComplianceSummary] = Field(default_factory=list,
                                                                  description="Network compliance summary")

    iam_analysis: List[GCPIAMSecurityResult] = Field(default_factory=list, description="IAM security analysis")
    iam_compliance: List[GCPIAMComplianceSummary] = Field(default_factory=list, description="IAM compliance summary")

    container_analysis: List[GCPContainerSecurityResult] = Field(default_factory=list,
                                                                 description="Container security analysis")
    container_compliance: List[GCPContainerComplianceSummary] = Field(default_factory=list,
                                                                      description="Container compliance summary")

    # Summary statistics
    total_resources_analyzed: int = Field(..., description="Total number of resources analyzed")
    high_risk_resources: int = Field(..., description="Number of high-risk resources")
    optimization_opportunities: int = Field(..., description="Number of optimization opportunities")
    compliance_issues: int = Field(..., description="Number of compliance issues")

    # Overall scores
    overall_security_score: float = Field(default=0.0, description="Overall security score")
    overall_compliance_score: float = Field(default=0.0, description="Overall compliance score")
    overall_optimization_score: float = Field(default=0.0, description="Overall optimization score")

    @property
    def critical_issues_count(self) -> int:
        """Count of critical security issues across all resources"""
        critical_count = 0
        critical_count += sum(1 for r in self.storage_analysis if r.is_high_risk)
        critical_count += sum(1 for r in self.kms_analysis if r.is_high_risk)
        critical_count += sum(1 for r in self.compute_analysis if r.is_high_risk)
        critical_count += sum(1 for r in self.network_analysis if r.is_high_risk)
        critical_count += sum(1 for r in self.iam_analysis if r.is_high_risk)
        critical_count += sum(1 for r in self.container_analysis if r.is_high_risk)
        return critical_count

    @property
    def total_optimization_savings_opportunities(self) -> int:
        """Count of high-value optimization opportunities"""
        optimization_count = 0
        optimization_count += sum(1 for r in self.storage_optimization if r.has_high_optimization_potential)
        # Add other optimization counts as they're implemented
        return optimization_count


# =============================================================================
# UTILITY CLASSES
# =============================================================================

class RateLimitTracker:
    """Track API rate limiting"""

    def __init__(self):
        self.requests_made: int = 0
        self.window_start: datetime = datetime.now()
        self.max_requests_per_minute: int = 100

    def can_make_request(self) -> bool:
        now = datetime.now()
        if (now - self.window_start).seconds > 60:
            self.window_start = now
            self.requests_made = 0
            return True
        return self.requests_made < self.max_requests_per_minute

    def record_request(self):
        self.requests_made += 1

    def wait_if_needed(self):
        import time
        if not self.can_make_request():
            wait_time = 60 - (datetime.now() - self.window_start).seconds
            print(f"⏱️ Rate limit reached. Waiting {wait_time} seconds...")
            time.sleep(wait_time + 1)
            self.window_start = datetime.now()
            self.requests_made = 0


class GCPConfig:
    """GCP configuration class"""

    def __init__(self, project_ids: List[str], credentials_path: Optional[str] = None):
        self.project_ids = project_ids
        self.credentials_path = credentials_path
