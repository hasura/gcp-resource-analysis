"""
functions.py

Complete GCP Resource Analysis functions for Hasura Lambda connector.
Includes all available queries from the GCP Resource Analysis Client.
All functions return List[PydanticModel] as required by register_query.
"""
from hasura_ndc import start
from hasura_ndc.instrumentation import with_active_span
from opentelemetry.trace import get_tracer
from hasura_ndc.function_connector import FunctionConnector
from hasura_ndc.errors import UnprocessableContent
from typing import Annotated, List, Optional, Dict, Any
from pydantic import BaseModel, Field
import asyncio

# Import the GCP client and all its models
from gcp_resource_analysis import GCPResourceAnalysisClient
from gcp_resource_analysis.models import (
    # Storage models
    GCPStorageResource, GCPStorageAccessControlResult, GCPStorageBackupResult,
    GCPStorageOptimizationResult, GCPStorageComplianceSummary, GCPKMSSecurityResult,
    GCPEnhancedStorageComplianceSummary,

    # Compute Governance models
    GCPVMSecurityResult, GCPVMOptimizationResult, GCPVMConfigurationResult,
    GCPVMPatchComplianceResult, GCPVMGovernanceSummary, GCPComputeComplianceSummary,

    # Network models
    GCPNetworkResource, GCPFirewallRule, GCPSSLCertificateResult,
    GCPNetworkTopologyResult, GCPNetworkOptimizationResult, GCPNetworkComplianceSummary,

    # IAM models
    GCPServiceAccountSecurityResult, GCPIAMPolicyBindingResult, GCPCustomRoleResult,
    GCPWorkloadIdentityResult, GCPServiceAccountKeyResult, GCPIAMComplianceSummary,

    # Container Workloads models
    GCPGKEClusterSecurityResult, GCPGKENodePoolResult, GCPArtifactRegistrySecurityResult,
    GCPCloudRunSecurityResult, GCPAppEngineSecurityResult, GCPCloudFunctionsSecurityResult,
    GCPContainerWorkloadsComplianceSummary,

    # Comprehensive analysis
    GCPComprehensiveAnalysisResult
)

connector = FunctionConnector()
tracer = get_tracer("ndc-sdk-python.server")

# Initialize GCP client
client = GCPResourceAnalysisClient()

# ============================================================================
# ADDITIONAL PYDANTIC MODELS FOR COMPREHENSIVE ANALYSIS
# ============================================================================

class ApplicationStorageResource(BaseModel):
    """Pydantic model for application-specific storage resources"""
    application: str = Field(..., description="Application name")
    storage_resource: str = Field(..., description="Storage resource name")
    storage_type: str = Field(..., description="Type of storage resource")
    resource_group: str = Field(..., description="Project ID")
    location: str = Field(..., description="GCP region location")
    tags: Dict[str, Any] = Field(default_factory=dict, description="Resource labels")
    resource_id: str = Field(..., description="Full GCP resource ID")

class ComprehensiveAnalysisResult(BaseModel):
    """Pydantic model for comprehensive analysis results"""
    category: str = Field(..., description="Analysis category (storage, compute_governance, network, iam, container_workloads)")
    subcategory: str = Field(..., description="Analysis subcategory")
    resource_count: int = Field(..., description="Number of resources analyzed")
    high_risk_count: int = Field(..., description="Number of high-risk resources")
    medium_risk_count: int = Field(..., description="Number of medium-risk resources")
    low_risk_count: int = Field(..., description="Number of low-risk resources")
    compliance_score: float = Field(..., description="Overall compliance score for this category")
    summary: str = Field(..., description="Summary of findings")

class ApplicationAnalysisResult(BaseModel):
    """Pydantic model for application-specific analysis results"""
    application: str = Field(..., description="Application name")
    category: str = Field(..., description="Analysis category")
    subcategory: str = Field(..., description="Analysis subcategory")
    resource_count: int = Field(..., description="Number of resources for this application")
    issues_count: int = Field(..., description="Number of issues found")
    compliance_score: float = Field(..., description="Compliance score for this application category")
    risk_level: str = Field(..., description="Overall risk level (High/Medium/Low)")
    summary: str = Field(..., description="Summary of findings for this application")

class ContainerWorkloadsAnalysisResult(BaseModel):
    """Pydantic model for comprehensive container workloads analysis"""
    analysis_type: str = Field(..., description="Type of container workloads analysis")
    resource_count: int = Field(..., description="Number of resources analyzed")
    issues_count: int = Field(..., description="Number of issues found")
    compliance_score: float = Field(..., description="Compliance score")
    risk_level: str = Field(..., description="Overall risk level")
    summary: str = Field(..., description="Summary of findings")

# ============================================================================
# STORAGE ANALYSIS FUNCTIONS
# ============================================================================

@connector.register_query
async def gcp_storage_analysis(project_ids: Optional[List[str]] = None) -> List[GCPStorageResource]:
    """
    Comprehensive storage security analysis including encryption, compliance, and security findings.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of storage resources with security analysis
    """
    return client.query_storage_analysis(project_ids)

@connector.register_query
async def gcp_storage_encryption(project_ids: Optional[List[str]] = None) -> List[GCPStorageResource]:
    """
    Storage encryption analysis across all storage types.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of storage resources with encryption status
    """
    return client.query_storage_encryption(project_ids)

@connector.register_query
async def gcp_enhanced_storage_analysis(project_ids: Optional[List[str]] = None) -> List[GCPStorageResource]:
    """
    Enhanced storage security analysis using comprehensive analyzers.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of storage resources with enhanced security analysis
    """
    return client.query_enhanced_storage_analysis(project_ids)

@connector.register_query
async def gcp_storage_access_control(project_ids: Optional[List[str]] = None) -> List[GCPStorageAccessControlResult]:
    """
    Storage access control and network security analysis.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of storage access control analysis results
    """
    return client.query_storage_access_control()

@connector.register_query
async def gcp_storage_backup_analysis(project_ids: Optional[List[str]] = None) -> List[GCPStorageBackupResult]:
    """
    Storage backup configuration and disaster recovery analysis.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of storage backup analysis results
    """
    return client.query_storage_backup_analysis()

@connector.register_query
async def gcp_enhanced_storage_backup_analysis(project_ids: Optional[List[str]] = None) -> List[GCPStorageBackupResult]:
    """
    Enhanced backup analysis covering all storage types.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of enhanced backup analysis results
    """
    return client.query_enhanced_storage_backup_analysis()

@connector.register_query
async def gcp_storage_optimization(project_ids: Optional[List[str]] = None) -> List[GCPStorageOptimizationResult]:
    """
    Storage cost optimization and utilization analysis.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of storage optimization recommendations
    """
    return client.query_storage_optimization()

@connector.register_query
async def gcp_enhanced_storage_optimization(project_ids: Optional[List[str]] = None) -> List[GCPStorageOptimizationResult]:
    """
    Enhanced cost optimization analysis using comprehensive analyzer.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of enhanced storage optimization results
    """
    return client.query_enhanced_storage_optimization()

@connector.register_query
async def gcp_cloud_kms_security(project_ids: Optional[List[str]] = None) -> List[GCPKMSSecurityResult]:
    """
    Cloud KMS security analysis - equivalent to Azure Key Vault analysis.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of Cloud KMS security analysis results
    """
    return client.query_cloud_kms_security()

@connector.register_query
async def gcp_storage_compliance_summary(project_ids: Optional[List[str]] = None) -> List[GCPStorageComplianceSummary]:
    """
    Storage compliance summary by application.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of storage compliance summaries per application
    """
    return client.get_storage_compliance_summary()

@connector.register_query
async def gcp_enhanced_storage_compliance_summary(project_ids: Optional[List[str]] = None) -> List[GCPEnhancedStorageComplianceSummary]:
    """
    Enhanced storage compliance summary including all storage services and KMS.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of enhanced storage compliance summaries per application
    """
    return client.get_enhanced_storage_compliance_summary()

# ============================================================================
# COMPUTE GOVERNANCE FUNCTIONS
# ============================================================================

@connector.register_query
async def gcp_vm_security(project_ids: Optional[List[str]] = None) -> List[GCPVMSecurityResult]:
    """
    Compute Engine VM security analysis including encryption, configurations, and compliance.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of VM security analysis results
    """
    return client.query_vm_security(project_ids)

@connector.register_query
async def gcp_vm_optimization(project_ids: Optional[List[str]] = None) -> List[GCPVMOptimizationResult]:
    """
    Compute Engine VM cost optimization and sizing analysis.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of VM optimization recommendations
    """
    return client.query_vm_optimization(project_ids)

@connector.register_query
async def gcp_vm_configurations(project_ids: Optional[List[str]] = None) -> List[GCPVMConfigurationResult]:
    """
    Compute Engine VM configuration analysis for security and compliance impact.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of VM configuration analysis results
    """
    return client.query_vm_configurations(project_ids)

@connector.register_query
async def gcp_vm_patch_compliance(project_ids: Optional[List[str]] = None) -> List[GCPVMPatchComplianceResult]:
    """
    Compute Engine VM patch management and update compliance analysis.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of VM patch compliance results
    """
    return client.query_vm_patch_compliance(project_ids)

@connector.register_query
async def gcp_vm_governance_summary(project_ids: Optional[List[str]] = None) -> List[GCPVMGovernanceSummary]:
    """
    VM governance summary by application including security and optimization metrics.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of VM governance summaries per application
    """
    return client.get_vm_governance_summary()

@connector.register_query
async def gcp_compute_compliance_summary(project_ids: Optional[List[str]] = None) -> List[GCPComputeComplianceSummary]:
    """
    Compute compliance summary by application.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of compute compliance summaries per application
    """
    return client.get_compute_compliance_summary()

# ============================================================================
# NETWORK ANALYSIS FUNCTIONS
# ============================================================================

@connector.register_query
async def gcp_vpc_network_analysis(project_ids: Optional[List[str]] = None) -> List[GCPNetworkResource]:
    """
    Comprehensive VPC network security analysis including VPCs, subnets, and load balancers.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of network resources with security analysis
    """
    return client.query_vpc_network_analysis(project_ids)

@connector.register_query
async def gcp_vpc_network_security(project_ids: Optional[List[str]] = None) -> List[GCPNetworkResource]:
    """
    VPC network security analysis (alias for vpc_network_analysis).

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of VPC network security analysis results
    """
    return client.query_vpc_network_security(project_ids)

@connector.register_query
async def gcp_firewall_rules_detailed(project_ids: Optional[List[str]] = None) -> List[GCPFirewallRule]:
    """
    Detailed firewall rules analysis with risk assessment.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of firewall rules with detailed security analysis
    """
    return client.query_firewall_rules_detailed(project_ids)

@connector.register_query
async def gcp_ssl_certificate_analysis(project_ids: Optional[List[str]] = None) -> List[GCPSSLCertificateResult]:
    """
    SSL/TLS certificate analysis for Load Balancers and other services.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of SSL certificate analysis results
    """
    return client.query_ssl_certificate_analysis(project_ids)

@connector.register_query
async def gcp_network_topology(project_ids: Optional[List[str]] = None) -> List[GCPNetworkTopologyResult]:
    """
    Network topology and configuration analysis.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of network topology analysis results
    """
    return client.query_network_topology(project_ids)

@connector.register_query
async def gcp_network_resource_optimization(project_ids: Optional[List[str]] = None) -> List[GCPNetworkOptimizationResult]:
    """
    Network resource optimization and cost analysis.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of network resource optimization recommendations
    """
    return client.query_network_resource_optimization(project_ids)

@connector.register_query
async def gcp_network_compliance_summary(project_ids: Optional[List[str]] = None) -> List[GCPNetworkComplianceSummary]:
    """
    Network compliance summary by application.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of network compliance summaries per application
    """
    return client.get_network_compliance_summary()

# ============================================================================
# IAM ANALYSIS FUNCTIONS
# ============================================================================

@connector.register_query
async def gcp_service_account_security(project_ids: Optional[List[str]] = None) -> List[GCPServiceAccountSecurityResult]:
    """
    Service account security analysis including usage patterns and security risks.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of service account security analysis results
    """
    return client.query_service_account_security()

@connector.register_query
async def gcp_iam_policy_bindings(project_ids: Optional[List[str]] = None) -> List[GCPIAMPolicyBindingResult]:
    """
    IAM policy bindings analysis and security assessment.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of IAM policy binding analysis results
    """
    return client.query_iam_policy_bindings()

@connector.register_query
async def gcp_custom_roles(project_ids: Optional[List[str]] = None) -> List[GCPCustomRoleResult]:
    """
    Custom IAM roles analysis and security assessment.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of custom role analysis results
    """
    return client.query_custom_roles()

@connector.register_query
async def gcp_workload_identity(project_ids: Optional[List[str]] = None) -> List[GCPWorkloadIdentityResult]:
    """
    Workload Identity configuration and security analysis.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of Workload Identity analysis results
    """
    return client.query_workload_identity(project_ids)

@connector.register_query
async def gcp_service_account_keys(project_ids: Optional[List[str]] = None) -> List[GCPServiceAccountKeyResult]:
    """
    Service account keys analysis including age and security risks.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of service account key analysis results
    """
    return client.query_service_account_keys()

@connector.register_query
async def gcp_iam_compliance_summary(project_ids: Optional[List[str]] = None) -> List[GCPIAMComplianceSummary]:
    """
    Identity and Access Management compliance summary by application.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of IAM compliance summaries per application
    """
    return client.get_iam_compliance_summary()

# ============================================================================
# CONTAINER WORKLOADS ANALYSIS FUNCTIONS
# ============================================================================

@connector.register_query
async def gcp_gke_cluster_security(project_ids: Optional[List[str]] = None) -> List[GCPGKEClusterSecurityResult]:
    """
    Google Kubernetes Engine (GKE) cluster security analysis including RBAC and network policies.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of GKE cluster security analysis results
    """
    return client.query_gke_cluster_security(project_ids)

@connector.register_query
async def gcp_gke_node_pools(project_ids: Optional[List[str]] = None) -> List[GCPGKENodePoolResult]:
    """
    GKE node pool analysis including VM sizes, scaling, and optimization.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of GKE node pool analysis results
    """
    return client.query_gke_node_pools(project_ids)

@connector.register_query
async def gcp_artifact_registry_security(project_ids: Optional[List[str]] = None) -> List[GCPArtifactRegistrySecurityResult]:
    """
    Artifact Registry security analysis including access controls and scanning policies.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of Artifact Registry security analysis results
    """
    return client.query_artifact_registry_security(project_ids)

@connector.register_query
async def gcp_cloud_run_security(project_ids: Optional[List[str]] = None) -> List[GCPCloudRunSecurityResult]:
    """
    Cloud Run security analysis including TLS, authentication, and network security.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of Cloud Run security analysis results
    """
    return client.query_cloud_run_security(project_ids)

@connector.register_query
async def gcp_app_engine_security(project_ids: Optional[List[str]] = None) -> List[GCPAppEngineSecurityResult]:
    """
    App Engine security analysis including authentication and network security.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of App Engine security analysis results
    """
    return client.query_app_engine_security(project_ids)

@connector.register_query
async def gcp_cloud_functions_security(project_ids: Optional[List[str]] = None) -> List[GCPCloudFunctionsSecurityResult]:
    """
    Cloud Functions security analysis including authentication and network security.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of Cloud Functions security analysis results
    """
    return client.query_cloud_functions_security(project_ids)

@connector.register_query
async def gcp_container_workloads_compliance_summary(project_ids: Optional[List[str]] = None) -> List[GCPContainerWorkloadsComplianceSummary]:
    """
    Container and modern workloads compliance summary by application.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of container workloads compliance summaries per application
    """
    return client.get_container_workloads_compliance_summary()

@connector.register_query
async def gcp_comprehensive_container_workloads_analysis(project_ids: Optional[List[str]] = None) -> List[ContainerWorkloadsAnalysisResult]:
    """
    Comprehensive container and modern workloads analysis including all aspects.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of container workloads analysis results
    """
    with tracer.start_as_current_span("comprehensive_container_analysis"):
        try:
            # Get the raw results from client
            raw_results = client.query_comprehensive_container_workloads_analysis()

            # Convert to list of Pydantic objects
            analysis_results = []

            # Process GKE clusters
            gke_clusters = raw_results.get('gke_cluster_security', [])
            if gke_clusters:
                high_risk = len([r for r in gke_clusters if hasattr(r, 'is_high_risk') and r.is_high_risk])
                analysis_results.append(ContainerWorkloadsAnalysisResult(
                    analysis_type="GKE Cluster Security",
                    resource_count=len(gke_clusters),
                    issues_count=high_risk,
                    compliance_score=((len(gke_clusters) - high_risk) / len(gke_clusters) * 100) if gke_clusters else 100,
                    risk_level="High" if high_risk > 0 else "Low",
                    summary=f"Analyzed {len(gke_clusters)} GKE clusters, {high_risk} with high-risk configurations"
                ))

            # Process Artifact Registries
            registries = raw_results.get('artifact_registry_security', [])
            if registries:
                high_risk = len([r for r in registries if hasattr(r, 'is_high_risk') and r.is_high_risk])
                analysis_results.append(ContainerWorkloadsAnalysisResult(
                    analysis_type="Artifact Registry Security",
                    resource_count=len(registries),
                    issues_count=high_risk,
                    compliance_score=((len(registries) - high_risk) / len(registries) * 100) if registries else 100,
                    risk_level="High" if high_risk > 0 else "Low",
                    summary=f"Analyzed {len(registries)} artifact registries, {high_risk} with security issues"
                ))

            # Process Cloud Run services
            cloud_run_services = raw_results.get('cloud_run_security', [])
            if cloud_run_services:
                high_risk = len([r for r in cloud_run_services if hasattr(r, 'is_high_risk') and r.is_high_risk])
                analysis_results.append(ContainerWorkloadsAnalysisResult(
                    analysis_type="Cloud Run Security",
                    resource_count=len(cloud_run_services),
                    issues_count=high_risk,
                    compliance_score=((len(cloud_run_services) - high_risk) / len(cloud_run_services) * 100) if cloud_run_services else 100,
                    risk_level="High" if high_risk > 0 else "Low",
                    summary=f"Analyzed {len(cloud_run_services)} Cloud Run services, {high_risk} with security issues"
                ))

            # Process App Engine
            app_engine_services = raw_results.get('app_engine_security', [])
            if app_engine_services:
                high_risk = len([r for r in app_engine_services if hasattr(r, 'is_high_risk') and r.is_high_risk])
                analysis_results.append(ContainerWorkloadsAnalysisResult(
                    analysis_type="App Engine Security",
                    resource_count=len(app_engine_services),
                    issues_count=high_risk,
                    compliance_score=((len(app_engine_services) - high_risk) / len(app_engine_services) * 100) if app_engine_services else 100,
                    risk_level="High" if high_risk > 0 else "Low",
                    summary=f"Analyzed {len(app_engine_services)} App Engine services, {high_risk} with security issues"
                ))

            # Process Cloud Functions
            cloud_functions = raw_results.get('cloud_functions_security', [])
            if cloud_functions:
                high_risk = len([r for r in cloud_functions if hasattr(r, 'is_high_risk') and r.is_high_risk])
                analysis_results.append(ContainerWorkloadsAnalysisResult(
                    analysis_type="Cloud Functions Security",
                    resource_count=len(cloud_functions),
                    issues_count=high_risk,
                    compliance_score=((len(cloud_functions) - high_risk) / len(cloud_functions) * 100) if cloud_functions else 100,
                    risk_level="High" if high_risk > 0 else "Low",
                    summary=f"Analyzed {len(cloud_functions)} Cloud Functions, {high_risk} with security issues"
                ))

            # Process Node Pools
            node_pools = raw_results.get('gke_node_pools', [])
            if node_pools:
                high_risk = len([r for r in node_pools if hasattr(r, 'node_pool_risk') and 'High' in r.node_pool_risk])
                analysis_results.append(ContainerWorkloadsAnalysisResult(
                    analysis_type="GKE Node Pool Analysis",
                    resource_count=len(node_pools),
                    issues_count=high_risk,
                    compliance_score=((len(node_pools) - high_risk) / len(node_pools) * 100) if node_pools else 100,
                    risk_level="High" if high_risk > 0 else "Low",
                    summary=f"Analyzed {len(node_pools)} node pools, {high_risk} with optimization issues"
                ))

            return analysis_results

        except Exception as e:
            raise UnprocessableContent(f"Failed to perform comprehensive container workloads analysis: {str(e)}")

# ============================================================================
# APPLICATION-SPECIFIC FUNCTIONS
# ============================================================================

@connector.register_query
async def gcp_application_storage(application_name: str, project_ids: Optional[List[str]] = None) -> List[ApplicationStorageResource]:
    """
    Query storage resources for a specific application.

    Args:
        application_name: Name of the application to query
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of storage resources for the specified application
    """
    try:
        # Get all storage resources and filter by application
        all_storage = client.query_storage_analysis()

        # Filter resources for the specified application
        app_storage = [resource for resource in all_storage if resource.application == application_name]

        # Convert to ApplicationStorageResource format
        storage_resources = []
        for resource in app_storage:
            storage_resource = ApplicationStorageResource(
                application=resource.application,
                storage_resource=resource.storage_resource,
                storage_type=resource.storage_type,
                resource_group=resource.resource_group,
                location=resource.location,
                tags={},  # GCP uses labels, but we'll keep this simple
                resource_id=resource.resource_id
            )
            storage_resources.append(storage_resource)

        return storage_resources

    except Exception as e:
        raise UnprocessableContent(f"Failed to get application storage for {application_name}: {str(e)}")

# ============================================================================
# COMPREHENSIVE ANALYSIS FUNCTIONS
# ============================================================================

@connector.register_query
async def gcp_comprehensive_security_analysis(project_ids: Optional[List[str]] = None) -> List[ComprehensiveAnalysisResult]:
    """
    Comprehensive security analysis across all GCP resource types.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of comprehensive analysis results organized by category
    """
    with tracer.start_as_current_span("comprehensive_analysis"):
        results = []

        try:
            # Storage Analysis
            with tracer.start_as_current_span("storage_analysis_section"):
                storage_resources = client.query_enhanced_storage_analysis()
                storage_summaries = client.get_enhanced_storage_compliance_summary()

                high_risk = len([r for r in storage_resources if r.is_high_risk])
                medium_risk = len([r for r in storage_resources if 'Medium' in r.compliance_risk])
                low_risk = len(storage_resources) - high_risk - medium_risk
                avg_compliance = sum([s.compliance_score for s in storage_summaries]) / len(storage_summaries) if storage_summaries else 0

                results.append(ComprehensiveAnalysisResult(
                    category="storage",
                    subcategory="security_analysis",
                    resource_count=len(storage_resources),
                    high_risk_count=high_risk,
                    medium_risk_count=medium_risk,
                    low_risk_count=low_risk,
                    compliance_score=avg_compliance,
                    summary=f"Analyzed {len(storage_resources)} storage resources across {len(storage_summaries)} applications"
                ))

            # Compute Governance
            with tracer.start_as_current_span("compute_governance_section"):
                vm_security = client.query_vm_security()
                vm_summaries = client.get_vm_governance_summary()

                high_risk = len([r for r in vm_security if r.is_high_risk])
                medium_risk = len([r for r in vm_security if 'Medium' in r.security_risk])
                low_risk = len(vm_security) - high_risk - medium_risk
                avg_governance = sum([s.governance_score for s in vm_summaries]) / len(vm_summaries) if vm_summaries else 0

                results.append(ComprehensiveAnalysisResult(
                    category="compute_governance",
                    subcategory="security_analysis",
                    resource_count=len(vm_security),
                    high_risk_count=high_risk,
                    medium_risk_count=medium_risk,
                    low_risk_count=low_risk,
                    compliance_score=avg_governance,
                    summary=f"Analyzed {len(vm_security)} VMs across {len(vm_summaries)} applications"
                ))

            # Network Analysis
            with tracer.start_as_current_span("network_analysis_section"):
                network_resources = client.query_vpc_network_security()
                network_summaries = client.get_network_compliance_summary()

                high_risk = len([r for r in network_resources if r.is_high_risk])
                medium_risk = len([r for r in network_resources if 'Medium' in r.compliance_risk])
                low_risk = len(network_resources) - high_risk - medium_risk
                avg_security = sum([s.security_score for s in network_summaries]) / len(network_summaries) if network_summaries else 0

                results.append(ComprehensiveAnalysisResult(
                    category="network",
                    subcategory="security_analysis",
                    resource_count=len(network_resources),
                    high_risk_count=high_risk,
                    medium_risk_count=medium_risk,
                    low_risk_count=low_risk,
                    compliance_score=avg_security,
                    summary=f"Analyzed {len(network_resources)} network resources across {len(network_summaries)} applications"
                ))

            # IAM Analysis
            with tracer.start_as_current_span("iam_analysis_section"):
                service_accounts = client.query_service_account_security()
                iam_summaries = client.get_iam_compliance_summary()

                high_risk = len([r for r in service_accounts if r.is_high_risk])
                medium_risk = len([r for r in service_accounts if 'Medium' in r.security_risk])
                low_risk = len(service_accounts) - high_risk - medium_risk
                avg_iam = sum([s.iam_compliance_score for s in iam_summaries]) / len(iam_summaries) if iam_summaries else 0

                results.append(ComprehensiveAnalysisResult(
                    category="iam",
                    subcategory="security_analysis",
                    resource_count=len(service_accounts),
                    high_risk_count=high_risk,
                    medium_risk_count=medium_risk,
                    low_risk_count=low_risk,
                    compliance_score=avg_iam,
                    summary=f"Analyzed {len(service_accounts)} Service Accounts across {len(iam_summaries)} applications"
                ))

            # Container Workloads
            with tracer.start_as_current_span("container_workloads_section"):
                gke_clusters = client.query_gke_cluster_security()
                container_summaries = client.get_container_workloads_compliance_summary()

                high_risk = len([r for r in gke_clusters if hasattr(r, 'is_high_risk') and r.is_high_risk])
                medium_risk = len([r for r in gke_clusters if hasattr(r, 'security_risk') and 'Medium' in r.security_risk])
                low_risk = len(gke_clusters) - high_risk - medium_risk
                avg_container = sum([s.container_workloads_compliance_score for s in container_summaries]) / len(container_summaries) if container_summaries else 0

                results.append(ComprehensiveAnalysisResult(
                    category="container_workloads",
                    subcategory="security_analysis",
                    resource_count=len(gke_clusters),
                    high_risk_count=high_risk,
                    medium_risk_count=medium_risk,
                    low_risk_count=low_risk,
                    compliance_score=avg_container,
                    summary=f"Analyzed {len(gke_clusters)} container workloads across {len(container_summaries)} applications"
                ))

            return results

        except Exception as e:
            raise UnprocessableContent(f"Failed to perform comprehensive analysis: {str(e)}")

@connector.register_query
async def gcp_application_analysis(application_name: str, project_ids: Optional[List[str]] = None) -> List[ApplicationAnalysisResult]:
    """
    Comprehensive analysis for a specific application across all resource types.

    Args:
        application_name: Name of the application to analyze
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of analysis results for the specified application
    """
    with tracer.start_as_current_span("application_specific_analysis"):
        try:
            results = []

            # Storage Analysis for Application
            storage_resources = [r for r in client.query_enhanced_storage_analysis() if r.application == application_name]
            if storage_resources:
                issues = len([r for r in storage_resources if r.is_high_risk or 'Medium' in r.compliance_risk])
                compliance_score = ((len(storage_resources) - issues) / len(storage_resources) * 100) if storage_resources else 100

                results.append(ApplicationAnalysisResult(
                    application=application_name,
                    category="storage",
                    subcategory="security_analysis",
                    resource_count=len(storage_resources),
                    issues_count=issues,
                    compliance_score=compliance_score,
                    risk_level="High" if issues > len(storage_resources) * 0.3 else "Medium" if issues > 0 else "Low",
                    summary=f"Found {len(storage_resources)} storage resources with {issues} security issues"
                ))

            # VM Analysis for Application
            vm_resources = [r for r in client.query_vm_security() if r.application == application_name]
            if vm_resources:
                issues = len([r for r in vm_resources if r.is_high_risk or 'Medium' in r.security_risk])
                compliance_score = ((len(vm_resources) - issues) / len(vm_resources) * 100) if vm_resources else 100

                results.append(ApplicationAnalysisResult(
                    application=application_name,
                    category="compute_governance",
                    subcategory="security_analysis",
                    resource_count=len(vm_resources),
                    issues_count=issues,
                    compliance_score=compliance_score,
                    risk_level="High" if issues > len(vm_resources) * 0.3 else "Medium" if issues > 0 else "Low",
                    summary=f"Found {len(vm_resources)} VMs with {issues} security issues"
                ))

            # Network Analysis for Application
            network_resources = [r for r in client.query_vpc_network_security() if r.application == application_name]
            if network_resources:
                issues = len([r for r in network_resources if r.is_high_risk or 'Medium' in r.compliance_risk])
                compliance_score = ((len(network_resources) - issues) / len(network_resources) * 100) if network_resources else 100

                results.append(ApplicationAnalysisResult(
                    application=application_name,
                    category="network",
                    subcategory="security_analysis",
                    resource_count=len(network_resources),
                    issues_count=issues,
                    compliance_score=compliance_score,
                    risk_level="High" if issues > len(network_resources) * 0.3 else "Medium" if issues > 0 else "Low",
                    summary=f"Found {len(network_resources)} network resources with {issues} security issues"
                ))

            # IAM Analysis for Application
            service_accounts = [r for r in client.query_service_account_security() if r.application == application_name]
            if service_accounts:
                issues = len([r for r in service_accounts if r.is_high_risk or 'Medium' in r.security_risk])
                compliance_score = ((len(service_accounts) - issues) / len(service_accounts) * 100) if service_accounts else 100

                results.append(ApplicationAnalysisResult(
                    application=application_name,
                    category="iam",
                    subcategory="service_account_security",
                    resource_count=len(service_accounts),
                    issues_count=issues,
                    compliance_score=compliance_score,
                    risk_level="High" if issues > len(service_accounts) * 0.3 else "Medium" if issues > 0 else "Low",
                    summary=f"Found {len(service_accounts)} Service Accounts with {issues} security issues"
                ))

            # Container Workloads Analysis for Application
            gke_clusters = [r for r in client.query_gke_cluster_security() if r.application == application_name]
            if gke_clusters:
                issues = len([r for r in gke_clusters if hasattr(r, 'is_high_risk') and r.is_high_risk])
                compliance_score = ((len(gke_clusters) - issues) / len(gke_clusters) * 100) if gke_clusters else 100

                results.append(ApplicationAnalysisResult(
                    application=application_name,
                    category="container_workloads",
                    subcategory="gke_security",
                    resource_count=len(gke_clusters),
                    issues_count=issues,
                    compliance_score=compliance_score,
                    risk_level="High" if issues > len(gke_clusters) * 0.3 else "Medium" if issues > 0 else "Low",
                    summary=f"Found {len(gke_clusters)} GKE clusters with {issues} security issues"
                ))

            return results

        except Exception as e:
            raise UnprocessableContent(f"Failed to perform application analysis for {application_name}: {str(e)}")

@connector.register_query
async def gcp_comprehensive_analysis_enhanced(project_ids: Optional[List[str]] = None) -> List[GCPComprehensiveAnalysisResult]:
    """
    Comprehensive analysis across all resource types with enhanced results.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List containing single comprehensive analysis result
    """
    with tracer.start_as_current_span("enhanced_comprehensive_analysis"):
        try:
            result = client.query_comprehensive_analysis_enhanced()
            return [result]  # Return as list since function must return List[PydanticModel]

        except Exception as e:
            raise UnprocessableContent(f"Failed to perform enhanced comprehensive analysis: {str(e)}")

# ============================================================================
# COMPREHENSIVE SECTION ANALYSIS FUNCTIONS
# ============================================================================

@connector.register_query
async def gcp_comprehensive_storage_analysis(project_ids: Optional[List[str]] = None) -> List[ApplicationAnalysisResult]:
    """
    Comprehensive storage analysis across all projects and applications.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of storage analysis results by application
    """
    with tracer.start_as_current_span("comprehensive_storage_analysis"):
        try:
            # Get comprehensive storage analysis
            storage_analysis = client.query_comprehensive_storage_analysis_enhanced()

            # Convert to ApplicationAnalysisResult format
            results = []

            # Get storage compliance summaries for application breakdown
            compliance_summaries = storage_analysis.get('compliance_summary', [])

            for summary in compliance_summaries:
                result = ApplicationAnalysisResult(
                    application=summary.application,
                    category="storage",
                    subcategory="comprehensive_analysis",
                    resource_count=summary.total_storage_resources,
                    issues_count=summary.resources_with_issues,
                    compliance_score=summary.compliance_score,
                    risk_level="High" if summary.compliance_score < 70 else "Medium" if summary.compliance_score < 90 else "Low",
                    summary=f"Storage analysis: {summary.total_storage_resources} resources, {summary.resources_with_issues} issues, {summary.compliance_score}% compliance"
                )
                results.append(result)

            return results

        except Exception as e:
            raise UnprocessableContent(f"Failed to perform comprehensive storage analysis: {str(e)}")

@connector.register_query
async def gcp_comprehensive_compute_governance_analysis(project_ids: Optional[List[str]] = None) -> List[ApplicationAnalysisResult]:
    """
    Comprehensive compute governance analysis across all projects and applications.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of compute governance analysis results by application
    """
    with tracer.start_as_current_span("comprehensive_compute_governance_analysis"):
        try:
            # Get comprehensive VM governance analysis
            compute_analysis = client.query_comprehensive_vm_governance_analysis()

            # Convert to ApplicationAnalysisResult format
            results = []

            # Get VM governance summaries for application breakdown
            governance_summaries = compute_analysis.get('vm_governance_summary', [])

            for summary in governance_summaries:
                result = ApplicationAnalysisResult(
                    application=summary.application,
                    category="compute_governance",
                    subcategory="comprehensive_analysis",
                    resource_count=summary.total_vms,
                    issues_count=summary.vms_with_issues,
                    compliance_score=summary.governance_score,
                    risk_level="High" if summary.governance_score < 70 else "Medium" if summary.governance_score < 90 else "Low",
                    summary=f"VM governance: {summary.total_vms} VMs, {summary.vms_with_issues} issues, {summary.governance_score}% governance score"
                )
                results.append(result)

            return results

        except Exception as e:
            raise UnprocessableContent(f"Failed to perform comprehensive compute governance analysis: {str(e)}")

@connector.register_query
async def gcp_comprehensive_network_analysis(project_ids: Optional[List[str]] = None) -> List[ApplicationAnalysisResult]:
    """
    Comprehensive network analysis across all projects and applications.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of network analysis results by application
    """
    with tracer.start_as_current_span("comprehensive_network_analysis"):
        try:
            # Get comprehensive network analysis
            network_analysis = client.query_comprehensive_network_analysis()

            # Convert to ApplicationAnalysisResult format
            results = []

            # Get network compliance summaries for application breakdown
            compliance_summaries = network_analysis.get('compliance_summary', [])

            for summary in compliance_summaries:
                result = ApplicationAnalysisResult(
                    application=summary.application,
                    category="network",
                    subcategory="comprehensive_analysis",
                    resource_count=summary.total_network_resources,
                    issues_count=summary.resources_with_issues,
                    compliance_score=summary.security_score,
                    risk_level="High" if summary.security_score < 70 else "Medium" if summary.security_score < 90 else "Low",
                    summary=f"Network analysis: {summary.total_network_resources} resources, {summary.resources_with_issues} issues, {summary.security_score}% security score"
                )
                results.append(result)

            return results

        except Exception as e:
            raise UnprocessableContent(f"Failed to perform comprehensive network analysis: {str(e)}")

@connector.register_query
async def gcp_comprehensive_iam_analysis(project_ids: Optional[List[str]] = None) -> List[ApplicationAnalysisResult]:
    """
    Comprehensive IAM analysis across all projects and applications.

    Args:
        project_ids: Optional list of GCP project IDs to query

    Returns:
        List of IAM analysis results by application
    """
    with tracer.start_as_current_span("comprehensive_iam_analysis"):
        try:
            # Get comprehensive IAM analysis
            iam_analysis = client.query_comprehensive_iam_analysis()

            # Convert to ApplicationAnalysisResult format
            results = []

            # Get IAM compliance summaries for application breakdown
            compliance_summaries = iam_analysis.get('iam_compliance_summary', [])

            for summary in compliance_summaries:
                result = ApplicationAnalysisResult(
                    application=summary.application,
                    category="iam",
                    subcategory="comprehensive_analysis",
                    resource_count=summary.total_iam_resources,
                    issues_count=summary.total_issues,
                    compliance_score=summary.iam_compliance_score,
                    risk_level="High" if summary.iam_compliance_score < 70 else "Medium" if summary.iam_compliance_score < 90 else "Low",
                    summary=f"IAM analysis: {summary.total_iam_resources} resources, {summary.total_issues} issues, {summary.iam_compliance_score}% compliance"
                )
                results.append(result)

            return results

        except Exception as e:
            raise UnprocessableContent(f"Failed to perform comprehensive IAM analysis: {str(e)}")

if __name__ == "__main__":
    start(connector)
