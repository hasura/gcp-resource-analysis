# =============================================================================
# CONTAINER & MODERN WORKLOADS MODELS (New - Equivalent to Azure Container Analysis)
# =============================================================================
from pydantic import Field, BaseModel


class GCPGKEClusterSecurityResult(BaseModel):
    """GKE cluster security analysis results - equivalent to Azure AKS"""
    application: str = Field(..., description="Application name")
    cluster_name: str = Field(..., description="GKE cluster name")
    cluster_version: str = Field(..., description="Kubernetes version")
    network_configuration: str = Field(..., description="Network configuration details")
    rbac_configuration: str = Field(..., description="RBAC configuration")
    api_server_access: str = Field(..., description="API server access configuration")
    security_findings: str = Field(..., description="Security findings and issues")
    security_risk: str = Field(..., description="Security risk assessment")
    cluster_compliance: str = Field(..., description="Cluster compliance status")
    cluster_details: str = Field(..., description="Additional cluster details")
    node_pool_count: int = Field(default=0, description="Number of node pools")
    resource_group: str = Field(..., description="GCP Project ID")
    location: str = Field(..., description="GCP region/zone")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this cluster has high security risk"""
        return self.security_risk.lower().startswith('high')


class GCPGKENodePoolResult(BaseModel):
    """GKE node pool analysis results - equivalent to Azure AKS node pools"""
    application: str = Field(..., description="Application name")
    cluster_name: str = Field(..., description="GKE cluster name")
    node_pool_name: str = Field(..., description="Node pool name")
    node_pool_type: str = Field(..., description="Node pool type/configuration")
    vm_size: str = Field(..., description="Machine type (e.g., e2-medium)")
    vm_size_category: str = Field(..., description="Machine type category")
    scaling_configuration: str = Field(..., description="Autoscaling configuration")
    security_configuration: str = Field(..., description="Security configuration")
    optimization_potential: str = Field(..., description="Cost optimization potential")
    node_pool_risk: str = Field(..., description="Node pool risk assessment")
    node_pool_details: str = Field(..., description="Additional node pool details")
    resource_group: str = Field(..., description="GCP Project ID")
    location: str = Field(..., description="GCP region/zone")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this node pool has high risk"""
        return self.node_pool_risk.lower().startswith('high')

    @property
    def has_high_optimization_potential(self) -> bool:
        """Check if this node pool has high optimization potential"""
        return 'high' in self.optimization_potential.lower()


class GCPArtifactRegistrySecurityResult(BaseModel):
    """Artifact Registry security analysis results - equivalent to Azure Container Registry"""
    application: str = Field(..., description="Application name")
    registry_name: str = Field(..., description="Artifact Registry name")
    registry_sku: str = Field(..., description="Registry format and configuration")
    network_security: str = Field(..., description="Network security configuration")
    access_control: str = Field(..., description="Access control configuration")
    security_policies: str = Field(..., description="Security policies configuration")
    security_findings: str = Field(..., description="Security findings")
    security_risk: str = Field(..., description="Security risk assessment")
    compliance_status: str = Field(..., description="Compliance status")
    registry_details: str = Field(..., description="Additional registry details")
    resource_group: str = Field(..., description="GCP Project ID")
    location: str = Field(..., description="GCP region/location")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this registry has high security risk"""
        return self.security_risk.lower().startswith('high')


class GCPCloudRunSecurityResult(BaseModel):
    """Cloud Run security analysis results - equivalent to Azure App Service"""
    application: str = Field(..., description="Application name")
    service_name: str = Field(..., description="Cloud Run service name")
    service_kind: str = Field(..., description="Service kind/type")
    tls_configuration: str = Field(..., description="TLS configuration")
    network_security: str = Field(..., description="Network security configuration")
    authentication_method: str = Field(..., description="Authentication method")
    security_findings: str = Field(..., description="Security findings")
    security_risk: str = Field(..., description="Security risk assessment")
    compliance_status: str = Field(..., description="Compliance status")
    service_details: str = Field(..., description="Additional service details")
    custom_domain_count: int = Field(default=0, description="Number of custom domains")
    resource_group: str = Field(..., description="GCP Project ID")
    location: str = Field(..., description="GCP region/location")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this service has high security risk"""
        return self.security_risk.lower().startswith('high')


class GCPAppEngineSecurityResult(BaseModel):
    """App Engine security analysis results"""
    application: str = Field(..., description="Application name")
    app_name: str = Field(..., description="App Engine application/service name")
    app_kind: str = Field(..., description="App Engine kind (Application/Service/Version)")
    tls_configuration: str = Field(..., description="TLS configuration")
    network_security: str = Field(..., description="Network security configuration")
    authentication_method: str = Field(..., description="Authentication method")
    security_findings: str = Field(..., description="Security findings")
    security_risk: str = Field(..., description="Security risk assessment")
    compliance_status: str = Field(..., description="Compliance status")
    app_details: str = Field(..., description="Additional app details")
    resource_group: str = Field(..., description="GCP Project ID")
    location: str = Field(..., description="GCP region/location")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this app has high security risk"""
        return self.security_risk.lower().startswith('high')


class GCPCloudFunctionsSecurityResult(BaseModel):
    """Cloud Functions security analysis results"""
    application: str = Field(..., description="Application name")
    function_name: str = Field(..., description="Cloud Function name")
    function_kind: str = Field(..., description="Function kind/trigger type")
    tls_configuration: str = Field(..., description="TLS configuration")
    network_security: str = Field(..., description="Network security configuration")
    authentication_method: str = Field(..., description="Authentication method")
    security_findings: str = Field(..., description="Security findings")
    security_risk: str = Field(..., description="Security risk assessment")
    compliance_status: str = Field(..., description="Compliance status")
    function_details: str = Field(..., description="Additional function details")
    resource_group: str = Field(..., description="GCP Project ID")
    location: str = Field(..., description="GCP region/location")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this function has high security risk"""
        return self.security_risk.lower().startswith('high')


class GCPContainerWorkloadsComplianceSummary(BaseModel):
    """Container & Modern Workloads compliance summary by application"""
    application: str = Field(..., description="Application name")
    total_container_workloads: int = Field(..., description="Total container/serverless workloads")
    total_gke_clusters: int = Field(..., description="Total GKE clusters")
    secure_gke_clusters: int = Field(..., description="Number of secure GKE clusters")
    total_artifact_registries: int = Field(..., description="Total Artifact Registries")
    secure_artifact_registries: int = Field(..., description="Number of secure Artifact Registries")
    total_cloud_run_services: int = Field(..., description="Total Cloud Run services")
    secure_cloud_run_services: int = Field(..., description="Number of secure Cloud Run services")
    total_app_engine_services: int = Field(..., description="Total App Engine services")
    secure_app_engine_services: int = Field(..., description="Number of secure App Engine services")
    total_cloud_functions: int = Field(..., description="Total Cloud Functions")
    secure_cloud_functions: int = Field(..., description="Number of secure Cloud Functions")
    container_workloads_with_issues: int = Field(..., description="Number of workloads with issues")
    container_workloads_compliance_score: float = Field(..., description="Container workloads compliance score")
    container_workloads_compliance_status: str = Field(..., description="Container workloads compliance status")
