from pydantic import BaseModel, Field


class GCPVMSecurityResult(BaseModel):
    """GCP Compute Engine VM security analysis result - equivalent to Azure VMSecurityResult"""

    application: str = Field(..., description="Application name from labels")
    vm_name: str = Field(..., description="Name of the Compute Engine instance")
    machine_type: str = Field(..., description="Machine type/family")
    machine_type_category: str = Field(...,
                                       description="Machine type category (e.g., General Purpose, Memory Optimized)")
    instance_status: str = Field(..., description="Current instance status")
    zone: str = Field(..., description="GCP zone where instance is running")
    disk_encryption: str = Field(..., description="Disk encryption configuration")
    security_configuration: str = Field(..., description="Security features enabled (Shielded VM, OS Login, etc.)")
    security_findings: str = Field(..., description="Security assessment findings")
    security_risk: str = Field(..., description="Security risk level")
    compliance_status: str = Field(..., description="Overall compliance status")
    vm_details: str = Field(..., description="Additional VM configuration details")
    project_id: str = Field(..., description="GCP project ID")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_compliant(self) -> bool:
        """Check if VM security configuration is compliant"""
        # Fix: Don't match "Non-Compliant" as compliant
        return self.compliance_status == "Compliant"  # Exact match only

    @property
    def is_encrypted(self) -> bool:
        """Check if VM disk encryption is properly configured"""
        return "Customer Managed" in self.disk_encryption

    @property
    def has_shielded_vm(self) -> bool:
        """Check if VM has Shielded VM features enabled"""
        config_lower = self.security_configuration.lower()
        findings_lower = self.security_findings.lower()

        indicators = ["vtpm", "integrity monitoring", "secure boot", "shielded vm", "shielded features"]
        return any(indicator in config_lower or indicator in findings_lower for indicator in indicators)

    @property
    def is_high_risk(self) -> bool:
        """Check if VM has high security risk"""
        return self.security_risk.lower().startswith("high")

    @property
    def has_os_login(self) -> bool:
        """Check if VM has OS Login enabled"""
        return "OS Login Enabled" in self.security_configuration

    @property
    def is_running(self) -> bool:
        """Check if VM is currently running"""
        return self.instance_status == "RUNNING"

    @property
    def risk_level(self) -> str:
        """Extract risk level from security_risk field"""
        return self.security_risk.split(" - ")[0] if " - " in self.security_risk else self.security_risk

    def __str__(self) -> str:
        status_emoji = "✅" if self.is_compliant else "❌" if self.is_high_risk else "⚠️"
        return f"{status_emoji} {self.application}/{self.vm_name} ({self.machine_type}) - {self.security_risk}"


class GCPVMOptimizationResult(BaseModel):
    """GCP Compute Engine VM optimization analysis result - equivalent to Azure VMOptimizationResult"""

    application: str = Field(..., description="Application name from labels")
    vm_name: str = Field(..., description="Name of the Compute Engine instance")
    machine_type: str = Field(..., description="Current machine type")
    machine_type_category: str = Field(..., description="Machine type category")
    instance_status: str = Field(..., description="Current instance status")
    scheduling_configuration: str = Field(..., description="Instance scheduling configuration")
    utilization_status: str = Field(..., description="Resource utilization assessment")
    optimization_potential: str = Field(..., description="Cost optimization potential")
    optimization_recommendation: str = Field(..., description="Specific optimization recommendation")
    estimated_monthly_cost: str = Field(..., description="Estimated monthly cost category")
    days_running: int = Field(..., description="Number of days the instance has been running")
    committed_use_discount: str = Field(..., description="Committed use discount status")
    preemptible_suitable: str = Field(..., description="Preemptible instance suitability")
    project_id: str = Field(..., description="GCP project ID")
    zone: str = Field(..., description="GCP zone")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_stopped_but_charged(self) -> bool:
        """Check if VM is stopped but still incurring costs"""
        return self.instance_status == "TERMINATED"

    @property
    def is_legacy_machine_type(self) -> bool:
        """Check if VM is using legacy machine types"""
        return "Legacy" in self.machine_type_category or self.machine_type.startswith(
            "n1-") or self.machine_type.startswith("f1-")

    @property
    def has_high_optimization_potential(self) -> bool:
        """Check if VM has high cost optimization potential"""
        return "High" in self.optimization_potential

    @property
    def is_recently_created(self) -> bool:
        """Check if VM was created recently"""
        return self.days_running < 7

    @property
    def is_expensive(self) -> bool:
        """Check if VM is in expensive cost category"""
        return self.estimated_monthly_cost in ["High", "Very High"]

    @property
    def can_use_preemptible(self) -> bool:
        """Check if VM is suitable for preemptible instances"""
        text = self.preemptible_suitable.lower()
        return "suitable" in text or "already preemptible" in text or "achieving maximum" in text

    @property
    def has_cud_opportunity(self) -> bool:
        """Check if VM has Committed Use Discount opportunity"""
        return "Opportunity" in self.committed_use_discount

    @property
    def optimization_priority(self) -> str:
        """Get optimization priority level"""
        if self.has_high_optimization_potential:
            return "High"
        elif "Medium" in self.optimization_potential:
            return "Medium"
        else:
            return "Low"

    def __str__(self) -> str:
        priority_emoji = "🔴" if self.optimization_priority == "High" else "🟡" if self.optimization_priority == "Medium" else "🟢"
        return f"{priority_emoji} {self.application}/{self.vm_name} ({self.machine_type}) - {self.optimization_potential}"


class GCPVMConfigurationResult(BaseModel):
    """GCP Compute Engine VM configuration analysis result - equivalent to Azure VMExtensionResult"""

    application: str = Field(..., description="Application name from labels")
    vm_name: str = Field(..., description="Name of the Compute Engine instance")
    configuration_type: str = Field(..., description="Type of configuration (Monitoring, Security, Patching)")
    configuration_name: str = Field(..., description="Name of the configuration/agent")
    configuration_category: str = Field(..., description="Category (Security, Monitoring, Management)")
    configuration_status: str = Field(..., description="Configuration status")
    installation_method: str = Field(..., description="How the configuration was installed")
    security_importance: str = Field(..., description="Security importance level")
    compliance_impact: str = Field(..., description="Impact on compliance if configuration is missing")
    configuration_details: str = Field(..., description="Additional configuration details")
    project_id: str = Field(..., description="GCP project ID")
    zone: str = Field(..., description="GCP zone")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_security_configuration(self) -> bool:
        """Check if this is a security-related configuration"""
        return "Security" in self.configuration_category

    @property
    def is_monitoring_configuration(self) -> bool:
        """Check if this is a monitoring-related configuration"""
        return "Monitoring" in self.configuration_category

    @property
    def is_management_configuration(self) -> bool:
        """Check if this is a management-related configuration"""
        return "Management" in self.configuration_category

    @property
    def is_healthy(self) -> bool:
        """Check if configuration is in healthy state"""
        return self.configuration_status in ["Active", "Enabled", "Running"]

    @property
    def is_critical(self) -> bool:
        """Check if configuration is critical for security"""
        return self.security_importance == "Critical"

    @property
    def has_compliance_impact(self) -> bool:
        """Check if missing configuration impacts compliance"""
        return not self.compliance_impact.lower().startswith("low")

    def __str__(self) -> str:
        status_emoji = "✅" if self.is_healthy else "❌" if self.configuration_status == "Missing" else "⚠️"
        importance_icon = "🔒" if self.is_security_configuration else "📊" if self.is_monitoring_configuration else "⚙️"
        return f"{status_emoji} {importance_icon} {self.application}/{self.vm_name}: {self.configuration_type} - {self.configuration_status}"


class GCPVMPatchComplianceResult(BaseModel):
    """GCP Compute Engine VM patch compliance analysis result - equivalent to Azure VMPatchComplianceResult"""

    application: str = Field(..., description="Application name from labels")
    vm_name: str = Field(..., description="Name of the Compute Engine instance")
    os_type: str = Field(..., description="Operating system type")
    instance_status: str = Field(..., description="Current instance status")
    os_config_agent_status: str = Field(..., description="OS Config agent status")
    patch_deployment_status: str = Field(..., description="Patch deployment configuration")
    patch_compliance_status: str = Field(..., description="Patch compliance status")
    patch_risk: str = Field(..., description="Patch management risk level")
    last_patch_time: str = Field(..., description="Last patch installation time")
    available_patches: int = Field(..., description="Number of available patches")
    project_id: str = Field(..., description="GCP project ID")
    zone: str = Field(..., description="GCP zone")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def has_os_config_agent(self) -> bool:
        """Check if VM has OS Config agent installed"""
        return "Installed" in self.os_config_agent_status and "Enabled" in self.os_config_agent_status

    @property
    def has_automated_patching(self) -> bool:
        """Check if VM has automated patching configured"""
        return "Automated" in self.patch_deployment_status

    @property
    def requires_manual_patching(self) -> bool:
        """Check if VM requires manual patch management"""
        return "Manual" in self.patch_deployment_status

    @property
    def is_high_risk(self) -> bool:
        """Check if VM has high patch management risk"""
        return self.patch_risk.lower().startswith("high")

    @property
    def has_pending_patches(self) -> bool:
        """Check if VM has pending patches"""
        return self.available_patches > 0

    @property
    def is_patch_compliant(self) -> bool:
        """Check if VM is patch compliant"""
        return "Compliant" in self.patch_compliance_status

    @property
    def risk_level(self) -> str:
        """Extract risk level from patch_risk field"""
        return self.patch_risk.split(" - ")[0] if " - " in self.patch_risk else self.patch_risk

    def __str__(self) -> str:
        risk_emoji = "❌" if self.is_high_risk else "⚠️" if self.risk_level.lower() == "medium" else "✅"
        patch_icon = "🤖" if self.has_automated_patching else "👤"
        return f"{risk_emoji} {patch_icon} {self.application}/{self.vm_name} ({self.os_type}) - {self.patch_compliance_status}"


class GCPVMGovernanceSummary(BaseModel):
    """GCP Compute Engine VM governance compliance summary - equivalent to Azure VMGovernanceSummary"""

    application: str = Field(..., description="Application name")
    total_vms: int = Field(..., description="Total number of Compute Engine instances")
    linux_vms: int = Field(..., description="Number of Linux instances")
    windows_vms: int = Field(..., description="Number of Windows instances")
    running_vms: int = Field(..., description="Number of running instances")
    stopped_vms: int = Field(..., description="Number of stopped instances")
    preemptible_vms: int = Field(..., description="Number of preemptible instances")
    encrypted_vms: int = Field(..., description="Number of instances with proper encryption")
    shielded_vms: int = Field(..., description="Number of instances with Shielded VM enabled")
    legacy_machine_type_vms: int = Field(..., description="Number of instances with legacy machine types")
    optimized_vms: int = Field(..., description="Number of cost-optimized instances")
    vms_with_issues: int = Field(..., description="Number of instances with governance issues")
    governance_score: float = Field(..., description="Governance score percentage")
    governance_status: str = Field(..., description="Overall governance status")

    @property
    def encryption_coverage(self) -> float:
        """Get encryption coverage percentage"""
        if self.total_vms == 0:
            return 0.0
        return (self.encrypted_vms / self.total_vms) * 100

    @property
    def shielded_vm_coverage(self) -> float:
        """Get Shielded VM coverage percentage"""
        if self.total_vms == 0:
            return 0.0
        return (self.shielded_vms / self.total_vms) * 100

    @property
    def optimization_ratio(self) -> float:
        """Get optimization ratio percentage"""
        if self.total_vms == 0:
            return 0.0
        return (self.optimized_vms / self.total_vms) * 100

    @property
    def cost_efficiency_ratio(self) -> float:
        """Get cost efficiency ratio (preemptible + optimized instances)"""
        if self.total_vms == 0:
            return 0.0
        return ((self.preemptible_vms + self.optimized_vms) / self.total_vms) * 100

    @property
    def legacy_ratio(self) -> float:
        """Get percentage of VMs using legacy machine types"""
        if self.total_vms == 0:
            return 0.0
        return (self.legacy_machine_type_vms / self.total_vms) * 100

    @property
    def is_well_governed(self) -> bool:
        """Check if VMs are well governed"""
        return self.governance_score >= 80.0

    @property
    def has_critical_issues(self) -> bool:
        """Check if there are critical governance issues"""
        return self.vms_with_issues > 0 and self.governance_score < 60

    @property
    def governance_grade(self) -> str:
        """Get governance grade"""
        if self.governance_score >= 95:
            return "A"
        elif self.governance_score >= 85:
            return "B"
        elif self.governance_score >= 70:
            return "C"
        elif self.governance_score >= 60:
            return "D"
        else:
            return "F"

    @property
    def security_maturity(self) -> str:
        """Assess security maturity based on Shielded VM coverage"""
        if self.shielded_vm_coverage >= 90:
            return "Advanced"
        elif self.shielded_vm_coverage >= 70:
            return "Intermediate"
        elif self.shielded_vm_coverage >= 50:
            return "Basic"
        else:
            return "Minimal"

    def __str__(self) -> str:
        status_emoji = "✅" if self.is_well_governed else "⚠️" if self.governance_score >= 60 else "❌"
        security_icon = {"Advanced": "🛡️", "Intermediate": "🔒", "Basic": "🔐", "Minimal": "⚠️"}.get(
            self.security_maturity, "❓")
        return f"{status_emoji} {security_icon} {self.application}: {self.governance_score:.1f}% governed ({self.vms_with_issues} issues, {self.total_vms} VMs) - Grade {self.governance_grade}"


# Fix for GCPComputeComplianceSummary computed fields
from pydantic import computed_field


class GCPComputeComplianceSummary(BaseModel):
    """
    GCP Compute Compliance Summary by Application

    Enhanced compliance summary covering all compute services including
    Compute Engine VMs, GKE, Cloud Run, Cloud Functions, and App Engine.
    """
    application: str = Field(..., description="Application name")

    # Core compute resource counts
    total_compute_resources: int = Field(default=0, description="Total compute resources")
    compute_instances: int = Field(default=0, description="Number of Compute Engine instances")
    gke_nodes: int = Field(default=0, description="Number of GKE nodes")
    cloud_functions: int = Field(default=0, description="Number of Cloud Functions")
    cloud_run_services: int = Field(default=0, description="Number of Cloud Run services")
    app_engine_services: int = Field(default=0, description="Number of App Engine services")

    # Security and compliance metrics
    secure_compute_resources: int = Field(default=0, description="Securely configured resources")
    encrypted_resources: int = Field(default=0, description="Resources with encryption")
    resources_with_issues: int = Field(default=0, description="Resources with security issues")

    # Primary compliance scoring
    compute_compliance_score: float = Field(default=0.0, description="Overall compliance score (0-100)")
    compute_compliance_status: str = Field(default="Unknown", description="Overall compliance status")

    # VM-specific fields for backward compatibility
    total_instances: int = Field(default=0, description="Total VM instances")
    running_instances: int = Field(default=0, description="Running VM instances")
    stopped_instances: int = Field(default=0, description="Stopped VM instances")
    encrypted_instances: int = Field(default=0, description="Encrypted VM instances")
    properly_configured_instances: int = Field(default=0, description="Properly configured instances")
    instances_with_issues: int = Field(default=0, description="Instances with issues")

    # Additional scoring metrics
    security_score: float = Field(default=0.0, description="Security score (0-100)")
    optimization_score: float = Field(default=0.0, description="Optimization score (0-100)")
    compliance_status: str = Field(default="Unknown", description="Compliance status")

    @computed_field
    @property
    def is_compute_compliant(self) -> bool:
        """Check if compute resources are compliant (>= 90% score)"""
        return self.compute_compliance_score >= 90.0

    @computed_field
    @property
    def compute_compliance_grade(self) -> str:
        """Get compliance grade based on score"""
        if self.compute_compliance_score >= 95:
            return "A+"
        elif self.compute_compliance_score >= 90:
            return "A"
        elif self.compute_compliance_score >= 85:
            return "B"
        elif self.compute_compliance_score >= 80:
            return "C"
        elif self.compute_compliance_score >= 70:
            return "D"
        else:
            return "F"

    @computed_field
    @property
    def has_critical_compute_issues(self) -> bool:
        """Check if there are critical compute issues (< 70% score)"""
        return self.compute_compliance_score < 70.0

    @computed_field
    @property
    def security_coverage(self) -> float:
        """Calculate security coverage percentage"""
        if self.total_compute_resources == 0:
            return 100.0
        return (self.secure_compute_resources / self.total_compute_resources) * 100

    @computed_field
    @property
    def encryption_coverage(self) -> float:
        """Calculate encryption coverage percentage"""
        if self.total_compute_resources == 0:
            return 100.0
        return (self.encrypted_resources / self.total_compute_resources) * 100

    @computed_field
    @property
    def compute_diversity_score(self) -> str:
        """Calculate compute service diversity"""
        services_used = sum([
            1 if self.compute_instances > 0 else 0,
            1 if self.gke_nodes > 0 else 0,
            1 if self.cloud_functions > 0 else 0,
            1 if self.cloud_run_services > 0 else 0,
            1 if self.app_engine_services > 0 else 0
        ])

        if services_used >= 4:
            return "Highly Diverse"
        elif services_used >= 2:
            return "Moderately Diverse"
        elif services_used == 1:
            return "Single Service"
        else:
            return "No Services"
