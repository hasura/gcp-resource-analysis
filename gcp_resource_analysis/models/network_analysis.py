#!/usr/bin/env python3
"""
GCP Network Analysis Models

Pydantic models for GCP network and VPC analysis results.
Equivalent to Azure's network analysis models but adapted for GCP services.

Models included:
- GCPNetworkResource: VPC network security analysis
- GCPFirewallRule: Firewall rule detailed analysis
- GCPSSLCertificateResult: SSL certificate security analysis
- GCPNetworkTopologyResult: Network topology analysis
- GCPNetworkOptimizationResult: Network resource optimization
- GCPNetworkComplianceSummary: Network compliance summary

These models follow the same structure and naming patterns as the existing
GCP storage and compute models for consistency.
"""

from pydantic import BaseModel, Field


class GCPNetworkResource(BaseModel):
    """
    GCP VPC Network Resource Security Analysis Result

    Equivalent to Azure NetworkResource but for GCP VPC networks, subnets,
    routers, and other network infrastructure components.

    Attributes:
        application: Application or service name from labels/tags
        network_resource: Name of the network resource
        network_resource_type: Type of network resource (VPC, Subnet, Router, etc.)
        security_findings: Security configuration findings
        compliance_risk: Risk level assessment
        resource_group: GCP project ID
        location: GCP region/zone
        additional_details: Additional resource-specific details
        resource_id: Full GCP resource identifier
    """
    application: str = Field(..., description="Application name from resource labels")
    network_resource: str = Field(..., description="Network resource name")
    network_resource_type: str = Field(..., description="Type of network resource")
    security_findings: str = Field(..., description="Security configuration findings")
    compliance_risk: str = Field(..., description="Risk level assessment")
    resource_group: str = Field(..., description="GCP project ID")
    location: str = Field(..., description="GCP region or zone")
    additional_details: str = Field(..., description="Additional resource details")
    resource_id: str = Field(..., description="Full GCP resource identifier")

    @property
    def is_high_risk(self) -> bool:
        """Check if the network resource is high risk"""
        return self.compliance_risk.lower().startswith('high')

    @property
    def is_vpc_network(self) -> bool:
        """Check if this is a VPC network resource"""
        return 'VPC' in self.network_resource_type or 'Network' in self.network_resource_type

    @property
    def is_subnetwork(self) -> bool:
        """Check if this is a subnetwork resource"""
        return 'Subnet' in self.network_resource_type

    def __str__(self) -> str:
        return (f"🌐 {self.network_resource} ({self.network_resource_type})\n"
                f"   🏷️  App: {self.application}\n"
                f"   🔍 Findings: {self.security_findings}\n"
                f"   ⚠️  Risk: {self.compliance_risk}\n"
                f"   📍 Location: {self.location}")


class GCPFirewallRule(BaseModel):
    """
    GCP Firewall Rule Detailed Analysis Result

    Equivalent to Azure NSGRule but for GCP firewall rules.
    Provides detailed security analysis of individual firewall rules.

    Attributes:
        application: Application name from resource labels
        firewall_name: Name of the firewall rule
        rule_name: Specific rule name (same as firewall_name for GCP)
        action: Allow or Deny action
        direction: Ingress or Egress direction
        priority: Rule priority (lower numbers = higher priority)
        protocol: Network protocol (TCP, UDP, ICMP, etc.)
        source_ranges: Source IP ranges or tags
        target_tags: Target tags for rule application
        port_ranges: Destination port ranges
        risk_level: Security risk assessment
        resource_group: GCP project ID
        resource_id: Full GCP resource identifier
    """
    application: str = Field(..., description="Application name from resource labels")
    firewall_name: str = Field(..., description="Firewall rule name")
    rule_name: str = Field(..., description="Rule name (same as firewall name)")
    action: str = Field(default="Allow", description="Allow or Deny action")
    direction: str = Field(default="Ingress", description="Ingress or Egress direction")
    priority: int = Field(default=1000, description="Rule priority")
    protocol: str = Field(..., description="Network protocol")
    source_ranges: str = Field(..., description="Source IP ranges or tags")
    target_tags: str = Field(..., description="Target tags for rule application")
    port_ranges: str = Field(..., description="Destination port ranges")
    risk_level: str = Field(..., description="Security risk assessment")
    resource_group: str = Field(..., description="GCP project ID")
    resource_id: str = Field(..., description="Full GCP resource identifier")

    @property
    def is_high_risk(self) -> bool:
        """Check if the firewall rule is high risk"""
        return self.risk_level.lower().startswith('high')

    @property
    def allows_any_source(self) -> bool:
        """Check if rule allows traffic from any source (0.0.0.0/0)"""
        return '0.0.0.0/0' in self.source_ranges

    @property
    def is_high_priority(self) -> bool:
        """Check if rule has high priority (<= 100)"""
        return self.priority <= 100

    @property
    def allows_ssh_rdp(self) -> bool:
        """Check if rule allows SSH (22) or RDP (3389) access"""
        return ('22' in self.port_ranges or '3389' in self.port_ranges) and self.action.upper() == 'ALLOW'

    def __str__(self) -> str:
        return (f"🛡️ {self.firewall_name}\n"
                f"   🏷️  App: {self.application}\n"
                f"   🎯 Action: {self.action} {self.direction}\n"
                f"   🔢 Priority: {self.priority}\n"
                f"   🌐 Protocol: {self.protocol}\n"
                f"   📥 Source: {self.source_ranges}\n"
                f"   🎯 Targets: {self.target_tags}\n"
                f"   🔌 Ports: {self.port_ranges}\n"
                f"   ⚠️  Risk: {self.risk_level}")


class GCPSSLCertificateResult(BaseModel):
    """
    GCP SSL Certificate Security Analysis Result

    Equivalent to Azure CertificateAnalysisResult but for GCP SSL certificates,
    load balancer configurations, and HTTPS proxies.

    Attributes:
        application: Application name from resource labels
        resource_name: Name of the certificate or proxy resource
        resource_type: Type of SSL/certificate resource
        certificate_count: Number of certificates (for proxies/load balancers)
        ssl_policy_details: SSL policy configuration details
        compliance_status: Compliance assessment
        security_risk: Security risk level
        listener_details: Additional certificate/proxy details
        resource_group: GCP project ID
        location: GCP region
        resource_id: Full GCP resource identifier
    """
    application: str = Field(..., description="Application name from resource labels")
    resource_name: str = Field(..., description="Certificate or proxy resource name")
    resource_type: str = Field(..., description="Type of SSL/certificate resource")
    certificate_count: int = Field(default=0, description="Number of certificates")
    ssl_policy_details: str = Field(..., description="SSL policy configuration details")
    compliance_status: str = Field(..., description="Compliance assessment")
    security_risk: str = Field(..., description="Security risk level")
    listener_details: str = Field(..., description="Additional certificate/proxy details")
    resource_group: str = Field(..., description="GCP project ID")
    location: str = Field(..., description="GCP region")
    resource_id: str = Field(..., description="Full GCP resource identifier")

    @property
    def is_high_risk(self) -> bool:
        """Check if the SSL certificate configuration is high risk"""
        return self.security_risk.lower().startswith('high')

    @property
    def is_managed_certificate(self) -> bool:
        """Check if using Google-managed certificates"""
        return 'Google-managed' in self.ssl_policy_details or 'MANAGED' in self.resource_type

    @property
    def has_multiple_certificates(self) -> bool:
        """Check if resource has multiple certificates"""
        return self.certificate_count > 1

    @property
    def is_compliant(self) -> bool:
        """Check if SSL configuration is compliant"""
        return 'Compliant' in self.compliance_status

    def __str__(self) -> str:
        return (f"🔐 {self.resource_name} ({self.resource_type})\n"
                f"   🏷️  App: {self.application}\n"
                f"   📜 Certificates: {self.certificate_count}\n"
                f"   🔒 SSL Policy: {self.ssl_policy_details}\n"
                f"   ✅ Status: {self.compliance_status}\n"
                f"   ⚠️  Risk: {self.security_risk}\n"
                f"   📍 Location: {self.location}")


class GCPNetworkTopologyResult(BaseModel):
    """
    GCP Network Topology Analysis Result

    Equivalent to Azure NetworkTopologyResult but for GCP network topology,
    including VPC peering, VPN connections, and load balancer configurations.

    Attributes:
        application: Application name from resource labels
        network_resource: Name of the network resource
        topology_type: Type of network topology (VPC, Route, Load Balancer, etc.)
        network_configuration: Network configuration details
        configuration_risk: Risk level of the configuration
        security_implications: Security implications of the topology
        resource_group: GCP project ID
        location: GCP region/zone
        resource_id: Full GCP resource identifier
    """
    application: str = Field(..., description="Application name from resource labels")
    network_resource: str = Field(..., description="Network resource name")
    topology_type: str = Field(..., description="Type of network topology")
    network_configuration: str = Field(..., description="Network configuration details")
    configuration_risk: str = Field(..., description="Risk level of the configuration")
    security_implications: str = Field(..., description="Security implications of the topology")
    resource_group: str = Field(..., description="GCP project ID")
    location: str = Field(..., description="GCP region/zone")
    resource_id: str = Field(..., description="Full GCP resource identifier")

    @property
    def is_high_risk(self) -> bool:
        """Check if the network topology is high risk"""
        return self.configuration_risk.lower().startswith('high')

    @property
    def is_external_facing(self) -> bool:
        """Check if topology is external facing"""
        topology_lower = self.topology_type.lower()
        config_lower = self.network_configuration.lower()
        return ('external' in topology_lower or
                'internet' in config_lower or
                'public' in config_lower)

    @property
    def has_vpn_connectivity(self) -> bool:
        """Check if topology includes VPN connectivity"""
        return 'VPN' in self.topology_type

    @property
    def has_load_balancer(self) -> bool:
        """Check if topology includes load balancing"""
        return 'Load Balancer' in self.topology_type

    def __str__(self) -> str:
        return (f"🌐 {self.network_resource}\n"
                f"   🏷️  App: {self.application}\n"
                f"   🏗️  Type: {self.topology_type}\n"
                f"   ⚙️  Config: {self.network_configuration}\n"
                f"   ⚠️  Risk: {self.configuration_risk}\n"
                f"   🔍 Implications: {self.security_implications}\n"
                f"   📍 Location: {self.location}")


class GCPNetworkOptimizationResult(BaseModel):
    """
    GCP Network Resource Optimization Analysis Result

    Equivalent to Azure ResourceOptimizationResult but for GCP network resources,
    focusing on cost optimization and performance improvements.

    Attributes:
        application: Application name from resource labels
        resource_name: Name of the network resource
        optimization_type: Type of optimization opportunity
        utilization_status: Current utilization status
        cost_optimization_potential: Cost optimization potential
        resource_details: Additional resource details
        resource_group: GCP project ID
        location: GCP region/zone
        resource_id: Full GCP resource identifier
    """
    application: str = Field(..., description="Application name from resource labels")
    resource_name: str = Field(..., description="Network resource name")
    optimization_type: str = Field(..., description="Type of optimization opportunity")
    utilization_status: str = Field(..., description="Current utilization status")
    cost_optimization_potential: str = Field(..., description="Cost optimization potential")
    resource_details: str = Field(..., description="Additional resource details")
    resource_group: str = Field(..., description="GCP project ID")
    location: str = Field(..., description="GCP region/zone")
    resource_id: str = Field(..., description="Full GCP resource identifier")

    @property
    def has_high_optimization_potential(self) -> bool:
        """Check if resource has high optimization potential"""
        return self.cost_optimization_potential.lower().startswith('high')

    @property
    def is_unused_resource(self) -> bool:
        """Check if resource is unused"""
        return ('Unused' in self.utilization_status or
                'unused' in self.cost_optimization_potential.lower())

    @property
    def needs_rightsizing(self) -> bool:
        """Check if resource needs rightsizing"""
        return ('underutilized' in self.utilization_status.lower() or
                'over-configured' in self.utilization_status.lower())

    @property
    def optimization_priority(self) -> str:
        """Get optimization priority level"""
        if self.has_high_optimization_potential:
            return "High"
        elif 'Medium' in self.cost_optimization_potential:
            return "Medium"
        else:
            return "Low"

    def __str__(self) -> str:
        return (f"⚡ {self.resource_name}\n"
                f"   🏷️  App: {self.application}\n"
                f"   🔧 Type: {self.optimization_type}\n"
                f"   📊 Utilization: {self.utilization_status}\n"
                f"   💰 Potential: {self.cost_optimization_potential}\n"
                f"   ℹ️  Details: {self.resource_details}\n"
                f"   📍 Location: {self.location}")


class GCPNetworkComplianceSummary(BaseModel):
    """
    GCP Network Compliance Summary by Application

    Equivalent to Azure NetworkComplianceSummary but for GCP network resources.
    Provides aggregated compliance metrics for network security.

    Attributes:
        application: Application name
        total_network_resources: Total number of network resources
        vpc_network_count: Number of VPC networks
        firewall_rule_count: Number of firewall rules
        ssl_certificate_count: Number of SSL certificates
        load_balancer_count: Number of load balancers
        resources_with_issues: Number of resources with security issues
        security_score: Overall security score (0-100)
        security_status: Overall security status description
    """
    application: str = Field(..., description="Application name")
    total_network_resources: int = Field(default=0, description="Total network resources")
    vpc_network_count: int = Field(default=0, description="Number of VPC networks")
    firewall_rule_count: int = Field(default=0, description="Number of firewall rules")
    ssl_certificate_count: int = Field(default=0, description="Number of SSL certificates")
    load_balancer_count: int = Field(default=0, description="Number of load balancers")
    resources_with_issues: int = Field(default=0, description="Resources with security issues")
    security_score: float = Field(default=0.0, description="Overall security score (0-100)")
    security_status: str = Field(default="Unknown", description="Overall security status")

    @property
    def compliance_percentage(self) -> float:
        """Calculate compliance percentage"""
        if self.total_network_resources == 0:
            return 100.0
        return ((self.total_network_resources - self.resources_with_issues) /
                self.total_network_resources * 100)

    @property
    def is_compliant(self) -> bool:
        """Check if application network is compliant (>= 80% compliance)"""
        return self.compliance_percentage >= 80.0

    @property
    def has_critical_issues(self) -> bool:
        """Check if application has critical network security issues"""
        return (self.resources_with_issues > 0 and
                self.compliance_percentage < 50.0)

    @property
    def status_emoji(self) -> str:
        """Get status emoji based on security score"""
        if self.security_score >= 90:
            return "🟢"
        elif self.security_score >= 70:
            return "🟡"
        else:
            return "🔴"

    def __str__(self) -> str:
        return (f"{self.status_emoji} {self.application} Network Security Summary\n"
                f"   📊 Total Resources: {self.total_network_resources}\n"
                f"   🌐 VPC Networks: {self.vpc_network_count}\n"
                f"   🛡️ Firewall Rules: {self.firewall_rule_count}\n"
                f"   🔐 SSL Certificates: {self.ssl_certificate_count}\n"
                f"   ⚖️ Load Balancers: {self.load_balancer_count}\n"
                f"   ⚠️  Issues: {self.resources_with_issues}\n"
                f"   🏆 Security Score: {self.security_score:.1f}%\n"
                f"   📈 Status: {self.security_status}")
