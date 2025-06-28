from .client import GCPResourceAnalysisClient

from .models import (
# Compute Governance Models
    GCPConfig,
    GCPComputeSecurityResult,
    GCPComputeOptimizationResult,
    GCPComputeResource,
    GCPComputeComplianceSummary,
)

from .gcp_network_analysis import GCPNetworkAnalysisQueries
from .gcp_storage_analysis import GCPStorageAnalysisQueries
from .gcp_compute_governance import GCPComputeGovernanceQueries
from .gcp_container_analysis import GCPContainerAnalysisQueries
from .gcp_iam_analysis import GCPIAMAnalysisQueries

__version__ = "1.0.11"
__author__ = "Kenneth Stott"
__email__ = "ken@promptql.io"

# Make key classes available at package level
__all__ = [
    # Core client and configuration
    'GCPResourceAnalysisClient',
    'GCPConfig',

    'GCPStorageAnalysisQueries',
    'GCPNetworkAnalysisQueries',
    'GCPComputeGovernanceQueries',
    'GCPContainerAnalysisQueries',
    'GCPIAMAnalysisQueries',

    'GCPComputeSecurityResult',
    'GCPComputeOptimizationResult',
    'GCPComputeResource',
    'GCPComputeComplianceSummary',

]

__description__ = "Python client for GCP Resource Analysis with comprehensive storage, network, and compute governance analysis including security assessment, cost optimization, and compliance reporting"

# Version history
__version_info__ = {
    "1.0.1": "Initial storage analysis",
    "1.0.2": "Enhanced with comprehensive network analysis and optimization",
    "1.0.3": "Major refactor: Comprehensive storage analysis with access control, backup assessment, cost optimization",
    "1.0.4": "Added comprehensive compute governance analysis: security, sizing optimization, and compliance"
}

# Quick start example
__example_usage__ = '''
from gcp_resource_analysis import GCPResourceAnalysisClient

# Initialize client
client = GCPResourceAnalysisClient()

# === STORAGE ANALYSIS ===

# Comprehensive storage security analysis
storage_results = client.query_storage_analysis()
print(f"Found {len(storage_results)} storage resources")

# Storage access control analysis
access_results = client.query_storage_access_control()
high_risk_access = [result for result in access_results if result.is_high_risk]
print(f"Found {len(high_risk_access)} high-risk access configurations")

# Storage backup analysis
backup_results = client.query_storage_backup_analysis()
no_backup = [result for result in backup_results if not result.has_backup_configured]
print(f"Found {len(no_backup)} resources without proper backup")

# Storage cost optimization
storage_optimization = client.query_storage_optimization()
high_savings = [result for result in storage_optimization if result.has_high_optimization_potential]
print(f"Found {len(high_savings)} high-cost optimization opportunities")

# Storage compliance summary
storage_summary = client.get_storage_compliance_summary()
critical_apps = [s for s in storage_summary if s.has_critical_issues]
print(f"Found {len(critical_apps)} applications with critical storage issues")

# === COMPUTE GOVERNANCE ANALYSIS ===

# Compute security analysis
compute_security = client.query_compute_security()
high_risk_instances = [instance for instance in compute_security if instance.is_high_risk]
unencrypted_instances = [instance for instance in compute_security if not instance.is_encrypted]
print(f"Found {len(high_risk_instances)} high-risk instances, {len(unencrypted_instances)} unencrypted instances")

# Compute optimization analysis
compute_optimization = client.query_compute_optimization()
stopped_instances = [instance for instance in compute_optimization if instance.is_stopped_but_allocated]
legacy_instances = [instance for instance in compute_optimization if instance.is_legacy_size]
high_cost_savings = [instance for instance in compute_optimization if instance.has_high_optimization_potential]
print(f"Found {len(stopped_instances)} stopped instances, {len(legacy_instances)} legacy sizes, {len(high_cost_savings)} high optimization potential")

# Compute governance summary
compute_summary = client.get_compute_governance_summary()
critical_compute_apps = [s for s in compute_summary if s.has_critical_issues]
print(f"Found {len(critical_compute_apps)} applications with critical compute governance issues")

# === NETWORK ANALYSIS ===

# Network security analysis  
network_results = client.query_network_analysis()
print(f"Found {len(network_results)} network resources")

# Firewall detailed analysis
firewall_rules = client.query_firewall_detailed()
high_risk = [rule for rule in firewall_rules if rule.is_high_risk]
admin_exposed = [rule for rule in firewall_rules if rule.is_internet_facing and rule.allows_admin_ports]
print(f"Found {len(high_risk)} high-risk firewall rules, {len(admin_exposed)} expose admin ports")

# Network topology analysis
topology_results = client.query_network_topology()
high_risk_topology = [topo for topo in topology_results if "High" in topo.get("ConfigurationRisk", "")]
print(f"Found {len(high_risk_topology)} high-risk network topology configurations")

# Network resource optimization
network_optimization = client.query_resource_optimization()
unused_network = [res for res in network_optimization if "Unused" in res.get("UtilizationStatus", "")]
print(f"Found {len(unused_network)} unused network resources for cost savings")

# Network compliance summary
network_summary = client.get_network_compliance_summary()
critical_network = [s for s in network_summary if s.has_critical_issues]
print(f"Found {len(critical_network)} applications with critical network issues")

# === EXAMPLES USING PYDANTIC PROPERTIES ===

# Filter storage resources by encryption strength
strong_encryption = [r for r in storage_results if r.encryption_strength == "Strong"]
weak_encryption = [r for r in storage_results if r.encryption_strength == "Weak"]

# Filter instances by governance criteria
production_instances = [instance for instance in compute_security if instance.is_running and instance.is_encrypted]
cost_waste_instances = [instance for instance in compute_optimization if instance.is_stopped_but_allocated or instance.is_legacy_size]
security_gaps = [instance for instance in compute_security if not instance.has_security_extensions]

# Filter network rules by specific risks
internet_admin = [rule for rule in firewall_rules if rule.is_internet_facing and rule.allows_admin_ports]
high_priority_issues = [rule for rule in firewall_rules if rule.is_high_risk and rule.priority < 1000]

        print(f"""
📊 COMPREHENSIVE ANALYSIS SUMMARY:
Storage: {len(strong_encryption)} strong encryption, {len(weak_encryption)} weak encryption
Compute: {len(production_instances)} production-ready, {len(cost_waste_instances)} cost waste, {len(security_gaps)} security gaps  
Network: {len(internet_admin)} critical admin exposure, {len(high_priority_issues)} high-priority issues
        """)
'''
