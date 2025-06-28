#!/usr/bin/env python3
"""
GCP Compute Engine Governance Analysis

Provides comprehensive analysis of GCP Compute Engine instances including:
- Security configuration analysis
- Cost optimization recommendations
- Configuration management analysis
- Patch compliance analysis
- Governance scoring and reporting

Equivalent to Azure Resource Graph VM Governance analysis but adapted for GCP.
"""

import logging
from datetime import datetime
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class GCPComputeGovernanceQueries:
    """
    GCP Compute Engine governance analysis queries and asset types
    Equivalent to Azure VMGovernanceQueries but for GCP Compute Engine
    """

    @staticmethod
    def get_compute_security_asset_types() -> List[str]:
        """Get asset types for Compute Engine security analysis"""
        return [
            "compute.googleapis.com/Instance",
            "compute.googleapis.com/Disk",
        ]

    @staticmethod
    def get_compute_optimization_asset_types() -> List[str]:
        """Get asset types for cost optimization analysis"""
        return [
            "compute.googleapis.com/Instance",
            "compute.googleapis.com/InstanceTemplate",
            "compute.googleapis.com/InstanceGroupManager"
        ]


class GCPComputeSecurityAnalyzer:
    """
    Analyzer for GCP Compute Engine security configurations
    Equivalent to Azure VM security analysis
    """

    @staticmethod
    def analyze_vm_security_comprehensive(asset_type: str, instance_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Comprehensive security analysis of GCP Compute Engine instance

        Args:
            asset_type: The GCP asset type
            instance_data: Instance configuration data

        Returns:
            Dictionary with security analysis results
        """
        try:
            if not instance_data:
                return GCPComputeSecurityAnalyzer._get_default_security_analysis()

            # Analyze disk encryption
            disk_encryption = GCPComputeSecurityAnalyzer._analyze_disk_encryption(instance_data)

            # Analyze security features
            security_config = GCPComputeSecurityAnalyzer._analyze_security_configuration(instance_data)

            # Determine overall security risk
            security_risk = GCPComputeSecurityAnalyzer._assess_security_risk(
                disk_encryption, security_config, instance_data)

            # Determine compliance status
            compliance_status = GCPComputeSecurityAnalyzer._assess_compliance_status(security_risk)

            # Generate security findings
            security_findings = GCPComputeSecurityAnalyzer._generate_security_findings(
                disk_encryption, security_config, instance_data)

            # Generate VM details
            vm_details = GCPComputeSecurityAnalyzer._generate_vm_details(instance_data)

            return {
                'disk_encryption': disk_encryption,
                'security_configuration': security_config,
                'security_findings': security_findings,
                'security_risk': security_risk,
                'compliance_status': compliance_status,
                'vm_details': vm_details
            }

        except Exception as e:
            logger.warning(f"Failed to analyze VM security: {e}")
            return GCPComputeSecurityAnalyzer._get_default_security_analysis()

    @staticmethod
    def _analyze_disk_encryption(instance_data: Dict[str, Any]) -> str:
        """Analyze disk encryption configuration"""
        try:
            disks = instance_data.get('disks', [])

            encryption_types = set()
            for disk in disks:
                disk_encryption_key = disk.get('diskEncryptionKey', {})

                if disk_encryption_key.get('kmsKeyName'):
                    encryption_types.add('Customer Managed Key (CMEK)')
                elif disk_encryption_key.get('sha256'):
                    encryption_types.add('Customer Supplied Key (CSEK)')
                else:
                    encryption_types.add('Google Managed Key')

            if 'Customer Managed Key (CMEK)' in encryption_types:
                return 'Customer Managed Key (CMEK) - Highest Security'
            elif 'Customer Supplied Key (CSEK)' in encryption_types:
                return 'Customer Supplied Key (CSEK) - High Security'
            elif len(encryption_types) == 1 and 'Google Managed Key' in encryption_types:
                return 'Google Managed Key - Standard Security'
            else:
                return 'Mixed Encryption Types - Review Required'

        except Exception as e:
            logger.warning(f"Failed to analyze disk encryption: {e}")
            return 'Encryption Analysis Failed'

    @staticmethod
    def _analyze_security_configuration(instance_data: Dict[str, Any]) -> str:
        """Analyze security configuration features"""
        try:
            security_features = []

            # Check Shielded VM features
            shielded_instance_config = instance_data.get('shieldedInstanceConfig', {})
            if shielded_instance_config.get('enableVtpm', False):
                security_features.append('vTPM Enabled')
            if shielded_instance_config.get('enableIntegrityMonitoring', False):
                security_features.append('Integrity Monitoring')
            if shielded_instance_config.get('enableSecureBoot', False):
                security_features.append('Secure Boot')

            # Check OS Login
            metadata = instance_data.get('metadata', {})
            metadata_items = metadata.get('items', [])

            for item in metadata_items:
                if item.get('key') == 'enable-oslogin' and item.get('value') == 'TRUE':
                    security_features.append('OS Login Enabled')
                elif item.get('key') == 'block-project-ssh-keys' and item.get('value') == 'TRUE':
                    security_features.append('Project SSH Keys Blocked')

            # Check for security agents in startup scripts or metadata
            startup_script = next((item.get('value', '') for item in metadata_items
                                   if item.get('key') == 'startup-script'), '')

            if 'google-cloud-ops-agent' in startup_script.lower():
                security_features.append('Cloud Ops Agent')
            if 'cloud-security-scanner' in startup_script.lower():
                security_features.append('Security Scanner')

            if security_features:
                return 'Security Features: ' + ', '.join(security_features)
            else:
                return 'Basic Security Configuration - No Advanced Features'

        except Exception as e:
            logger.warning(f"Failed to analyze security configuration: {e}")
            return 'Security Configuration Analysis Failed'

    @staticmethod
    def _assess_security_risk(disk_encryption: str, security_config: str, instance_data: Dict[str, Any]) -> str:
        """Assess overall security risk level"""
        try:
            risk_factors = []

            # Encryption risk assessment
            if 'Google Managed Key' in disk_encryption and 'Customer' not in disk_encryption:
                risk_factors.append('Standard encryption only')

            # Security configuration risk assessment
            if 'Basic Security Configuration' in security_config:
                risk_factors.append('No advanced security features')

            # Network configuration risk assessment
            network_interfaces = instance_data.get('networkInterfaces', [])
            has_external_ip = any(
                ni.get('accessConfigs', []) for ni in network_interfaces
            )

            if has_external_ip:
                risk_factors.append('External IP assigned')

            # Machine type risk assessment
            machine_type = instance_data.get('machineType', '').split('/')[-1]
            if machine_type.startswith('f1-') or machine_type.startswith('g1-'):
                risk_factors.append('Legacy machine type')

            # Status risk assessment
            status = instance_data.get('status', '')
            if status not in ['RUNNING', 'TERMINATED']:
                risk_factors.append('Unusual instance state')

            # Determine risk level
            if len(risk_factors) >= 3:
                return f"High - Multiple security concerns: {', '.join(risk_factors[:3])}"
            elif len(risk_factors) >= 1:
                return f"Medium - Security improvements needed: {', '.join(risk_factors[:2])}"
            else:
                return "Low - Good security configuration"

        except Exception as e:
            logger.warning(f"Failed to assess security risk: {e}")
            return "Unknown - Risk assessment failed"

    @staticmethod
    def _assess_compliance_status(security_risk: str) -> str:
        """Assess compliance status based on security risk"""
        if security_risk.startswith('High'):
            return 'Non-Compliant'
        elif security_risk.startswith('Medium'):
            return 'Needs Review'
        elif security_risk.startswith('Low'):
            return 'Compliant'
        else:
            return 'Review Required'

    @staticmethod
    def _generate_security_findings(disk_encryption: str, security_config: str,
                                    instance_data: Dict[str, Any]) -> str:
        """Generate security findings summary"""
        try:
            findings = []

            # Encryption findings
            if 'Customer Managed' in disk_encryption:
                findings.append('Advanced encryption configured')
            elif 'Google Managed' in disk_encryption:
                findings.append('Standard encryption in use')

            # Security features findings
            if 'vTPM Enabled' in security_config:
                findings.append('Shielded VM features active')
            elif 'Basic Security' in security_config:
                findings.append('Limited security features enabled')

            # Network findings
            network_interfaces = instance_data.get('networkInterfaces', [])
            if not any(ni.get('accessConfigs', []) for ni in network_interfaces):
                findings.append('Private IP only - good network security')

            return '; '.join(findings) if findings else 'Standard security configuration'

        except Exception as e:
            logger.warning(f"Failed to generate security findings: {e}")
            return 'Security findings analysis failed'

    @staticmethod
    def _generate_vm_details(instance_data: Dict[str, Any]) -> str:
        """Generate VM details summary"""
        try:
            details = []

            # Machine type
            machine_type = instance_data.get('machineType', '').split('/')[-1]
            details.append(f"Machine Type: {machine_type}")

            # Zone
            zone = instance_data.get('zone', '').split('/')[-1]
            details.append(f"Zone: {zone}")

            # Scheduling
            scheduling = instance_data.get('scheduling', {})
            if scheduling.get('preemptible', False):
                details.append("Preemptible Instance")

            # Boot disk
            boot_disk = next((disk for disk in instance_data.get('disks', [])
                              if disk.get('boot', False)), {})
            if boot_disk:
                boot_disk_name = boot_disk.get('source', '').split('/')[-1]
                details.append(f"Boot Disk: {boot_disk_name}")

            return ' | '.join(details)

        except Exception as e:
            logger.warning(f"Failed to generate VM details: {e}")
            return 'VM details unavailable'

    @staticmethod
    def _get_default_security_analysis() -> Dict[str, str]:
        """Return default security analysis when data is unavailable"""
        return {
            'disk_encryption': 'Analysis Failed',
            'security_configuration': 'Configuration Unknown',
            'security_findings': 'Analysis incomplete',
            'security_risk': 'Unknown - Manual review required',
            'compliance_status': 'Review Required',
            'vm_details': 'Instance details unavailable'
        }


class GCPComputeOptimizationAnalyzer:
    """
    Analyzer for GCP Compute Engine cost optimization
    Equivalent to Azure VM optimization analysis
    """

    @staticmethod
    def analyze_vm_optimization_comprehensive(asset_type: str, instance_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive optimization analysis of GCP Compute Engine instance

        Args:
            asset_type: The GCP asset type
            instance_data: Instance configuration data

        Returns:
            Dictionary with optimization analysis results
        """
        try:
            if not instance_data:
                return GCPComputeOptimizationAnalyzer._get_default_optimization_analysis()

            machine_type = instance_data.get('machineType', '').split('/')[-1]
            machine_type_category = GCPComputeOptimizationAnalyzer._categorize_machine_type(machine_type)

            scheduling_config = GCPComputeOptimizationAnalyzer._analyze_scheduling_configuration(instance_data)
            utilization_status = GCPComputeOptimizationAnalyzer._analyze_utilization_status(instance_data)
            optimization_potential = GCPComputeOptimizationAnalyzer._assess_optimization_potential(
                machine_type, instance_data)
            optimization_recommendation = GCPComputeOptimizationAnalyzer._generate_optimization_recommendation(
                machine_type, instance_data, optimization_potential)
            estimated_cost = GCPComputeOptimizationAnalyzer._estimate_monthly_cost(machine_type)
            days_running = GCPComputeOptimizationAnalyzer._calculate_days_running(instance_data)
            cud_status = GCPComputeOptimizationAnalyzer._analyze_committed_use_discount_opportunity(instance_data)
            preemptible_suitability = GCPComputeOptimizationAnalyzer._analyze_preemptible_suitability(instance_data)

            return {
                'machine_type_category': machine_type_category,
                'scheduling_configuration': scheduling_config,
                'utilization_status': utilization_status,
                'optimization_potential': optimization_potential,
                'optimization_recommendation': optimization_recommendation,
                'estimated_monthly_cost': estimated_cost,
                'days_running': days_running,
                'committed_use_discount': cud_status,
                'preemptible_suitable': preemptible_suitability
            }

        except Exception as e:
            logger.warning(f"Failed to analyze VM optimization: {e}")
            return GCPComputeOptimizationAnalyzer._get_default_optimization_analysis()

    @staticmethod
    def _categorize_machine_type(machine_type: str) -> str:
        """Categorize GCP machine type"""
        if machine_type.startswith('n1-'):
            return 'Legacy - N1 Series'
        elif machine_type.startswith('n2-'):
            return 'General Purpose - N2 Series'
        elif machine_type.startswith('n2d-'):
            return 'General Purpose - N2D AMD Series'
        elif machine_type.startswith('c2-'):
            return 'Compute Optimized - C2 Series'
        elif machine_type.startswith('c2d-'):
            return 'Compute Optimized - C2D AMD Series'
        elif machine_type.startswith('m1-'):
            return 'Memory Optimized - M1 Series'
        elif machine_type.startswith('m2-'):
            return 'Memory Optimized - M2 Series'
        elif machine_type.startswith('e2-'):
            return 'Cost Optimized - E2 Series'
        elif machine_type.startswith('t2d-'):
            return 'Shared Core - T2D Series'
        elif machine_type.startswith('f1-') or machine_type.startswith('g1-'):
            return 'Legacy - Deprecated Series'
        else:
            return 'Standard Machine Type'

    @staticmethod
    def _analyze_scheduling_configuration(instance_data: Dict[str, Any]) -> str:
        """Analyze instance scheduling configuration"""
        try:
            scheduling = instance_data.get('scheduling', {})
            config_details = []

            if scheduling.get('preemptible', False):
                config_details.append('Preemptible')
            else:
                config_details.append('Regular Instance')

            # Maintenance behavior
            on_host_maintenance = scheduling.get('onHostMaintenance', 'MIGRATE')
            config_details.append(f"Maintenance: {on_host_maintenance}")

            # Automatic restart
            automatic_restart = scheduling.get('automaticRestart', True)
            config_details.append(f"Auto-restart: {'Enabled' if automatic_restart else 'Disabled'}")

            return ' | '.join(config_details)

        except Exception as e:
            logger.warning(f"Failed to analyze scheduling configuration: {e}")
            return 'Scheduling configuration unknown'

    @staticmethod
    def _analyze_utilization_status(instance_data: Dict[str, Any]) -> str:
        """Analyze instance utilization status"""
        try:
            status = instance_data.get('status', 'UNKNOWN')

            if status == 'RUNNING':
                return 'Active - Currently Running'
            elif status == 'TERMINATED':
                return 'Stopped - Not Incurring Compute Costs'
            elif status == 'STOPPING':
                return 'Stopping - Transitioning to Stopped'
            elif status == 'PROVISIONING':
                return 'Starting - Provisioning Resources'
            elif status == 'STAGING':
                return 'Starting - Staging Instance'
            else:
                return f'Status: {status}'

        except Exception as e:
            logger.warning(f"Failed to analyze utilization status: {e}")
            return 'Utilization status unknown'

    @staticmethod
    def _assess_optimization_potential(machine_type: str, instance_data: Dict[str, Any]) -> str:
        """Assess cost optimization potential"""
        try:
            potential_factors = []

            # Machine type optimization
            if machine_type.startswith('n1-'):
                potential_factors.append('Legacy machine type - upgrade to N2')
            elif machine_type.startswith('f1-') or machine_type.startswith('g1-'):
                potential_factors.append('Deprecated machine type - immediate upgrade needed')

            # Preemptible optimization
            scheduling = instance_data.get('scheduling', {})
            if not scheduling.get('preemptible', False):
                potential_factors.append('Consider preemptible for cost savings')

            # Instance status optimization
            status = instance_data.get('status', '')
            if status == 'TERMINATED':
                potential_factors.append('Instance stopped - consider deletion if not needed')

            # Resource sizing
            if 'standard-' in machine_type and '-96' in machine_type:
                potential_factors.append('Very large instance - verify resource requirements')

            if len(potential_factors) >= 2:
                return f"High - Multiple optimization opportunities: {potential_factors[0]}"
            elif len(potential_factors) == 1:
                return f"Medium - {potential_factors[0]}"
            else:
                return "Low - Configuration appears optimized"

        except Exception as e:
            logger.warning(f"Failed to assess optimization potential: {e}")
            return "Unknown - Assessment failed"

    @staticmethod
    def _generate_optimization_recommendation(machine_type: str, instance_data: Dict[str, Any],
                                              optimization_potential: str) -> str:
        """Generate specific optimization recommendation"""
        try:
            if 'High' in optimization_potential:
                if machine_type.startswith('n1-'):
                    return 'Upgrade to N2 or E2 series for better price-performance'
                elif machine_type.startswith('f1-') or machine_type.startswith('g1-'):
                    return 'Migrate to E2 series - deprecated machine types no longer supported'
                elif instance_data.get('status') == 'TERMINATED':
                    return 'Delete instance if no longer needed to eliminate waste'
                else:
                    return 'Consider preemptible instances for up to 80% cost savings'
            elif 'Medium' in optimization_potential:
                scheduling = instance_data.get('scheduling', {})
                if not scheduling.get('preemptible', False):
                    return 'Evaluate preemptible instances for suitable workloads'
                else:
                    return 'Monitor resource utilization for rightsizing opportunities'
            else:
                return 'Configuration appears cost-optimized, monitor for changes'

        except Exception as e:
            logger.warning(f"Failed to generate optimization recommendation: {e}")
            return 'Manual review recommended'

    @staticmethod
    def _estimate_monthly_cost(machine_type: str) -> str:
        """Estimate monthly cost category based on machine type"""
        try:
            # Rough cost categorization based on machine type patterns
            if machine_type.startswith('f1-micro') or machine_type.startswith('g1-small'):
                return 'Very Low'
            elif machine_type.startswith('e2-') and ('micro' in machine_type or 'small' in machine_type):
                return 'Low'
            elif machine_type.startswith('e2-') or (machine_type.startswith('n1-') and 'standard-1' in machine_type):
                return 'Low-Medium'
            elif machine_type.startswith('n2-') and 'standard-4' in machine_type:
                return 'Medium'
            elif machine_type.startswith('c2-') or ('standard-8' in machine_type):
                return 'Medium-High'
            elif machine_type.startswith('m1-') or machine_type.startswith('m2-') or ('standard-16' in machine_type):
                return 'High'
            elif 'standard-32' in machine_type or 'standard-64' in machine_type or 'standard-96' in machine_type:
                return 'Very High'
            else:
                return 'Medium'

        except Exception as e:
            logger.warning(f"Failed to estimate monthly cost: {e}")
            return 'Unknown'

    @staticmethod
    def _calculate_days_running(instance_data: Dict[str, Any]) -> int:
        """Calculate approximate days the instance has been running"""
        try:
            creation_timestamp = instance_data.get('creationTimestamp')
            if creation_timestamp:
                # Parse ISO format timestamp
                creation_time = datetime.fromisoformat(creation_timestamp.replace('Z', '+00:00'))
                current_time = datetime.now(creation_time.tzinfo)
                days_old = (current_time - creation_time).days
                return max(0, days_old)
            else:
                return 0  # Default for instances without creation timestamp

        except Exception as e:
            logger.warning(f"Failed to calculate days running: {e}")
            return 0

    @staticmethod
    def _analyze_committed_use_discount_opportunity(instance_data: Dict[str, Any]) -> str:
        """Analyze Committed Use Discount opportunity"""
        try:
            # Check if instance is suitable for CUD based on consistent usage patterns
            status = instance_data.get('status', '')
            scheduling = instance_data.get('scheduling', {})

            if status == 'RUNNING' and not scheduling.get('preemptible', False):
                return 'CUD Opportunity - Consider 1-year or 3-year commitment for savings'
            elif scheduling.get('preemptible', False):
                return 'Not Applicable - Preemptible instances not eligible for CUD'
            else:
                return 'Evaluate Usage - CUD beneficial for consistent workloads'

        except Exception as e:
            logger.warning(f"Failed to analyze CUD opportunity: {e}")
            return 'Unknown'

    @staticmethod
    def _analyze_preemptible_suitability(instance_data: Dict[str, Any]) -> str:
        """Analyze suitability for preemptible instances"""
        try:
            scheduling = instance_data.get('scheduling', {})

            if scheduling.get('preemptible', False):
                return 'Already Preemptible - Achieving Maximum Cost Savings'

            # Check for factors that might make preemptible suitable
            machine_type = instance_data.get('machineType', '').split('/')[-1]

            # Batch processing workloads are often suitable
            labels = instance_data.get('labels', {})
            if any(label in ['batch', 'processing', 'analytics', 'dev', 'test']
                   for label in labels.values()):
                return 'Suitable - Workload appears fault-tolerant'

            # Development/test instances
            if any(env in str(labels).lower() for env in ['dev', 'test', 'staging']):
                return 'Suitable - Development/test workload'

            # Default assessment
            return 'Evaluate - Determine if workload can handle interruptions'

        except Exception as e:
            logger.warning(f"Failed to analyze preemptible suitability: {e}")
            return 'Unknown'

    @staticmethod
    def _get_default_optimization_analysis() -> Dict[str, Any]:
        """Return default optimization analysis when data is unavailable"""
        return {
            'machine_type_category': 'Unknown Machine Type',
            'scheduling_configuration': 'Configuration Unknown',
            'utilization_status': 'Status Unknown',
            'optimization_potential': 'Unknown - Manual review required',
            'optimization_recommendation': 'Manual analysis needed',
            'estimated_monthly_cost': 'Unknown',
            'days_running': 0,
            'committed_use_discount': 'Unknown',
            'preemptible_suitable': 'Unknown'
        }


class GCPComputeConfigurationAnalyzer:
    """
    Analyzer for GCP Compute Engine configuration management
    Equivalent to Azure VM Extensions analysis
    """

    @staticmethod
    def analyze_vm_configuration_comprehensive(asset_type: str, instance_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Comprehensive configuration analysis of GCP Compute Engine instance

        Args:
            asset_type: The GCP asset type
            instance_data: Instance configuration data

        Returns:
            List of configuration analysis results
        """
        try:
            if not instance_data:
                return [GCPComputeConfigurationAnalyzer._get_default_configuration_analysis()]

            configurations = []

            # Analyze OS Config Agent
            os_config_analysis = GCPComputeConfigurationAnalyzer._analyze_os_config_agent(instance_data)
            configurations.append(os_config_analysis)

            # Analyze Cloud Ops Agent (formerly Stackdriver)
            ops_agent_analysis = GCPComputeConfigurationAnalyzer._analyze_ops_agent(instance_data)
            configurations.append(ops_agent_analysis)

            # Analyze Security Agent configurations
            security_analysis = GCPComputeConfigurationAnalyzer._analyze_security_agents(instance_data)
            configurations.extend(security_analysis)

            return configurations

        except Exception as e:
            logger.warning(f"Failed to analyze VM configuration: {e}")
            return [GCPComputeConfigurationAnalyzer._get_default_configuration_analysis()]

    @staticmethod
    def _analyze_os_config_agent(instance_data: Dict[str, Any]) -> Dict[str, str]:
        """Analyze OS Config agent configuration"""
        try:
            metadata = instance_data.get('metadata', {})
            metadata_items = metadata.get('items', [])

            # Check for OS Config agent
            enable_os_config = next((item.get('value', 'FALSE')
                                     for item in metadata_items
                                     if item.get('key') == 'enable-osconfig'), 'FALSE')

            if enable_os_config.upper() == 'TRUE':
                configuration_status = 'Enabled'
                security_importance = 'Important'
                compliance_impact = 'Medium - OS patching and configuration management'
            else:
                configuration_status = 'Not Configured'
                security_importance = 'Important'
                compliance_impact = 'High - No automated patch management'

            return {
                'configuration_type': 'OS Config Agent',
                'configuration_name': 'Google Cloud OS Config',
                'configuration_category': 'Management',
                'configuration_status': configuration_status,
                'installation_method': 'Metadata Configuration',
                'security_importance': security_importance,
                'compliance_impact': compliance_impact,
                'configuration_details': f'OS Config Agent: {configuration_status}'
            }

        except Exception as e:
            logger.warning(f"Failed to analyze OS Config agent: {e}")
            return GCPComputeConfigurationAnalyzer._get_default_configuration_analysis()

    @staticmethod
    def _analyze_ops_agent(instance_data: Dict[str, Any]) -> Dict[str, str]:
        """Analyze Cloud Ops agent configuration"""
        try:
            metadata = instance_data.get('metadata', {})
            metadata_items = metadata.get('items', [])

            # Check startup script for ops agent installation
            startup_script = next((item.get('value', '')
                                   for item in metadata_items
                                   if item.get('key') == 'startup-script'), '')

            # Check for ops agent installation patterns
            has_ops_agent = (
                    'google-cloud-ops-agent' in startup_script.lower() or
                    'stackdriver' in startup_script.lower() or
                    'google-fluentd' in startup_script.lower()
            )

            if has_ops_agent:
                configuration_status = 'Installed'
                security_importance = 'Important'
                compliance_impact = 'Low - Monitoring and logging configured'
            else:
                configuration_status = 'Not Installed'
                security_importance = 'Important'
                compliance_impact = 'Medium - Limited monitoring and logging'

            return {
                'configuration_type': 'Cloud Ops Agent',
                'configuration_name': 'Google Cloud Operations Suite Agent',
                'configuration_category': 'Monitoring',
                'configuration_status': configuration_status,
                'installation_method': 'Startup Script',
                'security_importance': security_importance,
                'compliance_impact': compliance_impact,
                'configuration_details': f'Ops Agent: {configuration_status}'
            }

        except Exception as e:
            logger.warning(f"Failed to analyze ops agent: {e}")
            return GCPComputeConfigurationAnalyzer._get_default_configuration_analysis()

    @staticmethod
    def _analyze_security_agents(instance_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Analyze security agent configurations"""
        try:
            configurations = []
            metadata = instance_data.get('metadata', {})
            metadata_items = metadata.get('items', [])

            startup_script = next((item.get('value', '')
                                   for item in metadata_items
                                   if item.get('key') == 'startup-script'), '')

            # Check for security scanning agents
            security_agents = {
                'Security Command Center Agent': 'scc-agent',
                'Container Analysis Scanner': 'container-analysis',
                'CIS Benchmark Scanner': 'cis-benchmark',
                'Vulnerability Scanner': 'vulnerability-scan'
            }

            for agent_name, agent_pattern in security_agents.items():
                has_agent = agent_pattern in startup_script.lower()

                if has_agent:
                    configuration_status = 'Active'
                    compliance_impact = 'Low - Security scanning enabled'
                else:
                    configuration_status = 'Not Configured'
                    compliance_impact = 'Medium - No automated security scanning'

                configurations.append({
                    'configuration_type': agent_name,
                    'configuration_name': agent_name,
                    'configuration_category': 'Security',
                    'configuration_status': configuration_status,
                    'installation_method': 'Startup Script',
                    'security_importance': 'Critical' if 'Scanner' in agent_name else 'Important',
                    'compliance_impact': compliance_impact,
                    'configuration_details': f'{agent_name}: {configuration_status}'
                })

            return configurations if configurations else [
                GCPComputeConfigurationAnalyzer._get_default_configuration_analysis()
            ]

        except Exception as e:
            logger.warning(f"Failed to analyze security agents: {e}")
            return [GCPComputeConfigurationAnalyzer._get_default_configuration_analysis()]

    @staticmethod
    def _get_default_configuration_analysis() -> Dict[str, str]:
        """Return default configuration analysis when data is unavailable"""
        return {
            'configuration_type': 'Configuration Analysis',
            'configuration_name': 'Unknown Configuration',
            'configuration_category': 'Unknown',
            'configuration_status': 'Analysis Failed',
            'installation_method': 'Unknown',
            'security_importance': 'Unknown',
            'compliance_impact': 'Unknown - Manual review required',
            'configuration_details': 'Configuration analysis failed'
        }


class GCPComputePatchComplianceAnalyzer:
    """
    Analyzer for GCP Compute Engine patch compliance
    Equivalent to Azure VM Patch Compliance analysis
    """

    @staticmethod
    def analyze_patch_compliance_comprehensive(asset_type: str, instance_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive patch compliance analysis of GCP Compute Engine instance

        Args:
            asset_type: The GCP asset type
            instance_data: Instance configuration data

        Returns:
            Dictionary with patch compliance analysis results
        """
        try:
            if not instance_data:
                return GCPComputePatchComplianceAnalyzer._get_default_patch_analysis()

            os_type = GCPComputePatchComplianceAnalyzer._determine_os_type(instance_data)
            os_config_status = GCPComputePatchComplianceAnalyzer._analyze_os_config_status(instance_data)
            patch_deployment_status = GCPComputePatchComplianceAnalyzer._analyze_patch_deployment(instance_data)
            patch_compliance_status = GCPComputePatchComplianceAnalyzer._assess_patch_compliance(
                os_config_status, patch_deployment_status)
            patch_risk = GCPComputePatchComplianceAnalyzer._assess_patch_risk(
                os_config_status, patch_deployment_status, instance_data)
            last_patch_time = GCPComputePatchComplianceAnalyzer._get_last_patch_time(instance_data)
            available_patches = GCPComputePatchComplianceAnalyzer._estimate_available_patches(
                os_config_status, instance_data)

            return {
                'os_type': os_type,
                'os_config_agent_status': os_config_status,
                'patch_deployment_status': patch_deployment_status,
                'patch_compliance_status': patch_compliance_status,
                'patch_risk': patch_risk,
                'last_patch_time': last_patch_time,
                'available_patches': available_patches
            }

        except Exception as e:
            logger.warning(f"Failed to analyze patch compliance: {e}")
            return GCPComputePatchComplianceAnalyzer._get_default_patch_analysis()

    @staticmethod
    def _determine_os_type(instance_data: Dict[str, Any]) -> str:
        """Determine operating system type"""
        try:
            disks = instance_data.get('disks', [])
            boot_disk = next((disk for disk in disks if disk.get('boot', False)), {})

            if boot_disk:
                source_image = boot_disk.get('source', '').lower()
                if 'windows' in source_image:
                    return 'Windows'
                elif any(os_name in source_image for os_name in ['ubuntu', 'debian', 'centos', 'rhel', 'suse']):
                    return 'Linux'
                elif 'cos' in source_image:
                    return 'Container-Optimized OS'

            return 'Unknown'

        except Exception as e:
            logger.warning(f"Failed to determine OS type: {e}")
            return 'Unknown'

    @staticmethod
    def _analyze_os_config_status(instance_data: Dict[str, Any]) -> str:
        """Analyze OS Config agent status"""
        try:
            metadata = instance_data.get('metadata', {})
            metadata_items = metadata.get('items', [])

            enable_os_config = next((item.get('value', 'FALSE')
                                     for item in metadata_items
                                     if item.get('key') == 'enable-osconfig'), 'FALSE')

            if enable_os_config.upper() == 'TRUE':
                return 'Installed and Enabled'
            else:
                return 'Not Configured'

        except Exception as e:
            logger.warning(f"Failed to analyze OS Config status: {e}")
            return 'Unknown'

    @staticmethod
    def _analyze_patch_deployment(instance_data: Dict[str, Any]) -> str:
        """Analyze patch deployment configuration"""
        try:
            metadata = instance_data.get('metadata', {})
            metadata_items = metadata.get('items', [])

            # Check for automated patching configuration
            os_config_enabled = next((item.get('value', 'FALSE')
                                      for item in metadata_items
                                      if item.get('key') == 'enable-osconfig'), 'FALSE')

            # Check for startup script patch management
            startup_script = next((item.get('value', '')
                                   for item in metadata_items
                                   if item.get('key') == 'startup-script'), '')

            has_patch_management = (
                    'apt-get update' in startup_script.lower() or
                    'yum update' in startup_script.lower() or
                    'dnf update' in startup_script.lower() or
                    'zypper update' in startup_script.lower()
            )

            if os_config_enabled.upper() == 'TRUE':
                return 'Automated - OS Config Agent'
            elif has_patch_management:
                return 'Semi-Automated - Startup Script'
            else:
                return 'Manual - No Automation Detected'

        except Exception as e:
            logger.warning(f"Failed to analyze patch deployment: {e}")
            return 'Unknown'

    @staticmethod
    def _assess_patch_compliance(os_config_status: str, patch_deployment_status: str) -> str:
        """Assess overall patch compliance status"""
        if 'Automated - OS Config Agent' in patch_deployment_status:
            return 'Compliant - Automated Patch Management'
        elif 'Semi-Automated' in patch_deployment_status:
            return 'Partially Compliant - Basic Automation'
        elif 'Manual' in patch_deployment_status:
            return 'Non-Compliant - Manual Patching Required'
        else:
            return 'Unknown - Configuration Review Required'

    @staticmethod
    def _assess_patch_risk(os_config_status: str, patch_deployment_status: str,
                           instance_data: Dict[str, Any]) -> str:
        """Assess patch management risk"""
        try:
            risk_factors = []

            if 'Manual' in patch_deployment_status:
                risk_factors.append('Manual patching process')

            if 'Not Configured' in os_config_status:
                risk_factors.append('No OS Config agent')

            # Check instance age (older instances may have more patches)
            creation_timestamp = instance_data.get('creationTimestamp')
            if creation_timestamp:
                creation_time = datetime.fromisoformat(creation_timestamp.replace('Z', '+00:00'))
                days_old = (datetime.now(creation_time.tzinfo) - creation_time).days
                if days_old > 90:
                    risk_factors.append('Instance older than 90 days')

            # Check if instance is externally accessible
            network_interfaces = instance_data.get('networkInterfaces', [])
            has_external_ip = any(ni.get('accessConfigs', []) for ni in network_interfaces)
            if has_external_ip:
                risk_factors.append('External IP assigned')

            if len(risk_factors) >= 3:
                return f"High - Multiple risk factors: {', '.join(risk_factors[:2])}"
            elif len(risk_factors) >= 1:
                return f"Medium - {risk_factors[0]}"
            else:
                return "Low - Automated patch management configured"

        except Exception as e:
            logger.warning(f"Failed to assess patch risk: {e}")
            return "Unknown - Risk assessment failed"

    @staticmethod
    def _get_last_patch_time(instance_data: Dict[str, Any]) -> str:
        """Get last patch time (estimated)"""
        try:
            # For GCP, we don't have direct access to patch history via Asset Inventory
            # This would typically require VM Manager API or OS Config API
            creation_timestamp = instance_data.get('creationTimestamp')
            if creation_timestamp:
                return f"Estimated: At instance creation ({creation_timestamp[:10]})"
            else:
                return "Unknown - Requires OS Config API access"

        except Exception as e:
            logger.warning(f"Failed to get last patch time: {e}")
            return "Unknown"

    @staticmethod
    def _estimate_available_patches(os_config_status: str, instance_data: Dict[str, Any]) -> int:
        """Estimate available patches"""
        try:
            # Without direct access to OS Config API, provide estimation
            if 'Not Configured' in os_config_status:
                # Assume instances without OS Config have pending patches
                creation_timestamp = instance_data.get('creationTimestamp')
                if creation_timestamp:
                    creation_time = datetime.fromisoformat(creation_timestamp.replace('Z', '+00:00'))
                    days_old = (datetime.now(creation_time.tzinfo) - creation_time).days
                    # Rough estimate: 1-2 patches per week
                    return min(max(days_old // 7, 0), 50)  # Cap at 50 patches
                else:
                    return 10  # Default estimate
            else:
                return 0  # Assume automated patching keeps instances current

        except Exception as e:
            logger.warning(f"Failed to estimate available patches: {e}")
            return 0

    @staticmethod
    def _get_default_patch_analysis() -> Dict[str, Any]:
        """Return default patch analysis when data is unavailable"""
        return {
            'os_type': 'Unknown',
            'os_config_agent_status': 'Unknown',
            'patch_deployment_status': 'Unknown',
            'patch_compliance_status': 'Review Required',
            'patch_risk': 'Unknown - Manual review required',
            'last_patch_time': 'Unknown',
            'available_patches': 0
        }
