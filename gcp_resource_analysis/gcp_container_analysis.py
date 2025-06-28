#!/usr/bin/env python3
"""
GCP Container and Modern Workloads Analysis Module

Comprehensive analysis for GCP container and serverless workloads including:
- GKE cluster security and compliance
- GKE node pool optimization
- Artifact Registry security
- Cloud Run security analysis
- App Engine security analysis
- Cloud Functions security analysis
- Container workloads compliance summary

Equivalent to Azure's container_workload_analysis.py
"""

from typing import List, Dict, Any


class GCPContainerAnalysisQueries:
    """GCP Container and Modern Workloads analysis queries equivalent to Azure's ContainerWorkloadsAnalysisQueries"""

    @staticmethod
    def get_gke_cluster_security_asset_types() -> List[str]:
        """
        Get asset types for GKE cluster security analysis
        """
        return [
            "container.googleapis.com/Cluster",
            "container.googleapis.com/NodePool"
        ]

    @staticmethod
    def get_artifact_registry_security_asset_types() -> List[str]:
        """
        Get asset types for Artifact Registry security analysis
        """
        return [
            "artifactregistry.googleapis.com/Repository"
        ]

    @staticmethod
    def get_cloud_run_security_asset_types() -> List[str]:
        """
        Get asset types for Cloud Run security analysis
        """
        return [
            "run.googleapis.com/Service"
        ]

    @staticmethod
    def get_app_engine_security_asset_types() -> List[str]:
        """
        Get asset types for App Engine security analysis
        """
        return [
            "appengine.googleapis.com/Application",
            "appengine.googleapis.com/Service",
            "appengine.googleapis.com/Version"
        ]

    @staticmethod
    def get_cloud_functions_security_asset_types() -> List[str]:
        """
        Get asset types for Cloud Functions security analysis
        """
        return [
            "cloudfunctions.googleapis.com/Function"
        ]

    @staticmethod
    def get_comprehensive_container_asset_types() -> List[str]:
        """
        Get comprehensive list of container and serverless asset types
        """
        all_types = []
        all_types.extend(GCPContainerAnalysisQueries.get_gke_cluster_security_asset_types())
        all_types.extend(GCPContainerAnalysisQueries.get_artifact_registry_security_asset_types())
        all_types.extend(GCPContainerAnalysisQueries.get_cloud_run_security_asset_types())
        all_types.extend(GCPContainerAnalysisQueries.get_app_engine_security_asset_types())
        all_types.extend(GCPContainerAnalysisQueries.get_cloud_functions_security_asset_types())
        return list(set(all_types))  # Remove duplicates


class GCPGKEClusterAnalyzer:
    """GKE cluster security and compliance analyzer"""

    @staticmethod
    def analyze_gke_cluster_security(asset_type: str, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Analyze GKE cluster security configuration

        Args:
            asset_type: GCP asset type
            data: Asset data from Cloud Asset Inventory

        Returns:
            Dictionary with cluster security analysis
        """
        try:
            if data is None:
                return {
                    'cluster_version': 'Unknown',
                    'network_configuration': 'Unknown',
                    'rbac_configuration': 'Unknown',
                    'api_server_access': 'Unknown',
                    'security_findings': 'No data available',
                    'security_risk': 'Unknown',
                    'cluster_compliance': 'Manual review required',
                    'cluster_details': 'Analysis failed - no data'
                }

            if 'container.googleapis.com/Cluster' in asset_type:
                # Extract cluster configuration
                current_master_version = data.get('currentMasterVersion', 'Unknown')
                network_config = data.get('networkConfig', {})
                ip_allocation_policy = data.get('ipAllocationPolicy', {})
                master_auth = data.get('masterAuth', {})
                private_cluster_config = data.get('privateClusterConfig', {})
                workload_identity_config = data.get('workloadIdentityConfig', {})
                binary_authorization = data.get('binaryAuthorization', {})

                # Analyze network configuration
                if private_cluster_config.get('enablePrivateNodes', False):
                    if private_cluster_config.get('enablePrivateEndpoint', False):
                        network_config_desc = "Private cluster with private endpoint"
                        network_security_level = "High"
                    else:
                        network_config_desc = "Private nodes with public endpoint"
                        network_security_level = "Medium"
                else:
                    network_config_desc = "Public cluster"
                    network_security_level = "Low"

                # Analyze RBAC and authentication
                rbac_enabled = master_auth.get('rbacEnabled', False)
                workload_identity_enabled = workload_identity_config.get('workloadPool') is not None

                if rbac_enabled and workload_identity_enabled:
                    rbac_config = "RBAC + Workload Identity enabled"
                    rbac_security_level = "High"
                elif rbac_enabled:
                    rbac_config = "RBAC enabled, no Workload Identity"
                    rbac_security_level = "Medium"
                else:
                    rbac_config = "Legacy ABAC or basic auth"
                    rbac_security_level = "Low"

                # Analyze API server access
                authorized_networks = master_auth.get('authorizedNetworksConfig', {})
                if authorized_networks.get('enabled', False):
                    networks_count = len(authorized_networks.get('cidrBlocks', []))
                    api_access = f"Authorized networks: {networks_count} ranges"
                    api_security_level = "Medium" if networks_count > 0 else "Low"
                else:
                    api_access = "Open to internet"
                    api_security_level = "Low"

                # Calculate overall security findings
                security_issues = []
                if network_security_level == "Low":
                    security_issues.append("Public cluster configuration")
                if rbac_security_level == "Low":
                    security_issues.append("Legacy authentication")
                if api_security_level == "Low":
                    security_issues.append("Unrestricted API access")
                if not binary_authorization.get('enabled', False):
                    security_issues.append("Binary Authorization disabled")

                if len(security_issues) >= 3:
                    overall_risk = "High - Multiple security issues"
                    compliance_status = "Non-Compliant - Critical issues"
                elif len(security_issues) >= 1:
                    overall_risk = "Medium - Some security concerns"
                    compliance_status = "Partially Compliant - Needs improvement"
                else:
                    overall_risk = "Low - Well configured"
                    compliance_status = "Compliant - Good security posture"

                security_findings = " | ".join(security_issues) if security_issues else "No major issues found"

                # Additional cluster details
                node_count = data.get('currentNodeCount', 0)
                location_type = "Regional" if "-" in data.get('location', '') else "Zonal"
                cluster_details = f"Nodes: {node_count} | Type: {location_type} | Version: {current_master_version}"

                return {
                    'cluster_version': current_master_version,
                    'network_configuration': network_config_desc,
                    'rbac_configuration': rbac_config,
                    'api_server_access': api_access,
                    'security_findings': security_findings,
                    'security_risk': overall_risk,
                    'cluster_compliance': compliance_status,
                    'cluster_details': cluster_details
                }

            return {
                'cluster_version': 'Not a GKE cluster',
                'network_configuration': 'N/A',
                'rbac_configuration': 'N/A',
                'api_server_access': 'N/A',
                'security_findings': 'Unsupported asset type',
                'security_risk': 'Manual review required',
                'cluster_compliance': 'Not applicable',
                'cluster_details': f'Asset type: {asset_type}'
            }

        except Exception as e:
            return {
                'cluster_version': 'Analysis failed',
                'network_configuration': 'Unknown',
                'rbac_configuration': 'Unknown',
                'api_server_access': 'Unknown',
                'security_findings': f'Error: {str(e)}',
                'security_risk': 'Analysis error',
                'cluster_compliance': 'Manual review required',
                'cluster_details': 'Analysis failed'
            }

    @staticmethod
    def analyze_gke_node_pool(asset_type: str, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Analyze GKE node pool configuration and optimization

        Args:
            asset_type: GCP asset type
            data: Asset data from Cloud Asset Inventory

        Returns:
            Dictionary with node pool analysis
        """
        try:
            if data is None:
                return {
                    'node_pool_type': 'Unknown',
                    'vm_size': 'Unknown',
                    'vm_size_category': 'Unknown',
                    'scaling_configuration': 'Unknown',
                    'security_configuration': 'Unknown',
                    'optimization_potential': 'Unknown',
                    'node_pool_risk': 'Unknown',
                    'node_pool_details': 'No data available'
                }

            if 'container.googleapis.com/NodePool' in asset_type:
                config = data.get('config', {})
                management = data.get('management', {})
                autoscaling = data.get('autoscaling', {})

                # Analyze machine type and sizing
                machine_type = config.get('machineType', 'Unknown')
                disk_size = config.get('diskSizeGb', 0)

                if 'e2-' in machine_type:
                    vm_category = "Cost-optimized (E2)"
                elif 'n1-' in machine_type:
                    vm_category = "General purpose (N1)"
                elif 'n2-' in machine_type:
                    vm_category = "Balanced (N2)"
                elif 'c2-' in machine_type:
                    vm_category = "Compute-optimized (C2)"
                elif 'custom-' in machine_type:
                    vm_category = "Custom machine type"
                else:
                    vm_category = "Unknown type"

                # Analyze scaling configuration
                if autoscaling.get('enabled', False):
                    min_nodes = autoscaling.get('minNodeCount', 0)
                    max_nodes = autoscaling.get('maxNodeCount', 0)
                    scaling_config = f"Autoscaling: {min_nodes}-{max_nodes} nodes"
                    scaling_efficiency = "Good" if min_nodes < max_nodes else "Fixed size"
                else:
                    initial_node_count = data.get('initialNodeCount', 0)
                    scaling_config = f"Fixed size: {initial_node_count} nodes"
                    scaling_efficiency = "Manual scaling only"

                # Analyze security configuration
                security_features = []
                if config.get('serviceAccount') != 'default':
                    security_features.append("Custom service account")
                if config.get('oauthScopes'):
                    security_features.append("Custom OAuth scopes")
                if config.get('shieldedInstanceConfig', {}).get('enableSecureBoot', False):
                    security_features.append("Secure Boot")
                if config.get('workloadMetadataConfig', {}).get('mode') == 'GKE_METADATA':
                    security_features.append("Workload Identity")

                security_config = ", ".join(
                    security_features) if security_features else "Default security configuration"

                # Optimization analysis
                optimization_issues = []
                if 'n1-' in machine_type:
                    optimization_issues.append("Consider newer N2 or E2 machine types")
                if disk_size > 100 and 'e2-' not in machine_type:
                    optimization_issues.append("Large disk with premium machine type")
                if not autoscaling.get('enabled', False):
                    optimization_issues.append("No autoscaling configured")

                if len(optimization_issues) >= 2:
                    optimization_potential = "High - Multiple optimization opportunities"
                elif len(optimization_issues) >= 1:
                    optimization_potential = "Medium - Some optimization possible"
                else:
                    optimization_potential = "Low - Well optimized"

                # Risk assessment
                risk_factors = []
                if len(security_features) == 0:
                    risk_factors.append("Default security configuration")
                if not autoscaling.get('enabled', False):
                    risk_factors.append("No autoscaling")
                if config.get('serviceAccount') == 'default':
                    risk_factors.append("Default service account")

                if len(risk_factors) >= 2:
                    node_pool_risk = "Medium - Security and operational concerns"
                elif len(risk_factors) >= 1:
                    node_pool_risk = "Low - Minor concerns"
                else:
                    node_pool_risk = "Low - Well configured"

                node_pool_details = f"Machine: {machine_type} | Disk: {disk_size}GB | Security features: {len(security_features)}"

                return {
                    'node_pool_type': config.get('diskType', 'pd-standard'),
                    'vm_size': machine_type,
                    'vm_size_category': vm_category,
                    'scaling_configuration': scaling_config,
                    'security_configuration': security_config,
                    'optimization_potential': optimization_potential,
                    'node_pool_risk': node_pool_risk,
                    'node_pool_details': node_pool_details
                }

            return {
                'node_pool_type': 'Not a node pool',
                'vm_size': 'N/A',
                'vm_size_category': 'N/A',
                'scaling_configuration': 'N/A',
                'security_configuration': 'N/A',
                'optimization_potential': 'Not applicable',
                'node_pool_risk': 'Not applicable',
                'node_pool_details': f'Asset type: {asset_type}'
            }

        except Exception as e:
            return {
                'node_pool_type': 'Analysis failed',
                'vm_size': 'Unknown',
                'vm_size_category': 'Unknown',
                'scaling_configuration': 'Unknown',
                'security_configuration': 'Unknown',
                'optimization_potential': f'Error: {str(e)}',
                'node_pool_risk': 'Analysis error',
                'node_pool_details': 'Analysis failed'
            }


class GCPArtifactRegistryAnalyzer:
    """Artifact Registry security analyzer"""

    @staticmethod
    def analyze_registry_security(asset_type: str, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Analyze Artifact Registry security configuration

        Args:
            asset_type: GCP asset type
            data: Asset data from Cloud Asset Inventory

        Returns:
            Dictionary with registry security analysis
        """
        try:
            if data is None:
                return {
                    'registry_sku': 'Unknown',
                    'network_security': 'Unknown',
                    'access_control': 'Unknown',
                    'security_policies': 'Unknown',
                    'security_findings': 'No data available',
                    'security_risk': 'Unknown',
                    'compliance_status': 'Manual review required',
                    'registry_details': 'Analysis failed - no data'
                }

            if 'artifactregistry.googleapis.com/Repository' in asset_type:
                format_type = data.get('format', 'Unknown')
                mode = data.get('mode', 'STANDARD_REPOSITORY')

                # Analyze repository configuration
                registry_sku = f"{format_type} ({mode})"

                # Network security analysis (basic check)
                # Note: Artifact Registry doesn't have complex network configs like Container Registry
                network_security = "VPC-SC compatible" if mode == 'STANDARD_REPOSITORY' else "Basic network access"

                # Access control analysis
                # In real implementation, would need to check IAM policies
                access_control = "IAM controlled access"

                # Security policies analysis
                security_policies = []
                if mode == 'STANDARD_REPOSITORY':
                    security_policies.append("Standard repository mode")
                if format_type in ['DOCKER', 'CONTAINER']:
                    security_policies.append("Container image scanning available")

                security_policies_desc = ", ".join(security_policies) if security_policies else "Basic policies"

                # Security findings
                security_issues = []
                if format_type == 'UNSPECIFIED':
                    security_issues.append("Unspecified repository format")

                if len(security_issues) > 0:
                    security_findings = " | ".join(security_issues)
                    security_risk = "Medium - Configuration review needed"
                    compliance_status = "Partially Compliant - Review required"
                else:
                    security_findings = "Standard configuration"
                    security_risk = "Low - Standard security"
                    compliance_status = "Compliant - Standard configuration"

                registry_details = f"Format: {format_type} | Mode: {mode}"

                return {
                    'registry_sku': registry_sku,
                    'network_security': network_security,
                    'access_control': access_control,
                    'security_policies': security_policies_desc,
                    'security_findings': security_findings,
                    'security_risk': security_risk,
                    'compliance_status': compliance_status,
                    'registry_details': registry_details
                }

            return {
                'registry_sku': 'Not an Artifact Registry',
                'network_security': 'N/A',
                'access_control': 'N/A',
                'security_policies': 'N/A',
                'security_findings': 'Unsupported asset type',
                'security_risk': 'Not applicable',
                'compliance_status': 'Not applicable',
                'registry_details': f'Asset type: {asset_type}'
            }

        except Exception as e:
            return {
                'registry_sku': 'Analysis failed',
                'network_security': 'Unknown',
                'access_control': 'Unknown',
                'security_policies': 'Unknown',
                'security_findings': f'Error: {str(e)}',
                'security_risk': 'Analysis error',
                'compliance_status': 'Manual review required',
                'registry_details': 'Analysis failed'
            }


class GCPCloudRunAnalyzer:
    """Cloud Run security analyzer"""

    @staticmethod
    def analyze_cloud_run_security(asset_type: str, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Analyze Cloud Run service security configuration

        Args:
            asset_type: GCP asset type
            data: Asset data from Cloud Asset Inventory

        Returns:
            Dictionary with Cloud Run security analysis
        """
        try:
            if data is None:
                return {
                    'service_kind': 'Unknown',
                    'tls_configuration': 'Unknown',
                    'network_security': 'Unknown',
                    'authentication_method': 'Unknown',
                    'security_findings': 'No data available',
                    'security_risk': 'Unknown',
                    'compliance_status': 'Manual review required',
                    'service_details': 'Analysis failed - no data'
                }

            if 'run.googleapis.com/Service' in asset_type:
                spec = data.get('spec', {})
                metadata = data.get('metadata', {})
                status = data.get('status', {})

                # Analyze service kind and configuration
                annotations = metadata.get('annotations', {})

                # TLS Configuration
                ingress = annotations.get('run.googleapis.com/ingress', 'all')
                if ingress == 'internal':
                    tls_config = "Internal traffic only"
                    network_security_level = "High"
                elif ingress == 'internal-and-cloud-load-balancing':
                    tls_config = "Internal + Load Balancer"
                    network_security_level = "Medium"
                else:
                    tls_config = "Public internet access"
                    network_security_level = "Low"

                # Authentication analysis
                if 'run.googleapis.com/invoker' in annotations:
                    invoker = annotations['run.googleapis.com/invoker']
                    if invoker == 'allUsers':
                        auth_method = "Unauthenticated (public)"
                        auth_security_level = "Low"
                    else:
                        auth_method = f"IAM restricted: {invoker}"
                        auth_security_level = "High"
                else:
                    auth_method = "Default IAM authentication"
                    auth_security_level = "Medium"

                # Network security analysis
                vpc_access = annotations.get('run.googleapis.com/vpc-access-connector')
                if vpc_access:
                    network_security = f"VPC connector: {vpc_access}"
                    if network_security_level == "High":
                        network_security_level = "High"
                    else:
                        network_security_level = "Medium"
                else:
                    network_security = "Default network (no VPC)"

                # Security findings
                security_issues = []
                if auth_security_level == "Low":
                    security_issues.append("Public unauthenticated access")
                if network_security_level == "Low":
                    security_issues.append("Public internet access")
                if not vpc_access and ingress != 'internal':
                    security_issues.append("No VPC isolation")

                if len(security_issues) >= 2:
                    overall_risk = "High - Multiple security concerns"
                    compliance_status = "Non-Compliant - Public service"
                elif len(security_issues) >= 1:
                    overall_risk = "Medium - Some security concerns"
                    compliance_status = "Partially Compliant - Review needed"
                else:
                    overall_risk = "Low - Properly secured"
                    compliance_status = "Compliant - Good security"

                security_findings = " | ".join(security_issues) if security_issues else "No major issues"

                # Service details
                service_name = metadata.get('name', 'Unknown')
                ready_replicas = status.get('readyReplicas', 0)
                service_details = f"Service: {service_name} | Replicas: {ready_replicas} | Ingress: {ingress}"

                return {
                    'service_kind': 'Cloud Run Service',
                    'tls_configuration': tls_config,
                    'network_security': network_security,
                    'authentication_method': auth_method,
                    'security_findings': security_findings,
                    'security_risk': overall_risk,
                    'compliance_status': compliance_status,
                    'service_details': service_details
                }

            return {
                'service_kind': 'Not a Cloud Run service',
                'tls_configuration': 'N/A',
                'network_security': 'N/A',
                'authentication_method': 'N/A',
                'security_findings': 'Unsupported asset type',
                'security_risk': 'Not applicable',
                'compliance_status': 'Not applicable',
                'service_details': f'Asset type: {asset_type}'
            }

        except Exception as e:
            return {
                'service_kind': 'Analysis failed',
                'tls_configuration': 'Unknown',
                'network_security': 'Unknown',
                'authentication_method': 'Unknown',
                'security_findings': f'Error: {str(e)}',
                'security_risk': 'Analysis error',
                'compliance_status': 'Manual review required',
                'service_details': 'Analysis failed'
            }


class GCPAppEngineAnalyzer:
    """App Engine security analyzer"""

    @staticmethod
    def analyze_app_engine_security(asset_type: str, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Analyze App Engine application/service security

        Args:
            asset_type: GCP asset type
            data: Asset data from Cloud Asset Inventory

        Returns:
            Dictionary with App Engine security analysis
        """
        try:
            if data is None:
                return {
                    'app_kind': 'Unknown',
                    'tls_configuration': 'Unknown',
                    'network_security': 'Unknown',
                    'authentication_method': 'Unknown',
                    'security_findings': 'No data available',
                    'security_risk': 'Unknown',
                    'compliance_status': 'Manual review required',
                    'app_details': 'Analysis failed - no data'
                }

            if 'appengine.googleapis.com/Application' in asset_type:
                auth_domain = data.get('authDomain', '')
                serving_status = data.get('servingStatus', 'UNSPECIFIED')
                location_id = data.get('locationId', 'Unknown')

                # TLS is always enabled for App Engine
                tls_config = "HTTPS enforced (automatic)"

                # Network security analysis
                if auth_domain:
                    network_security = f"Custom domain: {auth_domain}"
                    network_security_level = "Medium"
                else:
                    network_security = "Default .appspot.com domain"
                    network_security_level = "Low"

                # Authentication analysis (basic)
                auth_method = "App Engine default authentication"

                # Security findings
                security_issues = []
                if serving_status != 'SERVING':
                    security_issues.append(f"Application not serving: {serving_status}")

                if len(security_issues) > 0:
                    security_findings = " | ".join(security_issues)
                    security_risk = "Medium - Operational issues"
                    compliance_status = "Review required"
                else:
                    security_findings = "Standard App Engine configuration"
                    security_risk = "Low - Standard configuration"
                    compliance_status = "Compliant - Standard setup"

                app_details = f"Location: {location_id} | Status: {serving_status}"

                return {
                    'app_kind': 'App Engine Application',
                    'tls_configuration': tls_config,
                    'network_security': network_security,
                    'authentication_method': auth_method,
                    'security_findings': security_findings,
                    'security_risk': security_risk,
                    'compliance_status': compliance_status,
                    'app_details': app_details
                }

            elif 'appengine.googleapis.com/Service' in asset_type:
                traffic_split = data.get('split', {})

                app_kind = 'App Engine Service'
                tls_config = "HTTPS enforced (automatic)"
                network_security = "App Engine managed"
                auth_method = "Service-level authentication"

                # Analyze traffic split
                allocations = traffic_split.get('allocations', {})
                if len(allocations) > 1:
                    security_findings = f"Traffic split across {len(allocations)} versions"
                    security_risk = "Low - Multiple versions deployed"
                    compliance_status = "Compliant - Version management"
                else:
                    security_findings = "Single version deployment"
                    security_risk = "Low - Standard deployment"
                    compliance_status = "Compliant - Standard setup"

                app_details = f"Versions: {len(allocations)} | Traffic split configured"

                return {
                    'app_kind': app_kind,
                    'tls_configuration': tls_config,
                    'network_security': network_security,
                    'authentication_method': auth_method,
                    'security_findings': security_findings,
                    'security_risk': security_risk,
                    'compliance_status': compliance_status,
                    'app_details': app_details
                }

            return {
                'app_kind': 'Unknown App Engine resource',
                'tls_configuration': 'N/A',
                'network_security': 'N/A',
                'authentication_method': 'N/A',
                'security_findings': 'Unsupported asset type',
                'security_risk': 'Not applicable',
                'compliance_status': 'Not applicable',
                'app_details': f'Asset type: {asset_type}'
            }

        except Exception as e:
            return {
                'app_kind': 'Analysis failed',
                'tls_configuration': 'Unknown',
                'network_security': 'Unknown',
                'authentication_method': 'Unknown',
                'security_findings': f'Error: {str(e)}',
                'security_risk': 'Analysis error',
                'compliance_status': 'Manual review required',
                'app_details': 'Analysis failed'
            }


class GCPCloudFunctionsAnalyzer:
    """Cloud Functions security analyzer"""

    @staticmethod
    def analyze_cloud_function_security(asset_type: str, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Analyze Cloud Functions security configuration

        Args:
            asset_type: GCP asset type
            data: Asset data from Cloud Asset Inventory

        Returns:
            Dictionary with Cloud Functions security analysis
        """
        try:
            if data is None:
                return {
                    'function_kind': 'Unknown',
                    'tls_configuration': 'Unknown',
                    'network_security': 'Unknown',
                    'authentication_method': 'Unknown',
                    'security_findings': 'No data available',
                    'security_risk': 'Unknown',
                    'compliance_status': 'Manual review required',
                    'function_details': 'Analysis failed - no data'
                }

            if 'cloudfunctions.googleapis.com/Function' in asset_type:
                https_trigger = data.get('httpsTrigger', {})
                event_trigger = data.get('eventTrigger', {})
                vpc_connector = data.get('vpcConnector', '')
                ingress_settings = data.get('ingressSettings', 'ALLOW_ALL')

                # Determine function type and trigger
                if https_trigger:
                    function_kind = 'HTTP triggered function'
                    trigger_type = 'HTTPS'
                elif event_trigger:
                    function_kind = 'Event triggered function'
                    trigger_type = 'Event'
                else:
                    function_kind = 'Unknown trigger type'
                    trigger_type = 'Unknown'

                # TLS configuration
                if trigger_type == 'HTTPS':
                    tls_config = "HTTPS enforced (automatic)"
                else:
                    tls_config = "N/A (event triggered)"

                # Network security analysis
                if vpc_connector:
                    network_security = f"VPC connector: {vpc_connector}"
                    network_security_level = "High"
                elif ingress_settings == 'ALLOW_INTERNAL_ONLY':
                    network_security = "Internal traffic only"
                    network_security_level = "High"
                elif ingress_settings == 'ALLOW_INTERNAL_AND_GCLB':
                    network_security = "Internal + Load Balancer"
                    network_security_level = "Medium"
                else:
                    network_security = "Public internet access"
                    network_security_level = "Low"

                # Authentication analysis
                if trigger_type == 'HTTPS':
                    # For HTTP functions, check if authentication is required
                    security_level = https_trigger.get('securityLevel', 'SECURE_ALWAYS')
                    if security_level == 'SECURE_ALWAYS':
                        auth_method = "HTTPS with authentication required"
                        auth_security_level = "Medium"
                    else:
                        auth_method = "HTTPS with optional authentication"
                        auth_security_level = "Low"
                else:
                    auth_method = "Event-based (no direct auth)"
                    auth_security_level = "High"

                # Security findings
                security_issues = []
                if trigger_type == 'HTTPS' and ingress_settings == 'ALLOW_ALL':
                    security_issues.append("Public HTTP function")
                if not vpc_connector and network_security_level == "Low":
                    security_issues.append("No VPC isolation")
                if auth_security_level == "Low":
                    security_issues.append("Weak authentication")

                if len(security_issues) >= 2:
                    overall_risk = "High - Multiple security concerns"
                    compliance_status = "Non-Compliant - Public function"
                elif len(security_issues) >= 1:
                    overall_risk = "Medium - Some security concerns"
                    compliance_status = "Partially Compliant - Review needed"
                else:
                    overall_risk = "Low - Properly secured"
                    compliance_status = "Compliant - Good security"

                security_findings = " | ".join(security_issues) if security_issues else "No major issues"

                # Function details
                status = data.get('status', 'UNKNOWN')
                function_details = f"Trigger: {trigger_type} | Status: {status} | Ingress: {ingress_settings}"

                return {
                    'function_kind': function_kind,
                    'tls_configuration': tls_config,
                    'network_security': network_security,
                    'authentication_method': auth_method,
                    'security_findings': security_findings,
                    'security_risk': overall_risk,
                    'compliance_status': compliance_status,
                    'function_details': function_details
                }

            return {
                'function_kind': 'Not a Cloud Function',
                'tls_configuration': 'N/A',
                'network_security': 'N/A',
                'authentication_method': 'N/A',
                'security_findings': 'Unsupported asset type',
                'security_risk': 'Not applicable',
                'compliance_status': 'Not applicable',
                'function_details': f'Asset type: {asset_type}'
            }

        except Exception as e:
            return {
                'function_kind': 'Analysis failed',
                'tls_configuration': 'Unknown',
                'network_security': 'Unknown',
                'authentication_method': 'Unknown',
                'security_findings': f'Error: {str(e)}',
                'security_risk': 'Analysis error',
                'compliance_status': 'Manual review required',
                'function_details': 'Analysis failed'
            }
