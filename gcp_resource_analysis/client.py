#!/usr/bin/env python3
"""
GCP Resource Analysis Client

Main client class providing comprehensive analysis of Google Cloud Platform resources
using Cloud Asset Inventory. Equivalent functionality to Azure Resource Graph Client
but adapted for GCP services and APIs.

This client provides:
- Storage security and compliance analysis
- Compute resource optimization analysis
- Network security configuration analysis
- IAM and access control analysis
- Container workload analysis
- Cost optimization recommendations
- Compliance scoring and reporting

Example Usage:
    client = GCPResourceAnalysisClient(
        project_ids=["project-1", "project-2"],
        credentials_path="/path/to/service-account.json"
    )

    # Run comprehensive analysis
    results = client.query_comprehensive_analysis()

    # Individual analysis components
    storage_results = client.query_storage_analysis()
    compliance_summary = client.get_storage_compliance_summary()
"""

import logging
import os
import threading
from typing import List, Dict, Any, Optional

import google.auth.exceptions
from google.auth import default
# Google Cloud imports
from google.cloud import asset_v1
from google.oauth2 import service_account

from .gcp_compute_governance import GCPComputeGovernanceQueries, GCPComputeSecurityAnalyzer, \
    GCPComputeOptimizationAnalyzer, GCPComputeConfigurationAnalyzer, GCPComputePatchComplianceAnalyzer
from .gcp_container_analysis import GCPContainerAnalysisQueries, GCPGKEClusterAnalyzer, GCPArtifactRegistryAnalyzer, \
    GCPCloudRunAnalyzer, GCPAppEngineAnalyzer, GCPCloudFunctionsAnalyzer
from .gcp_iam_analysis import GCPIAMAnalysisQueries, GCPWorkloadIdentityAnalyzer
from .gcp_network_analysis import (
    GCPNetworkAnalysisQueries,
    GCPNetworkSecurityAnalyzer,
    GCPFirewallRuleAnalyzer,
    GCPSSLCertificateAnalyzer,
    GCPNetworkTopologyAnalyzer,
    GCPNetworkOptimizationAnalyzer
)
from .gcp_storage_analysis import GCPStorageAnalysisQueries, GCPStorageSecurityAnalyzer, GCPKMSAnalyzer, \
    GCPStorageBackupAnalyzer, GCPStorageOptimizationAnalyzer
from .models import (
    GCPIAMPolicyBindingResult,
    GCPCustomRoleResult,
    GCPWorkloadIdentityResult,
    GCPServiceAccountKeyResult,
    GCPIAMComplianceSummary,
    GCPServiceAccountSecurityResult,
    GCPNetworkResource,
    GCPFirewallRule,
    GCPSSLCertificateResult,
    GCPNetworkTopologyResult,
    GCPNetworkOptimizationResult,
    GCPNetworkComplianceSummary,
    GCPGKEClusterSecurityResult,
    GCPGKENodePoolResult,
    GCPArtifactRegistrySecurityResult,
    GCPCloudRunSecurityResult,
    GCPAppEngineSecurityResult,
    GCPCloudFunctionsSecurityResult,
    GCPContainerWorkloadsComplianceSummary,
    GCPVMSecurityResult,
    GCPVMOptimizationResult,
    GCPVMConfigurationResult,
    GCPVMPatchComplianceResult,
    GCPVMGovernanceSummary,
    GCPComputeComplianceSummary,
    GCPStorageResource,
    GCPStorageAccessControlResult,
    GCPStorageBackupResult,
    GCPStorageOptimizationResult,
    GCPStorageComplianceSummary,
    GCPComprehensiveAnalysisResult,
    RateLimitTracker,
    GCPKMSSecurityResult, GCPEnhancedStorageComplianceSummary
)

# Set up logging
logger = logging.getLogger(__name__)


class GCPResourceAnalysisClient:
    """
    GCP Resource Analysis Client - Equivalent to Azure Resource Graph Client

    Provides comprehensive analysis of GCP resources using Cloud Asset Inventory API.
    Offers security, compliance, optimization, and governance insights across multiple
    projects and resource types.
    """

    def __init__(self, project_ids: Optional[List[str]] = None, credentials_path: Optional[str] = None):
        """
        Initialize the GCP Resource Analysis Client

        Args:
            project_ids: Optional list of GCP project IDs to analyze (loads from .env if not provided)
            credentials_path: Optional path to service account JSON file (loads from .env if not provided)

        Raises:
            ValueError: If no project_ids can be found
            Exception: If authentication setup fails
        """
        # Load configuration from .env file if not provided
        config = self._load_config_from_env()

        # Use provided parameters or fall back to environment
        self.project_ids = project_ids or config.get('project_ids', [])
        credentials_path = credentials_path or config.get('credentials_path')

        if not self.project_ids:
            raise ValueError(
                "No project IDs provided. Set GCP_PROJECT_IDS environment variable or pass project_ids parameter.\n"
                "Example: GCP_PROJECT_IDS=project1,project2,project3"
            )

        # Set up rate limiting with environment configuration
        self.rate_limiter = RateLimitTracker()
        self.rate_limiter.max_requests_per_minute = config.get('max_requests_per_minute', 100)
        self._request_lock = threading.Lock()

        # Set up logging level
        log_level = config.get('log_level', 'INFO')
        logging.getLogger(__name__).setLevel(getattr(logging, log_level.upper(), logging.INFO))

        # Initialize credentials
        self.credentials = self._setup_credentials(credentials_path)

        # Initialize Asset Inventory client
        try:
            self.asset_client = asset_v1.AssetServiceClient(credentials=self.credentials)
            logger.info(f"Initialized GCP Resource Analysis Client for {len(self.project_ids)} projects")
        except Exception as e:
            logger.error(f"Failed to initialize Asset Service Client: {e}")
            raise

    # Add these imports to the top of client.py (after existing imports)
    from gcp_resource_analysis.models import (
        # Add these to existing model imports
        GCPServiceAccountSecurityResult,
        GCPIAMPolicyBindingResult,
        GCPCustomRoleResult,
        GCPWorkloadIdentityResult,
        GCPServiceAccountKeyResult,
        GCPIAMComplianceSummary
    )

    def query_service_account_security(self) -> List[GCPServiceAccountSecurityResult]:
        """Analyze service account security configurations across all projects"""
        from .gcp_iam_analysis import GCPServiceAccountSecurityAnalyzer

        all_results = []
        asset_types = ["iam.googleapis.com/ServiceAccount"]

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)
                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        if asset.asset_type != "iam.googleapis.com/ServiceAccount":
                            continue

                        # Get application tag
                        application = self._get_application_tag(asset)

                        # Extract service account details
                        sa_data = asset.resource.data
                        if not sa_data:
                            continue

                        email = sa_data.get('email', '')
                        sa_name = email.split('@')[0] if '@' in email else 'unknown'

                        # Use existing analyzer
                        analysis = GCPServiceAccountSecurityAnalyzer.analyze_service_account_security_comprehensive(
                            asset.asset_type, sa_data
                        )

                        result = GCPServiceAccountSecurityResult(
                            application=application,
                            service_account_name=sa_name,
                            service_account_email=email,
                            usage_pattern=analysis['usage_pattern'],
                            orphaned_status=analysis['orphaned_status'],
                            security_risk=analysis['security_risk'],
                            service_account_details=analysis['service_account_details'],
                            key_management=analysis['key_management'],
                            access_pattern=analysis['access_pattern'],
                            project_id=project_id,
                            resource_id=asset.name
                        )

                        all_results.append(result)

                    except Exception as e:
                        logger.warning(f"Error analyzing service account {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Error querying service accounts for project {project_id}: {e}")
                continue

        return all_results

    def query_iam_policy_bindings(self) -> List[GCPIAMPolicyBindingResult]:
        """Analyze IAM policy bindings across all projects"""
        from .gcp_iam_analysis import GCPIAMPolicyAnalyzer

        all_results = []

        # Asset types that commonly have IAM policies
        asset_types = [
            "storage.googleapis.com/Bucket",
            "compute.googleapis.com/Instance",
            "compute.googleapis.com/Disk",
            "sqladmin.googleapis.com/Instance",
            "bigquery.googleapis.com/Dataset"
        ]

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)
                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        # Check if asset has IAM policy - handle both real data and mock data
                        iam_policy: Dict | None = None
                        asset_data = asset.resource.data

                        # Handle mock objects that might not have proper dict structure
                        if hasattr(asset_data, 'get'):
                            iam_policy = asset_data.get('iamPolicy')
                        elif isinstance(asset_data, dict):
                            iam_policy = asset_data.get('iamPolicy')
                        elif hasattr(asset, 'resource') and hasattr(asset.resource, 'data'):
                            # Try to convert to dict for mock objects
                            try:
                                asset_data = dict(asset.resource.data) if asset.resource.data else {}
                                iam_policy = asset_data.get('iamPolicy')
                            except:
                                continue

                        if not iam_policy:
                            continue

                        # Get application tag and resource details
                        application = self._get_application_tag(asset)
                        resource_name = self._extract_resource_name(asset.name)
                        resource_type = self._get_resource_type_display_name(asset.asset_type)

                        # Use existing analyzer
                        analysis = GCPIAMPolicyAnalyzer.analyze_iam_policy_bindings_comprehensive(
                            asset.asset_type, asset_data, iam_policy
                        )

                        # Extract location
                        location = getattr(asset.resource, 'location', 'global') or 'global'

                        result = GCPIAMPolicyBindingResult(
                            application=application,
                            resource_name=resource_name,
                            resource_type=resource_type,
                            policy_scope=analysis['policy_scope'],
                            privilege_level=analysis['privilege_level'],
                            external_user_risk=analysis['external_user_risk'],
                            security_risk=analysis['security_risk'],
                            binding_details=analysis['binding_details'],
                            member_count=int(analysis['member_count']),
                            role_types=analysis['role_types'],
                            project_id=project_id,
                            location=location,
                            resource_id=asset.name
                        )

                        all_results.append(result)

                    except Exception as e:
                        logger.warning(f"Error analyzing IAM policy for {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Error querying IAM policies for project {project_id}: {e}")
                continue

        return all_results

    def query_custom_roles(self) -> List[GCPCustomRoleResult]:
        """Analyze custom IAM roles across all projects"""
        from .gcp_iam_analysis import GCPCustomRoleAnalyzer

        all_results = []
        asset_types = ["iam.googleapis.com/Role"]

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)
                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        if asset.asset_type != "iam.googleapis.com/Role":
                            continue

                        role_data = asset.resource.data
                        if not role_data:
                            continue

                        # Only analyze project-level custom roles
                        role_name = role_data.get('name', '')
                        if not role_name.startswith(f'projects/{project_id}/roles/'):
                            continue

                        # Get application tag
                        application = self._get_application_tag(asset)

                        # Extract role name
                        role_short_name = role_name.split('/')[-1]

                        # Use existing analyzer
                        analysis = GCPCustomRoleAnalyzer.analyze_custom_role_comprehensive(
                            asset.asset_type, role_data
                        )

                        result = GCPCustomRoleResult(
                            application=application,
                            role_name=role_short_name,
                            role_type=analysis['role_type'],
                            permission_scope=analysis['permission_scope'],
                            security_risk=analysis['security_risk'],
                            role_details=analysis['role_details'],
                            permission_count=int(analysis['permission_count']),
                            usage_status=analysis['usage_status'],
                            project_id=project_id,
                            resource_id=asset.name
                        )

                        all_results.append(result)

                    except Exception as e:
                        logger.warning(f"Error analyzing custom role {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Error querying custom roles for project {project_id}: {e}")
                continue

        return all_results

    def query_service_account_keys(self) -> List[GCPServiceAccountKeyResult]:
        """Analyze service account keys across all projects"""
        from .gcp_iam_analysis import GCPServiceAccountKeyAnalyzer

        all_results = []
        asset_types = ["iam.googleapis.com/ServiceAccountKey"]

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)
                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        if asset.asset_type != "iam.googleapis.com/ServiceAccountKey":
                            continue

                        key_data = asset.resource.data
                        if not key_data:
                            continue

                        # Get application tag
                        application = self._get_application_tag(asset)

                        # Extract key and service account details
                        key_name = key_data.get('name', '')
                        key_id = key_name.split('/')[-1] if '/' in key_name else 'unknown'

                        # Extract service account name from key name
                        sa_name = self._extract_sa_name_from_key(key_name)

                        # Use existing analyzer
                        analysis = GCPServiceAccountKeyAnalyzer.analyze_service_account_key_security(
                            asset.asset_type, key_data
                        )

                        result = GCPServiceAccountKeyResult(
                            application=application,
                            service_account_name=sa_name,
                            key_id=key_id,
                            key_type=analysis['key_type'],
                            key_age=analysis['key_age'],
                            key_usage=analysis['key_usage'],
                            security_risk=analysis['security_risk'],
                            key_details=analysis['key_details'],
                            project_id=project_id,
                            resource_id=asset.name
                        )

                        all_results.append(result)

                    except Exception as e:
                        logger.warning(f"Error analyzing service account key {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Error querying service account keys for project {project_id}: {e}")
                continue

        return all_results

    def get_iam_compliance_summary(self) -> List[GCPIAMComplianceSummary]:
        """Generate IAM compliance summary by application"""

        # Get all IAM analysis results
        service_accounts = self.query_service_account_security()
        iam_bindings = self.query_iam_policy_bindings()
        custom_roles = self.query_custom_roles()
        sa_keys = self.query_service_account_keys()

        # Group by application
        app_data = {}

        # Process service accounts
        for sa in service_accounts:
            app = sa.application
            if app not in app_data:
                app_data[app] = {
                    'service_accounts': [],
                    'iam_bindings': [],
                    'custom_roles': [],
                    'sa_keys': []
                }
            app_data[app]['service_accounts'].append(sa)

        # Process IAM bindings
        for binding in iam_bindings:
            app = binding.application
            if app not in app_data:
                app_data[app] = {
                    'service_accounts': [],
                    'iam_bindings': [],
                    'custom_roles': [],
                    'sa_keys': []
                }
            app_data[app]['iam_bindings'].append(binding)

        # Process custom roles
        for role in custom_roles:
            app = role.application
            if app not in app_data:
                app_data[app] = {
                    'service_accounts': [],
                    'iam_bindings': [],
                    'custom_roles': [],
                    'sa_keys': []
                }
            app_data[app]['custom_roles'].append(role)

        # Process service account keys
        for key in sa_keys:
            app = key.application
            if app not in app_data:
                app_data[app] = {
                    'service_accounts': [],
                    'iam_bindings': [],
                    'custom_roles': [],
                    'sa_keys': []
                }
            app_data[app]['sa_keys'].append(key)

        # Generate summaries
        summaries = []
        for app, data in app_data.items():
            try:
                summary = self._create_iam_compliance_summary(app, data)
                summaries.append(summary)
            except Exception as e:
                logger.warning(f"Error creating IAM compliance summary for {app}: {e}")
                continue

        return summaries

    def query_comprehensive_iam_analysis(self) -> Dict[str, Any]:
        """Perform comprehensive IAM analysis across all areas"""
        try:
            # Run all IAM analyses
            service_account_security = self.query_service_account_security()
            iam_policy_bindings = self.query_iam_policy_bindings()
            custom_roles = self.query_custom_roles()
            workload_identity = self.query_workload_identity()
            service_account_keys = self.query_service_account_keys()
            iam_compliance_summary = self.get_iam_compliance_summary()

            # Calculate summary statistics
            stats = self._calculate_iam_summary_statistics(
                service_account_security,
                iam_policy_bindings,
                custom_roles,
                workload_identity,
                service_account_keys
            )

            return {
                'service_account_security': service_account_security,
                'iam_policy_bindings': iam_policy_bindings,
                'custom_roles': custom_roles,
                'workload_identity': workload_identity,
                'service_account_keys': service_account_keys,
                'iam_compliance_summary': iam_compliance_summary,
                'summary_statistics': stats
            }

        except Exception as e:
            logger.error(f"Error in comprehensive IAM analysis: {e}")
            return {
                'service_account_security': [],
                'iam_policy_bindings': [],
                'custom_roles': [],
                'workload_identity': [],
                'service_account_keys': [],
                'iam_compliance_summary': [],
                'summary_statistics': {
                    'total_iam_resources': 0,
                    'high_risk_configurations': 0,
                    'external_access_bindings': 0,
                    'orphaned_service_accounts': 0
                }
            }

    # 4. ADD MISSING HELPER METHODS TO CLIENT

    @staticmethod
    def _extract_sa_name_from_key(key_name: str) -> str:
        """Extract service account name from key resource name"""
        try:
            # Format: projects/PROJECT/serviceAccounts/SA_EMAIL/keys/KEY_ID
            parts = key_name.split('/')
            for i, part in enumerate(parts):
                if part == 'serviceAccounts' and i + 1 < len(parts):
                    email = parts[i + 1]
                    return email.split('@')[0] if '@' in email else email
            return 'unknown'
        except Exception:
            return 'unknown'

    @staticmethod
    def _create_iam_compliance_summary(application: str, data: Dict) -> 'GCPIAMComplianceSummary':
        """Create IAM compliance summary for an application"""

        try:
            service_accounts = data['service_accounts']
            iam_bindings = data['iam_bindings']
            custom_roles = data['custom_roles']
            sa_keys = data['sa_keys']

            # Count various metrics
            total_service_accounts = len(service_accounts)
            secure_service_accounts = sum(1 for sa in service_accounts if not sa.is_high_risk)
            orphaned_service_accounts = sum(1 for sa in service_accounts if sa.is_orphaned)

            total_custom_roles = len(custom_roles)
            secure_custom_roles = sum(1 for role in custom_roles if not role.is_high_risk)

            total_iam_bindings = len(iam_bindings)
            high_privilege_bindings = sum(1 for binding in iam_bindings if binding.has_high_privileges)
            external_user_bindings = sum(1 for binding in iam_bindings if binding.has_external_users)
            bindings_with_issues = high_privilege_bindings + external_user_bindings

            user_managed_keys = sum(1 for key in sa_keys if key.is_user_managed)
            old_keys = sum(1 for key in sa_keys if key.is_old_key)

            # Calculate total IAM resources and issues
            total_iam_resources = total_service_accounts + total_custom_roles
            total_issues = (total_service_accounts - secure_service_accounts) + \
                           (total_custom_roles - secure_custom_roles) + \
                           user_managed_keys + old_keys

            # Calculate compliance score
            if total_iam_resources > 0:
                iam_compliance_score = max(0, int(100 * (1 - total_issues / max(total_iam_resources, 1))))
            else:
                iam_compliance_score = 100.0

            # Determine status
            if iam_compliance_score >= 90:
                iam_compliance_status = "Excellent"
            elif iam_compliance_score >= 80:
                iam_compliance_status = "Good"
            elif iam_compliance_score >= 70:
                iam_compliance_status = "Fair"
            else:
                iam_compliance_status = "Needs Improvement"

            return GCPIAMComplianceSummary(
                application=application,
                total_iam_resources=total_iam_resources,
                service_account_count=total_service_accounts,  # Added field
                total_service_accounts=total_service_accounts,
                secure_service_accounts=secure_service_accounts,
                orphaned_service_accounts=orphaned_service_accounts,
                custom_role_count=total_custom_roles,  # Added field
                total_custom_roles=total_custom_roles,
                secure_custom_roles=secure_custom_roles,
                total_iam_bindings=total_iam_bindings,
                high_privilege_bindings=high_privilege_bindings,
                external_user_bindings=external_user_bindings,
                bindings_with_issues=bindings_with_issues,  # Added field
                user_managed_keys=user_managed_keys,
                old_keys=old_keys,
                total_issues=total_issues,
                iam_compliance_score=iam_compliance_score,
                iam_compliance_status=iam_compliance_status
            )

        except Exception as e:
            logger.error(f"Error creating IAM compliance summary: {e}")
            # Return minimal summary on error
            return GCPIAMComplianceSummary(
                application=application,
                total_iam_resources=0,
                service_account_count=0,
                total_service_accounts=0,
                secure_service_accounts=0,
                orphaned_service_accounts=0,
                custom_role_count=0,
                total_custom_roles=0,
                secure_custom_roles=0,
                total_iam_bindings=0,
                high_privilege_bindings=0,
                external_user_bindings=0,
                bindings_with_issues=0,
                user_managed_keys=0,
                old_keys=0,
                total_issues=0,
                iam_compliance_score=0.0,
                iam_compliance_status="Unknown"
            )

    @staticmethod
    def _calculate_iam_summary_statistics(service_accounts, iam_bindings, custom_roles, workload_identity,
                                          sa_keys) -> Dict[str, int]:
        """Calculate summary statistics for IAM analysis"""
        try:
            total_iam_resources = len(service_accounts) + len(custom_roles)
            high_risk_configurations = sum(1 for sa in service_accounts if sa.is_high_risk) + \
                                       sum(1 for role in custom_roles if role.is_high_risk) + \
                                       sum(1 for key in sa_keys if key.is_high_risk)
            external_access_bindings = sum(1 for binding in iam_bindings if binding.has_external_users)
            orphaned_service_accounts = sum(1 for sa in service_accounts if sa.is_orphaned)

            return {
                'total_iam_resources': total_iam_resources,
                'high_risk_configurations': high_risk_configurations,
                'external_access_bindings': external_access_bindings,
                'orphaned_service_accounts': orphaned_service_accounts
            }
        except Exception as e:
            logger.warning(f"Error calculating IAM summary statistics: {e}")
            return {
                'total_iam_resources': 0,
                'high_risk_configurations': 0,
                'external_access_bindings': 0,
                'orphaned_service_accounts': 0
            }

    # 5. ADD MISSING HELPER METHODS THAT ARE REFERENCED

    @staticmethod
    def _get_resource_type_display_name(asset_type: str) -> str:
        """Get human-readable display name for asset type"""
        type_mapping = {
            "storage.googleapis.com/Bucket": "Cloud Storage Bucket",
            "compute.googleapis.com/Disk": "Persistent Disk",
            "sqladmin.googleapis.com/Instance": "Cloud SQL Instance",
            "compute.googleapis.com/Instance": "Compute Instance",
            "bigquery.googleapis.com/Dataset": "BigQuery Dataset",
            "spanner.googleapis.com/Instance": "Cloud Spanner Instance",
            "container.googleapis.com/Cluster": "GKE Cluster",
            "iam.googleapis.com/ServiceAccount": "Service Account",
            "iam.googleapis.com/Role": "IAM Role",
            "iam.googleapis.com/ServiceAccountKey": "Service Account Key"
        }
        return type_mapping.get(asset_type, "GCP Resource")

    @staticmethod
    def _extract_resource_name(resource_path: str) -> str:
        """Extract resource name from full resource path"""
        try:
            # Handle different resource path formats
            if '/' in resource_path:
                # Extract the last part after the last slash
                name = resource_path.split('/')[-1]
                # Handle bucket URLs like //storage.googleapis.com/bucket-name
                if resource_path.startswith('//storage.googleapis.com/'):
                    return resource_path.replace('//storage.googleapis.com/', '')
                return name
            return resource_path
        except Exception:
            return "unknown"

    def query_workload_identity(self, asset_types: Optional[List[str]] = None) -> List[GCPWorkloadIdentityResult]:
        """
        GCP Workload Identity analysis - GCP-specific for Kubernetes workload identity federation

        Args:
            asset_types: Optional list of specific asset types to query

        Returns:
            List of GCP Workload Identity analysis results
        """
        if asset_types is None:
            asset_types = GCPIAMAnalysisQueries.get_workload_identity_asset_types()

        # Ensure proper type conversion
        if not isinstance(asset_types, list):
            asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []
        asset_types = [str(item) for item in asset_types if item]

        logger.info("Starting GCP Workload Identity analysis...")
        workload_identity_results = []

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, ["iam.googleapis.com/ServiceAccount"])

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        if 'iam.googleapis.com/ServiceAccount' not in asset.asset_type:
                            continue

                        application = self._get_application_tag(asset)
                        service_account_name = asset.name.split('/')[-1]
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        # Check if this service account has Workload Identity configuration
                        workload_analysis = GCPWorkloadIdentityAnalyzer.analyze_workload_identity_comprehensive(data)

                        # Only include if it's actually configured for Workload Identity
                        if 'Standard Service Account' in workload_analysis['configuration_type']:
                            continue

                        result = GCPWorkloadIdentityResult(
                            application=application,
                            service_account_name=service_account_name,
                            configuration_type=workload_analysis['configuration_type'],
                            workload_binding=workload_analysis['workload_binding'],
                            security_configuration=workload_analysis['security_configuration'],
                            security_risk=workload_analysis['security_risk'],
                            workload_details=workload_analysis['workload_details'],
                            kubernetes_integration=workload_analysis['kubernetes_integration'],
                            project_id=project_id,
                            resource_id=asset.name
                        )

                        workload_identity_results.append(result)

                    except Exception as e:
                        logger.warning(f"Failed to analyze Workload Identity for {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"Workload Identity analysis complete. Analyzed {len(workload_identity_results)} configurations")
        return workload_identity_results

    def query_vpc_network_analysis(self, asset_types: Optional[List[str]] = None) -> List[GCPNetworkResource]:
        """
        VPC network security analysis - equivalent to Azure's query_network_analysis
        FIXED: Proper error handling and type safety
        """
        try:
            if asset_types is None:
                asset_types = GCPNetworkAnalysisQueries.get_vpc_network_security_asset_types()

            # Ensure proper type conversion
            if not isinstance(asset_types, list):
                asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []
            asset_types = [str(item) for item in asset_types if item]

            logger.info("Starting GCP VPC network security analysis...")
            network_resources = []

            for project_id in self.project_ids:
                try:
                    parent = f"projects/{project_id}"
                    request = self._create_list_assets_request(parent, asset_types)

                    response = self._make_rate_limited_request(
                        self.asset_client.list_assets,
                        request=request
                    )

                    for asset in response:
                        try:
                            application = self._get_application_tag(asset)
                            resource_name = asset.name.split('/')[-1] if asset.name else 'Unknown'
                            location = getattr(asset.resource, 'location', 'global')

                            # Safely extract data
                            if hasattr(asset.resource, 'data') and asset.resource.data is not None:
                                data = dict(asset.resource.data)
                            else:
                                data = {}

                            # Use network security analyzer with error handling
                            try:
                                security_analysis = GCPNetworkSecurityAnalyzer.analyze_vpc_network_security_comprehensive(
                                    asset.asset_type, data)
                            except Exception as e:
                                logger.warning(f"Security analysis failed for {asset.name}: {e}")
                                # Provide default values
                                security_analysis = {
                                    'security_findings': 'Analysis failed',
                                    'security_risk': 'Manual review needed',
                                    'network_details': 'Error in analysis'
                                }

                            # Determine network resource type
                            network_resource_type = self._get_resource_type_name(asset.asset_type)

                            # Get additional details with error handling
                            additional_details = security_analysis.get('network_details', 'No details available')

                            # Create the resource object
                            resource = GCPNetworkResource(
                                application=application,
                                network_resource=resource_name,
                                network_resource_type=network_resource_type,
                                security_findings=security_analysis.get('security_findings', 'No findings'),
                                compliance_risk=security_analysis.get('security_risk', 'Unknown risk'),
                                resource_group=project_id,
                                location=location,
                                additional_details=additional_details,
                                resource_id=asset.name
                            )

                            network_resources.append(resource)

                        except Exception as e:
                            logger.warning(
                                f"Failed to analyze network resource {getattr(asset, 'name', 'Unknown')}: {e}")
                            continue

                except Exception as e:
                    logger.error(f"Failed to scan project {project_id}: {e}")
                    continue

            logger.info(f"VPC network analysis complete. Found {len(network_resources)} network resources")
            return network_resources

        except Exception as e:
            logger.error(f"VPC network analysis failed completely: {e}")
            return []  # Return empty list on complete failure

    # Similar pattern for other methods
    def query_firewall_rules_detailed(self, asset_types: Optional[List[str]] = None) -> List[GCPFirewallRule]:
        """
        Firewall rules detailed analysis - FIXED: Proper error handling
        """
        try:
            if asset_types is None:
                asset_types = GCPNetworkAnalysisQueries.get_firewall_rules_analysis_asset_types()

            # Ensure proper type conversion
            if not isinstance(asset_types, list):
                asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []
            asset_types = [str(item) for item in asset_types if item]

            logger.info("Starting GCP firewall rules detailed analysis...")
            firewall_rules = []

            for project_id in self.project_ids:
                try:
                    parent = f"projects/{project_id}"
                    request = self._create_list_assets_request(parent, asset_types)

                    response = self._make_rate_limited_request(
                        self.asset_client.list_assets,
                        request=request
                    )

                    for asset in response:
                        try:
                            if 'compute.googleapis.com/Firewall' not in asset.asset_type:
                                continue

                            application = self._get_application_tag(asset)
                            firewall_name = asset.name.split('/')[-1] if asset.name else 'Unknown'

                            # Safely extract data
                            if hasattr(asset.resource, 'data') and asset.resource.data is not None:
                                data = dict(asset.resource.data)
                            else:
                                data = {}

                            # Extract firewall rule details with defaults
                            direction = data.get('direction', 'INGRESS')
                            action = 'ALLOW' if data.get('allowed') else 'DENY'
                            priority = data.get('priority', 1000)
                            source_ranges = data.get('sourceRanges', [])
                            target_tags = data.get('targetTags', [])
                            allowed_rules = data.get('allowed', [])
                            denied_rules = data.get('denied', [])

                            # Analyze firewall rule security with error handling
                            try:
                                firewall_analysis = GCPFirewallRuleAnalyzer.analyze_firewall_rule_security(
                                    asset.asset_type, data)
                            except Exception as e:
                                logger.warning(f"Firewall analysis failed for {asset.name}: {e}")
                                firewall_analysis = {
                                    'security_risk': 'Analysis failed - manual review needed'
                                }

                            # Format rule details for display with safe handling
                            protocol_ports = []
                            try:
                                for rule in allowed_rules:
                                    protocol = rule.get('IPProtocol', 'unknown')
                                    ports = rule.get('ports', [])
                                    if ports:
                                        protocol_ports.append(f"{protocol}:{','.join(map(str, ports))}")
                                    else:
                                        protocol_ports.append(f"{protocol}:all")

                                for rule in denied_rules:
                                    protocol = rule.get('IPProtocol', 'unknown')
                                    ports = rule.get('ports', [])
                                    if ports:
                                        protocol_ports.append(f"DENY-{protocol}:{','.join(map(str, ports))}")
                                    else:
                                        protocol_ports.append(f"DENY-{protocol}:all")
                            except Exception as e:
                                logger.warning(f"Failed to parse protocol/ports for {asset.name}: {e}")
                                protocol_ports = ['unknown']

                            port_ranges = "; ".join(protocol_ports) if protocol_ports else "None"

                            # Format source and target information
                            source_info = "; ".join(source_ranges) if source_ranges else "Not specified"
                            target_info = "; ".join(target_tags) if target_tags else "All instances"

                            rule = GCPFirewallRule(
                                application=application,
                                firewall_name=firewall_name,
                                rule_name=firewall_name,  # In GCP, firewall name is the rule name
                                action=action,
                                direction=direction,
                                priority=priority,
                                protocol=protocol_ports[0].split(':')[0] if protocol_ports else 'unknown',
                                source_ranges=source_info,
                                target_tags=target_info,
                                port_ranges=port_ranges,
                                risk_level=firewall_analysis.get('security_risk', 'Unknown risk'),
                                resource_group=project_id,
                                resource_id=asset.name
                            )

                            firewall_rules.append(rule)

                        except Exception as e:
                            logger.warning(f"Failed to analyze firewall rule {getattr(asset, 'name', 'Unknown')}: {e}")
                            continue

                except Exception as e:
                    logger.error(f"Failed to scan project {project_id}: {e}")
                    continue

            logger.info(f"Firewall rules analysis complete. Analyzed {len(firewall_rules)} rules")
            return firewall_rules

        except Exception as e:
            logger.error(f"Firewall rules analysis failed completely: {e}")
            return []  # Return empty list on complete failure

    def query_vpc_network_security(self, asset_types: Optional[List[str]] = None) -> List[GCPNetworkResource]:
        """
        VPC network security analysis - ALIAS METHOD matching Azure pattern

        Args:
            asset_types: Optional list of specific asset types to query

        Returns:
            List of GCP VPC network security analysis results
        """
        logger.info("Starting VPC network security analysis (alias to comprehensive network analysis)...")
        return self.query_vpc_network_analysis(asset_types)

    def query_ssl_certificate_analysis(self, asset_types: Optional[List[str]] = None) -> List[
        GCPSSLCertificateResult]:
        """
        SSL certificate analysis - equivalent to Azure's query_certificate_analysis

        Args:
            asset_types: Optional list of specific asset types to query

        Returns:
            List of GCP SSL certificate analysis results
        """
        if asset_types is None:
            asset_types = GCPNetworkAnalysisQueries.get_ssl_certificate_analysis_asset_types()

        # Ensure proper type conversion
        if not isinstance(asset_types, list):
            asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []
        asset_types = [str(item) for item in asset_types if item]

        logger.info("Starting GCP SSL certificate analysis...")
        certificate_results = []

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        application = self._get_application_tag(asset)
                        resource_name = asset.name.split('/')[-1]
                        location = getattr(asset.resource, 'location', 'global')
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        # Use SSL certificate analyzer
                        cert_analysis = GCPSSLCertificateAnalyzer.analyze_ssl_certificate_security(
                            asset.asset_type, data)

                        # Determine certificate count
                        cert_count = 1  # Default for single certificates
                        if 'TargetHttpsProxy' in asset.asset_type:
                            ssl_certificates = data.get('sslCertificates', [])
                            cert_count = len(ssl_certificates)

                        result = GCPSSLCertificateResult(
                            application=application,
                            resource_name=resource_name,
                            resource_type=self._get_resource_type_name(asset.asset_type),
                            certificate_count=cert_count,
                            ssl_policy_details=cert_analysis['certificate_configuration'],
                            compliance_status=cert_analysis['compliance_status'],
                            security_risk=cert_analysis['security_risk'],
                            listener_details=cert_analysis['certificate_details'],
                            resource_group=project_id,
                            location=location,
                            resource_id=asset.name
                        )

                        certificate_results.append(result)

                    except Exception as e:
                        logger.warning(f"Failed to analyze SSL certificate {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"SSL certificate analysis complete. Analyzed {len(certificate_results)} certificates")
        return certificate_results

    def query_network_topology(self, asset_types: Optional[List[str]] = None) -> List[GCPNetworkTopologyResult]:
        """
        Network topology analysis - equivalent to Azure's query_network_topology

        Args:
            asset_types: Optional list of specific asset types to query

        Returns:
            List of GCP network topology analysis results
        """
        if asset_types is None:
            asset_types = GCPNetworkAnalysisQueries.get_network_topology_asset_types()

        # Ensure proper type conversion
        if not isinstance(asset_types, list):
            asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []
        asset_types = [str(item) for item in asset_types if item]

        logger.info("Starting GCP network topology analysis...")
        topology_results = []

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        application = self._get_application_tag(asset)
                        resource_name = asset.name.split('/')[-1]
                        location = getattr(asset.resource, 'location', 'global')
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        # Use network topology analyzer
                        topology_analysis = GCPNetworkTopologyAnalyzer.analyze_network_topology(
                            asset.asset_type, data)

                        result = GCPNetworkTopologyResult(
                            application=application,
                            network_resource=resource_name,
                            topology_type=topology_analysis['topology_type'],
                            network_configuration=topology_analysis['network_configuration'],
                            configuration_risk=topology_analysis['configuration_risk'],
                            security_implications=topology_analysis['security_implications'],
                            resource_group=project_id,
                            location=location,
                            resource_id=asset.name
                        )

                        topology_results.append(result)

                    except Exception as e:
                        logger.warning(f"Failed to analyze network topology {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"Network topology analysis complete. Analyzed {len(topology_results)} resources")
        return topology_results

    def query_network_resource_optimization(self, asset_types: Optional[List[str]] = None) -> List[
        GCPNetworkOptimizationResult]:
        """
        Network resource optimization analysis - equivalent to Azure's query_resource_optimization

        Args:
            asset_types: Optional list of specific asset types to query

        Returns:
            List of GCP network resource optimization results
        """
        if asset_types is None:
            asset_types = GCPNetworkAnalysisQueries.get_network_optimization_asset_types()

        # Ensure proper type conversion
        if not isinstance(asset_types, list):
            asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []
        asset_types = [str(item) for item in asset_types if item]

        logger.info("Starting GCP network resource optimization analysis...")
        optimization_results = []

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        application = self._get_application_tag(asset)
                        resource_name = asset.name.split('/')[-1]
                        location = getattr(asset.resource, 'location', 'global')
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        # Use network optimization analyzer
                        optimization_analysis = GCPNetworkOptimizationAnalyzer.analyze_network_resource_optimization(
                            asset.asset_type, data)

                        result = GCPNetworkOptimizationResult(
                            application=application,
                            resource_name=resource_name,
                            optimization_type=optimization_analysis['optimization_type'],
                            utilization_status=optimization_analysis['utilization_status'],
                            cost_optimization_potential=optimization_analysis['cost_optimization_potential'],
                            resource_details=optimization_analysis['resource_details'],
                            resource_group=project_id,
                            location=location,
                            resource_id=asset.name
                        )

                        optimization_results.append(result)

                    except Exception as e:
                        logger.warning(f"Failed to analyze network optimization {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"Network optimization analysis complete. Analyzed {len(optimization_results)} resources")
        return optimization_results

    def get_network_compliance_summary(self) -> List[GCPNetworkComplianceSummary]:
        """
        Generate network compliance summary by application - equivalent to Azure's get_network_compliance_summary

        Returns:
            List of network compliance summaries
        """
        logger.info("Generating network compliance summary...")

        # Get all network resources
        network_resources = self.query_vpc_network_analysis()
        firewall_rules = self.query_firewall_rules_detailed()
        ssl_certificates = self.query_ssl_certificate_analysis()

        # Group by application
        app_summaries = {}

        # Process network resources
        for resource in network_resources:
            app = resource.application
            if app not in app_summaries:
                app_summaries[app] = {
                    'total': 0, 'vpc_networks': 0, 'firewall_rules': 0, 'ssl_certs': 0,
                    'load_balancers': 0, 'issues': 0
                }

            summary = app_summaries[app]
            summary['total'] += 1

            # Count by type
            if resource.is_vpc_network:
                summary['vpc_networks'] += 1
            elif 'Load Balancer' in resource.network_resource_type:
                summary['load_balancers'] += 1

            # Issues
            if resource.is_high_risk:
                summary['issues'] += 1

        # Process firewall rules
        for rule in firewall_rules:
            app = rule.application
            if app not in app_summaries:
                app_summaries[app] = {
                    'total': 0, 'vpc_networks': 0, 'firewall_rules': 0, 'ssl_certs': 0,
                    'load_balancers': 0, 'issues': 0
                }

            summary = app_summaries[app]
            summary['total'] += 1
            summary['firewall_rules'] += 1

            if rule.is_high_risk:
                summary['issues'] += 1

        # Process SSL certificates
        for cert in ssl_certificates:
            app = cert.application
            if app not in app_summaries:
                app_summaries[app] = {
                    'total': 0, 'vpc_networks': 0, 'firewall_rules': 0, 'ssl_certs': 0,
                    'load_balancers': 0, 'issues': 0
                }

            summary = app_summaries[app]
            summary['total'] += 1
            summary['ssl_certs'] += 1

            if 'Load Balancer' in cert.resource_type:
                summary['load_balancers'] += 1

            if cert.is_high_risk:
                summary['issues'] += 1

        # Create summary objects
        summaries = []
        for app, data in app_summaries.items():
            if data['total'] == 0:
                continue

            security_score = ((data['total'] - data['issues']) / data['total'] * 100) if data['total'] > 0 else 100

            if security_score >= 95:
                status = 'Excellent'
            elif security_score >= 85:
                status = 'Good'
            elif security_score >= 70:
                status = 'Acceptable'
            elif security_score >= 50:
                status = 'Needs Improvement'
            else:
                status = 'Critical Issues'

            summary = GCPNetworkComplianceSummary(
                application=app,
                total_network_resources=data['total'],
                vpc_network_count=data['vpc_networks'],
                firewall_rule_count=data['firewall_rules'],
                ssl_certificate_count=data['ssl_certs'],
                load_balancer_count=data['load_balancers'],
                resources_with_issues=data['issues'],
                security_score=round(security_score, 1),
                security_status=status
            )

            summaries.append(summary)

        logger.info(f"Generated network compliance summary for {len(summaries)} applications")
        return summaries

    def query_comprehensive_network_analysis(self) -> Dict[str, Any]:
        """
        Perform comprehensive network analysis - equivalent to Azure's comprehensive network analysis

        Returns:
            Dictionary containing all network analysis results
        """
        logger.info("Starting comprehensive GCP network analysis...")

        results = {}

        try:
            logger.info("Analyzing VPC network security...")
            results['vpc_network_security'] = self.query_vpc_network_analysis()
            logger.info(f"   Found {len(results['vpc_network_security'])} network resources")
        except Exception as e:
            logger.error(f"VPC network security analysis failed: {e}")
            results['vpc_network_security'] = []

        try:
            logger.info("Analyzing firewall rules...")
            results['firewall_rules'] = self.query_firewall_rules_detailed()
            logger.info(f"   Found {len(results['firewall_rules'])} firewall rules")
        except Exception as e:
            logger.error(f"Firewall rules analysis failed: {e}")
            results['firewall_rules'] = []

        try:
            logger.info("Analyzing SSL certificates...")
            results['ssl_certificates'] = self.query_ssl_certificate_analysis()
            logger.info(f"   Found {len(results['ssl_certificates'])} SSL certificates")
        except Exception as e:
            logger.error(f"SSL certificate analysis failed: {e}")
            results['ssl_certificates'] = []

        try:
            logger.info("Analyzing network topology...")
            results['network_topology'] = self.query_network_topology()
            logger.info(f"   Analyzed {len(results['network_topology'])} topology resources")
        except Exception as e:
            logger.error(f"Network topology analysis failed: {e}")
            results['network_topology'] = []

        try:
            logger.info("Analyzing network optimization...")
            results['network_optimization'] = self.query_network_resource_optimization()
            logger.info(f"   Found {len(results['network_optimization'])} optimization opportunities")
        except Exception as e:
            logger.error(f"Network optimization analysis failed: {e}")
            results['network_optimization'] = []

        try:
            logger.info("Generating compliance summary...")
            results['compliance_summary'] = self.get_network_compliance_summary()
            logger.info(f"   Generated summary for {len(results['compliance_summary'])} applications")
        except Exception as e:
            logger.error(f"Compliance summary generation failed: {e}")
            results['compliance_summary'] = []

        # Calculate summary statistics
        total_network_resources = (len(results['vpc_network_security']) +
                                   len(results['firewall_rules']) +
                                   len(results['ssl_certificates']))

        high_risk_count = 0
        high_risk_count += len([r for r in results['vpc_network_security'] if r.is_high_risk])
        high_risk_count += len([r for r in results['firewall_rules'] if r.is_high_risk])
        high_risk_count += len([r for r in results['ssl_certificates'] if r.is_high_risk])

        optimization_opportunities = len(
            [r for r in results['network_optimization'] if r.has_high_optimization_potential])

        logger.info(f"GCP network analysis complete!")
        logger.info(f"   Total network resources: {total_network_resources}")
        logger.info(f"   High-risk configurations: {high_risk_count}")
        logger.info(f"   High-value optimization opportunities: {optimization_opportunities}")
        logger.info(f"   Applications covered: {len(results['compliance_summary'])}")

        # Add summary statistics to results
        results['summary_statistics'] = {
            'total_network_resources': total_network_resources,
            'high_risk_configurations': high_risk_count,
            'optimization_opportunities': optimization_opportunities
        }

        return results

    def _analyze_vm_security(self, vm_asset) -> GCPVMSecurityResult:
        """Analyze VM security configuration"""
        vm_data = dict(vm_asset.resource.data)
        vm_name = vm_data.get('name', 'Unknown')

        # Basic VM info
        machine_type = vm_data.get('machineType', '').split('/')[-1] if vm_data.get('machineType') else 'Unknown'
        instance_status = vm_data.get('status', 'Unknown')
        zone = vm_data.get('zone', '').split('/')[-1] if vm_data.get('zone') else vm_asset.resource.location

        # Machine type category
        if machine_type.startswith('n2-'):
            machine_type_category = "General Purpose - N2 Series"
        elif machine_type.startswith('e2-'):
            machine_type_category = "Cost Optimized - E2 Series"
        elif machine_type.startswith('n1-'):
            machine_type_category = "Legacy - N1 Series"
        elif machine_type.startswith('f1-'):
            machine_type_category = "Legacy - Deprecated Series"
        else:
            machine_type_category = "General Purpose"

        # Encryption analysis - only CMEK counts as encrypted
        disks = vm_data.get('disks', [])
        has_cmek = False
        if disks:
            boot_disk = next((disk for disk in disks if disk.get('boot')), disks[0])
            kms_key = boot_disk.get('diskEncryptionKey', {}).get('kmsKeyName')
            has_cmek = bool(kms_key)

        if has_cmek:
            disk_encryption = "Customer Managed Key (CMEK) - Highest Security"
        else:
            disk_encryption = "Google Managed Key - Standard Security"

        # Shielded VM analysis
        shielded_config = vm_data.get('shieldedInstanceConfig', {})
        has_vtpm = shielded_config.get('enableVtpm', False)
        has_integrity = shielded_config.get('enableIntegrityMonitoring', False)
        has_secure_boot = shielded_config.get('enableSecureBoot', False)
        has_shielded = any([has_vtpm, has_integrity, has_secure_boot])

        # OS Login analysis
        metadata = vm_data.get('metadata', {})
        items = metadata.get('items', [])
        has_os_login = False
        for item in items:
            if item.get('key') == 'enable-oslogin' and item.get('value', '').upper() == 'TRUE':
                has_os_login = True
                break

        # Security configuration
        features = []
        if has_vtpm:
            features.append("vTPM Enabled")
        if has_integrity:
            features.append("Integrity Monitoring")
        if has_secure_boot:
            features.append("Secure Boot")
        if has_os_login:
            features.append("OS Login Enabled")

        if features:
            security_configuration = f"Security Features: {', '.join(features)}"
        else:
            security_configuration = "Basic Security Configuration - No Advanced Features"

        # Security findings
        findings = []
        if has_cmek:
            findings.append("Advanced encryption configured")
        if has_shielded:
            findings.append("Shielded VM features active")

        security_findings = "; ".join(findings) if findings else "Standard security configuration"

        # Risk assessment and compliance
        network_interfaces = vm_data.get('networkInterfaces', [])
        has_external_ip = any(interface.get('accessConfigs') for interface in network_interfaces)

        # Count security features
        security_features = sum([has_shielded, has_cmek, has_os_login])

        if security_features >= 2:
            security_risk = "Low - Good security configuration"
            compliance_status = "Compliant"
        elif security_features == 1:
            security_risk = "Low - Good security configuration"
            compliance_status = "Compliant"
        else:
            if "Legacy" in machine_type_category:
                security_risk = "High - Legacy machine type without advanced security"
            else:
                security_risk = "High - Multiple security concerns: No advanced security features"
            compliance_status = "Non-Compliant"

        # VM details
        vm_details = f"Machine Type: {machine_type} | Zone: {zone}"
        if vm_data.get('scheduling', {}).get('preemptible'):
            vm_details += " | Preemptible Instance"

        boot_disk_name = "Unknown"
        if disks:
            boot_disk = next((disk for disk in disks if disk.get('boot')), disks[0])
            boot_disk_name = boot_disk.get('source', '').split('/')[-1] if boot_disk.get('source') else 'Unknown'
        vm_details += f" | Boot Disk: {boot_disk_name}"

        return GCPVMSecurityResult(
            application=self._get_application_tag(vm_asset),
            vm_name=vm_name,
            machine_type=machine_type,
            machine_type_category=machine_type_category,
            instance_status=instance_status,
            zone=zone,
            disk_encryption=disk_encryption,
            security_configuration=security_configuration,
            security_findings=security_findings,
            security_risk=security_risk,
            compliance_status=compliance_status,
            vm_details=vm_details,
            project_id=vm_asset.name.split('/')[4],
            resource_id=vm_asset.name
        )

    def get_vm_governance_summary(self) -> List[GCPVMGovernanceSummary]:
        """Generate VM governance summary by application"""
        security_results = self.query_vm_security()
        optimization_results = self.query_vm_optimization()

        if not security_results:
            return []

        # Group by application
        app_data = {}
        for vm in security_results:
            app = vm.application
            if app not in app_data:
                app_data[app] = {'security': [], 'optimization': []}
            app_data[app]['security'].append(vm)

        for vm in optimization_results:
            app = vm.application
            if app in app_data:
                app_data[app]['optimization'].append(vm)

        summaries = []
        for app, data in app_data.items():
            security_vms = data['security']
            optimization_vms = data['optimization']

            total_vms = len(security_vms)
            running_vms = sum(1 for vm in security_vms if vm.is_running)
            stopped_vms = total_vms - running_vms

            # Only count CMEK as encrypted
            encrypted_vms = sum(1 for vm in security_vms if vm.is_encrypted)

            # Count shielded VMs
            shielded_vms = sum(1 for vm in security_vms if vm.has_shielded_vm)

            # Estimate Linux/Windows split
            linux_vms = max(1, int(total_vms * 0.6))
            windows_vms = total_vms - linux_vms

            # Optimization metrics
            preemptible_vms = 0
            legacy_vms = 0
            optimized_vms = 0

            for vm in optimization_vms:
                if "preemptible" in vm.scheduling_configuration.lower():
                    preemptible_vms += 1
                if vm.is_legacy_machine_type:
                    legacy_vms += 1
                if not vm.has_high_optimization_potential:
                    optimized_vms += 1

            # Issues calculation
            high_risk_security = sum(1 for vm in security_vms if vm.is_high_risk)
            high_optimization = sum(1 for vm in optimization_vms if vm.has_high_optimization_potential)
            vms_with_issues = high_risk_security + high_optimization

            # Calculate governance score
            score = 0
            if total_vms > 0:
                score += (encrypted_vms / total_vms) * 40
                score += (shielded_vms / total_vms) * 30
                score += ((total_vms - legacy_vms) / total_vms) * 20
                score -= (vms_with_issues / total_vms) * 10

            governance_score = max(0, min(100, score))

            if governance_score >= 90:
                status = "Excellent"
            elif governance_score >= 80:
                status = "Good"
            elif governance_score >= 60:
                status = "Acceptable"
            else:
                status = "Critical Issues"

            summary = GCPVMGovernanceSummary(
                application=app,
                total_vms=total_vms,
                linux_vms=linux_vms,
                windows_vms=windows_vms,
                running_vms=running_vms,
                stopped_vms=stopped_vms,
                preemptible_vms=preemptible_vms,
                encrypted_vms=encrypted_vms,
                shielded_vms=shielded_vms,
                legacy_machine_type_vms=legacy_vms,
                optimized_vms=optimized_vms,
                vms_with_issues=vms_with_issues,
                governance_score=governance_score,
                governance_status=status
            )
            summaries.append(summary)

        return summaries

    def get_compute_compliance_summary(self) -> List[GCPComputeComplianceSummary]:
        """
        Generate compute compliance summary by application

        Returns:
            List of GCPComputeComplianceSummary objects summarizing compute compliance by application
        """
        try:
            logger.info("Generating compute compliance summary")

            # Get VM governance summary
            vm_summaries = self.get_vm_governance_summary()

            compliance_summaries = []

            for vm_summary in vm_summaries:
                # Calculate compliance metrics
                total_compute_resources = vm_summary.total_vms
                secure_compute_resources = vm_summary.encrypted_vms + vm_summary.shielded_vms
                # Avoid double counting - use max of encrypted and shielded
                secure_compute_resources = max(vm_summary.encrypted_vms, vm_summary.shielded_vms)

                compliance_summary = GCPComputeComplianceSummary(
                    application=vm_summary.application,

                    # Core compute resource counts
                    total_compute_resources=total_compute_resources,
                    compute_instances=vm_summary.total_vms,
                    gke_nodes=0,  # Would need separate GKE analysis
                    cloud_functions=0,  # Would need separate Cloud Functions analysis
                    cloud_run_services=0,  # Would need separate Cloud Run analysis
                    app_engine_services=0,  # Would need separate App Engine analysis

                    # Security and compliance metrics
                    secure_compute_resources=secure_compute_resources,
                    encrypted_resources=vm_summary.encrypted_vms,
                    resources_with_issues=vm_summary.vms_with_issues,

                    # Primary compliance scoring
                    compute_compliance_score=vm_summary.governance_score,
                    compute_compliance_status=vm_summary.governance_status,

                    # VM-specific fields that tests expect
                    total_instances=vm_summary.total_vms,
                    running_instances=vm_summary.running_vms,
                    stopped_instances=vm_summary.stopped_vms,
                    encrypted_instances=vm_summary.encrypted_vms,
                    properly_configured_instances=vm_summary.optimized_vms,
                    instances_with_issues=vm_summary.vms_with_issues,

                    # Additional scoring metrics
                    security_score=vm_summary.governance_score,
                    optimization_score=vm_summary.governance_score,  # Could be calculated separately
                    compliance_status=vm_summary.governance_status
                )

                compliance_summaries.append(compliance_summary)

            logger.info(f"Generated {len(compliance_summaries)} compute compliance summaries")
            return compliance_summaries

        except Exception as e:
            logger.error(f"Failed to generate compute compliance summary: {e}")
            return []

    def query_vm_security(self, asset_types: Optional[List[str]] = None) -> List[GCPVMSecurityResult]:
        """
        GCP Compute Engine VM security analysis - equivalent to Azure's query_vm_security

        Args:
            asset_types: Optional list of specific asset types to query

        Returns:
            List of GCP VM security analysis results
        """
        if asset_types is None:
            asset_types = GCPComputeGovernanceQueries.get_compute_security_asset_types()

        # Ensure proper type conversion
        if not isinstance(asset_types, list):
            asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []
        asset_types = [str(item) for item in asset_types if item]

        logger.info("Starting GCP Compute Engine VM security analysis...")
        vm_security_results = []

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, ["compute.googleapis.com/Instance"])

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        if 'compute.googleapis.com/Instance' not in asset.asset_type:
                            continue

                        application = self._get_application_tag(asset)
                        vm_name = asset.name.split('/')[-1]
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        # Extract basic instance information
                        machine_type = data.get('machineType', '').split('/')[-1]
                        status = data.get('status', 'UNKNOWN')
                        zone = data.get('zone', '').split('/')[-1]

                        # Use enhanced security analyzer
                        security_analysis = GCPComputeSecurityAnalyzer.analyze_vm_security_comprehensive(
                            asset.asset_type, data)

                        # Determine machine type category
                        machine_type_category = GCPComputeOptimizationAnalyzer._categorize_machine_type(machine_type)

                        result = GCPVMSecurityResult(
                            application=application,
                            vm_name=vm_name,
                            machine_type=machine_type,
                            machine_type_category=machine_type_category,
                            instance_status=status,
                            zone=zone,
                            disk_encryption=security_analysis['disk_encryption'],
                            security_configuration=security_analysis['security_configuration'],
                            security_findings=security_analysis['security_findings'],
                            security_risk=security_analysis['security_risk'],
                            compliance_status=security_analysis['compliance_status'],
                            vm_details=security_analysis['vm_details'],
                            project_id=project_id,
                            resource_id=asset.name
                        )

                        vm_security_results.append(result)

                    except Exception as e:
                        logger.warning(f"Failed to analyze VM security for {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"VM security analysis complete. Analyzed {len(vm_security_results)} instances")
        return vm_security_results

    def query_vm_optimization(self, asset_types: Optional[List[str]] = None) -> List[GCPVMOptimizationResult]:
        """
        GCP Compute Engine VM optimization analysis - equivalent to Azure's query_vm_optimization

        Args:
            asset_types: Optional list of specific asset types to query

        Returns:
            List of GCP VM optimization analysis results
        """
        if asset_types is None:
            asset_types = GCPComputeGovernanceQueries.get_compute_optimization_asset_types()

        # Ensure proper type conversion
        if not isinstance(asset_types, list):
            asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []
        asset_types = [str(item) for item in asset_types if item]

        logger.info("Starting GCP Compute Engine VM optimization analysis...")
        vm_optimization_results = []

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, ["compute.googleapis.com/Instance"])

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        if 'compute.googleapis.com/Instance' not in asset.asset_type:
                            continue

                        application = self._get_application_tag(asset)
                        vm_name = asset.name.split('/')[-1]
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        # Extract basic instance information
                        machine_type = data.get('machineType', '').split('/')[-1]
                        status = data.get('status', 'UNKNOWN')
                        zone = data.get('zone', '').split('/')[-1]

                        # Use enhanced optimization analyzer
                        optimization_analysis = GCPComputeOptimizationAnalyzer.analyze_vm_optimization_comprehensive(
                            asset.asset_type, data)

                        result = GCPVMOptimizationResult(
                            application=application,
                            vm_name=vm_name,
                            machine_type=machine_type,
                            machine_type_category=optimization_analysis['machine_type_category'],
                            instance_status=status,
                            scheduling_configuration=optimization_analysis['scheduling_configuration'],
                            utilization_status=optimization_analysis['utilization_status'],
                            optimization_potential=optimization_analysis['optimization_potential'],
                            optimization_recommendation=optimization_analysis['optimization_recommendation'],
                            estimated_monthly_cost=optimization_analysis['estimated_monthly_cost'],
                            days_running=optimization_analysis['days_running'],
                            committed_use_discount=optimization_analysis['committed_use_discount'],
                            preemptible_suitable=optimization_analysis['preemptible_suitable'],
                            project_id=project_id,
                            zone=zone,
                            resource_id=asset.name
                        )

                        vm_optimization_results.append(result)

                    except Exception as e:
                        logger.warning(f"Failed to analyze VM optimization for {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"VM optimization analysis complete. Analyzed {len(vm_optimization_results)} instances")
        return vm_optimization_results

    def query_vm_configurations(self, asset_types: Optional[List[str]] = None) -> List[GCPVMConfigurationResult]:
        """
        GCP Compute Engine VM configuration analysis - equivalent to Azure's query_vm_extensions

        Args:
            asset_types: Optional list of specific asset types to query

        Returns:
            List of GCP VM configuration analysis results
        """
        if asset_types is None:
            asset_types = ["compute.googleapis.com/Instance"]

        # Ensure proper type conversion
        if not isinstance(asset_types, list):
            asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []
        asset_types = [str(item) for item in asset_types if item]

        logger.info("Starting GCP Compute Engine VM configuration analysis...")
        vm_configuration_results = []

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        if 'compute.googleapis.com/Instance' not in asset.asset_type:
                            continue

                        application = self._get_application_tag(asset)
                        vm_name = asset.name.split('/')[-1]
                        zone = asset.name.split('/')[-3] if len(asset.name.split('/')) >= 3 else 'unknown'
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        # Use enhanced configuration analyzer
                        configuration_analyses = GCPComputeConfigurationAnalyzer.analyze_vm_configuration_comprehensive(
                            asset.asset_type, data)

                        # Create a result for each configuration type analyzed
                        for config_analysis in configuration_analyses:
                            result = GCPVMConfigurationResult(
                                application=application,
                                vm_name=vm_name,
                                configuration_type=config_analysis['configuration_type'],
                                configuration_name=config_analysis['configuration_name'],
                                configuration_category=config_analysis['configuration_category'],
                                configuration_status=config_analysis['configuration_status'],
                                installation_method=config_analysis['installation_method'],
                                security_importance=config_analysis['security_importance'],
                                compliance_impact=config_analysis['compliance_impact'],
                                configuration_details=config_analysis['configuration_details'],
                                project_id=project_id,
                                zone=zone,
                                resource_id=asset.name
                            )

                            vm_configuration_results.append(result)

                    except Exception as e:
                        logger.warning(f"Failed to analyze VM configurations for {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"VM configuration analysis complete. Analyzed {len(vm_configuration_results)} configurations")
        return vm_configuration_results

    def query_vm_patch_compliance(self, asset_types: Optional[List[str]] = None) -> List[GCPVMPatchComplianceResult]:
        """
        GCP Compute Engine VM patch compliance analysis - equivalent to Azure's query_vm_patch_compliance

        Args:
            asset_types: Optional list of specific asset types to query

        Returns:
            List of GCP VM patch compliance analysis results
        """
        if asset_types is None:
            asset_types = ["compute.googleapis.com/Instance"]

        # Ensure proper type conversion
        if not isinstance(asset_types, list):
            asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []
        asset_types = [str(item) for item in asset_types if item]

        logger.info("Starting GCP Compute Engine VM patch compliance analysis...")
        vm_patch_results = []

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        if 'compute.googleapis.com/Instance' not in asset.asset_type:
                            continue

                        application = self._get_application_tag(asset)
                        vm_name = asset.name.split('/')[-1]
                        zone = asset.name.split('/')[-3] if len(asset.name.split('/')) >= 3 else 'unknown'
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        # Extract basic instance information
                        status = data.get('status', 'UNKNOWN')

                        # Use enhanced patch compliance analyzer
                        patch_analysis = GCPComputePatchComplianceAnalyzer.analyze_patch_compliance_comprehensive(
                            asset.asset_type, data)

                        result = GCPVMPatchComplianceResult(
                            application=application,
                            vm_name=vm_name,
                            os_type=patch_analysis['os_type'],
                            instance_status=status,
                            os_config_agent_status=patch_analysis['os_config_agent_status'],
                            patch_deployment_status=patch_analysis['patch_deployment_status'],
                            patch_compliance_status=patch_analysis['patch_compliance_status'],
                            patch_risk=patch_analysis['patch_risk'],
                            last_patch_time=patch_analysis['last_patch_time'],
                            available_patches=patch_analysis['available_patches'],
                            project_id=project_id,
                            zone=zone,
                            resource_id=asset.name
                        )

                        vm_patch_results.append(result)

                    except Exception as e:
                        logger.warning(f"Failed to analyze VM patch compliance for {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"VM patch compliance analysis complete. Analyzed {len(vm_patch_results)} instances")
        return vm_patch_results

    def query_comprehensive_vm_governance_analysis(self) -> Dict[str, Any]:
        """
        Perform comprehensive VM governance analysis - equivalent to Azure's comprehensive VM analysis

        Returns:
            Dictionary containing all VM governance analysis results
        """
        logger.info("Starting comprehensive GCP VM governance analysis...")

        results = {}

        try:
            logger.info("Analyzing VM security...")
            results['vm_security'] = self.query_vm_security()
            logger.info(f"   Found {len(results['vm_security'])} VM instances")
        except Exception as e:
            logger.error(f"VM security analysis failed: {e}")
            results['vm_security'] = []

        try:
            logger.info("Analyzing VM optimization...")
            results['vm_optimization'] = self.query_vm_optimization()
            logger.info(f"   Analyzed {len(results['vm_optimization'])} VM instances")
        except Exception as e:
            logger.error(f"VM optimization analysis failed: {e}")
            results['vm_optimization'] = []

        try:
            logger.info("Analyzing VM configurations...")
            results['vm_configurations'] = self.query_vm_configurations()
            logger.info(f"   Analyzed {len(results['vm_configurations'])} VM configurations")
        except Exception as e:
            logger.error(f"VM configuration analysis failed: {e}")
            results['vm_configurations'] = []

        try:
            logger.info("Analyzing VM patch compliance...")
            results['vm_patch_compliance'] = self.query_vm_patch_compliance()
            logger.info(f"   Analyzed {len(results['vm_patch_compliance'])} VM instances")
        except Exception as e:
            logger.error(f"VM patch compliance analysis failed: {e}")
            results['vm_patch_compliance'] = []

        try:
            logger.info("Generating VM governance summary...")
            results['vm_governance_summary'] = self.get_vm_governance_summary()
            logger.info(f"   Generated summary for {len(results['vm_governance_summary'])} applications")
        except Exception as e:
            logger.error(f"VM governance summary failed: {e}")
            results['vm_governance_summary'] = []

        try:
            logger.info("Generating compute compliance summary...")
            results['compute_compliance_summary'] = self.get_compute_compliance_summary()
            logger.info(f"   Generated summary for {len(results['compute_compliance_summary'])} applications")
        except Exception as e:
            logger.error(f"Compute compliance summary failed: {e}")
            results['compute_compliance_summary'] = []

        # Calculate summary statistics
        total_vms = len(results['vm_security'])
        high_risk_vms = len([vm for vm in results['vm_security'] if vm.is_high_risk])
        high_optimization_vms = len([vm for vm in results['vm_optimization'] if vm.has_high_optimization_potential])
        critical_config_issues = len([config for config in results['vm_configurations']
                                      if not config.is_healthy and config.is_critical])
        high_patch_risk_vms = len([vm for vm in results['vm_patch_compliance'] if vm.is_high_risk])

        logger.info(f"GCP VM governance analysis complete!")
        logger.info(f"   Total VMs analyzed: {total_vms}")
        logger.info(f"   High-risk VMs: {high_risk_vms}")
        logger.info(f"   High optimization potential: {high_optimization_vms}")
        logger.info(f"   Critical configuration issues: {critical_config_issues}")
        logger.info(f"   High patch risk VMs: {high_patch_risk_vms}")
        logger.info(f"   Applications covered: {len(results['vm_governance_summary'])}")

        # Add summary statistics to results
        results['summary_statistics'] = {
            'total_vms': total_vms,
            'high_risk_vms': high_risk_vms,
            'high_optimization_vms': high_optimization_vms,
            'critical_config_issues': critical_config_issues,
            'high_patch_risk_vms': high_patch_risk_vms
        }

        return results

    # ==========================================================================
    # Container & Modern Workloads Analysis Methods (New)
    # ==========================================================================

    def query_gke_cluster_security(self, asset_types: Optional[List[str]] = None) -> List[
        GCPGKEClusterSecurityResult]:
        """
        GKE cluster security analysis - equivalent to Azure's AKS cluster analysis

        Args:
            asset_types: Optional list of specific asset types to query

        Returns:
            List of GKE cluster security analysis results
        """
        if asset_types is None:
            asset_types = GCPContainerAnalysisQueries.get_gke_cluster_security_asset_types()

        # Ensure proper type conversion
        if not isinstance(asset_types, list):
            asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []
        asset_types = [str(item) for item in asset_types if item]

        logger.info("Starting GKE cluster security analysis...")
        cluster_results = []

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        if 'container.googleapis.com/Cluster' not in asset.asset_type:
                            continue  # Only process GKE clusters

                        application = self._get_application_tag(asset)
                        cluster_name = asset.name.split('/')[-1]
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        # Use GKE cluster analyzer
                        cluster_analysis = GCPGKEClusterAnalyzer.analyze_gke_cluster_security(asset.asset_type,
                                                                                              data)

                        result = GCPGKEClusterSecurityResult(
                            application=application,
                            cluster_name=cluster_name,
                            cluster_version=cluster_analysis['cluster_version'],
                            network_configuration=cluster_analysis['network_configuration'],
                            rbac_configuration=cluster_analysis['rbac_configuration'],
                            api_server_access=cluster_analysis['api_server_access'],
                            security_findings=cluster_analysis['security_findings'],
                            security_risk=cluster_analysis['security_risk'],
                            cluster_compliance=cluster_analysis['cluster_compliance'],
                            cluster_details=cluster_analysis['cluster_details'],
                            node_pool_count=data.get('currentNodeCount', 0),
                            resource_group=project_id,
                            location=getattr(asset.resource, 'location', 'unknown'),
                            resource_id=asset.name
                        )

                        cluster_results.append(result)

                    except Exception as e:
                        logger.warning(f"Failed to analyze GKE cluster {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"GKE cluster security analysis complete. Analyzed {len(cluster_results)} clusters")
        return cluster_results

    def query_gke_node_pools(self, asset_types: Optional[List[str]] = None) -> List[GCPGKENodePoolResult]:
        """
        GKE node pool analysis - equivalent to Azure's AKS node pool analysis

        Args:
            asset_types: Optional list of specific asset types to query

        Returns:
            List of GKE node pool analysis results
        """
        if asset_types is None:
            asset_types = ["container.googleapis.com/NodePool"]

        # Ensure proper type conversion
        if not isinstance(asset_types, list):
            asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []
        asset_types = [str(item) for item in asset_types if item]

        logger.info("Starting GKE node pool analysis...")
        node_pool_results = []

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        if 'container.googleapis.com/NodePool' not in asset.asset_type:
                            continue  # Only process node pools

                        application = self._get_application_tag(asset)
                        node_pool_name = asset.name.split('/')[-1]
                        cluster_name = asset.name.split('/')[-3] if len(asset.name.split('/')) >= 3 else 'unknown'
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        # Use node pool analyzer
                        node_pool_analysis = GCPGKEClusterAnalyzer.analyze_gke_node_pool(asset.asset_type, data)

                        result = GCPGKENodePoolResult(
                            application=application,
                            cluster_name=cluster_name,
                            node_pool_name=node_pool_name,
                            node_pool_type=node_pool_analysis['node_pool_type'],
                            vm_size=node_pool_analysis['vm_size'],
                            vm_size_category=node_pool_analysis['vm_size_category'],
                            scaling_configuration=node_pool_analysis['scaling_configuration'],
                            security_configuration=node_pool_analysis['security_configuration'],
                            optimization_potential=node_pool_analysis['optimization_potential'],
                            node_pool_risk=node_pool_analysis['node_pool_risk'],
                            node_pool_details=node_pool_analysis['node_pool_details'],
                            resource_group=project_id,
                            location=getattr(asset.resource, 'location', 'unknown'),
                            resource_id=asset.name
                        )

                        node_pool_results.append(result)

                    except Exception as e:
                        logger.warning(f"Failed to analyze node pool {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"GKE node pool analysis complete. Analyzed {len(node_pool_results)} node pools")
        return node_pool_results

    def query_artifact_registry_security(self, asset_types: Optional[List[str]] = None) -> List[
        GCPArtifactRegistrySecurityResult]:
        """
        Artifact Registry security analysis - equivalent to Azure's Container Registry analysis

        Args:
            asset_types: Optional list of specific asset types to query

        Returns:
            List of Artifact Registry security analysis results
        """
        if asset_types is None:
            asset_types = GCPContainerAnalysisQueries.get_artifact_registry_security_asset_types()

        # Ensure proper type conversion
        if not isinstance(asset_types, list):
            asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []
        asset_types = [str(item) for item in asset_types if item]

        logger.info("Starting Artifact Registry security analysis...")
        registry_results = []

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        application = self._get_application_tag(asset)
                        registry_name = asset.name.split('/')[-1]
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        # Use Artifact Registry analyzer
                        registry_analysis = GCPArtifactRegistryAnalyzer.analyze_registry_security(asset.asset_type,
                                                                                                  data)

                        result = GCPArtifactRegistrySecurityResult(
                            application=application,
                            registry_name=registry_name,
                            registry_sku=registry_analysis['registry_sku'],
                            network_security=registry_analysis['network_security'],
                            access_control=registry_analysis['access_control'],
                            security_policies=registry_analysis['security_policies'],
                            security_findings=registry_analysis['security_findings'],
                            security_risk=registry_analysis['security_risk'],
                            compliance_status=registry_analysis['compliance_status'],
                            registry_details=registry_analysis['registry_details'],
                            resource_group=project_id,
                            location=getattr(asset.resource, 'location', 'unknown'),
                            resource_id=asset.name
                        )

                        registry_results.append(result)

                    except Exception as e:
                        logger.warning(f"Failed to analyze Artifact Registry {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"Artifact Registry security analysis complete. Analyzed {len(registry_results)} registries")
        return registry_results

    def query_cloud_run_security(self, asset_types: Optional[List[str]] = None) -> List[GCPCloudRunSecurityResult]:
        """
        Cloud Run security analysis - equivalent to Azure's App Service analysis

        Args:
            asset_types: Optional list of specific asset types to query

        Returns:
            List of Cloud Run security analysis results
        """
        if asset_types is None:
            asset_types = GCPContainerAnalysisQueries.get_cloud_run_security_asset_types()

        # Ensure proper type conversion
        if not isinstance(asset_types, list):
            asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []
        asset_types = [str(item) for item in asset_types if item]

        logger.info("Starting Cloud Run security analysis...")
        service_results = []

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        application = self._get_application_tag(asset)
                        service_name = asset.name.split('/')[-1]
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        # Use Cloud Run analyzer
                        service_analysis = GCPCloudRunAnalyzer.analyze_cloud_run_security(asset.asset_type, data)

                        result = GCPCloudRunSecurityResult(
                            application=application,
                            service_name=service_name,
                            service_kind=service_analysis['service_kind'],
                            tls_configuration=service_analysis['tls_configuration'],
                            network_security=service_analysis['network_security'],
                            authentication_method=service_analysis['authentication_method'],
                            security_findings=service_analysis['security_findings'],
                            security_risk=service_analysis['security_risk'],
                            compliance_status=service_analysis['compliance_status'],
                            service_details=service_analysis['service_details'],
                            custom_domain_count=0,  # Would need additional API call to get custom domains
                            resource_group=project_id,
                            location=getattr(asset.resource, 'location', 'unknown'),
                            resource_id=asset.name
                        )

                        service_results.append(result)

                    except Exception as e:
                        logger.warning(f"Failed to analyze Cloud Run service {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"Cloud Run security analysis complete. Analyzed {len(service_results)} services")
        return service_results

    def query_app_engine_security(self, asset_types: Optional[List[str]] = None) -> List[
        GCPAppEngineSecurityResult]:
        """
        App Engine security analysis

        Args:
            asset_types: Optional list of specific asset types to query

        Returns:
            List of App Engine security analysis results
        """
        if asset_types is None:
            asset_types = GCPContainerAnalysisQueries.get_app_engine_security_asset_types()

        # Ensure proper type conversion
        if not isinstance(asset_types, list):
            asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []
        asset_types = [str(item) for item in asset_types if item]

        logger.info("Starting App Engine security analysis...")
        app_results = []

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        application = self._get_application_tag(asset)
                        app_name = asset.name.split('/')[-1]
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        # Use App Engine analyzer
                        app_analysis = GCPAppEngineAnalyzer.analyze_app_engine_security(asset.asset_type, data)

                        result = GCPAppEngineSecurityResult(
                            application=application,
                            app_name=app_name,
                            app_kind=app_analysis['app_kind'],
                            tls_configuration=app_analysis['tls_configuration'],
                            network_security=app_analysis['network_security'],
                            authentication_method=app_analysis['authentication_method'],
                            security_findings=app_analysis['security_findings'],
                            security_risk=app_analysis['security_risk'],
                            compliance_status=app_analysis['compliance_status'],
                            app_details=app_analysis['app_details'],
                            resource_group=project_id,
                            location=getattr(asset.resource, 'location', 'unknown'),
                            resource_id=asset.name
                        )

                        app_results.append(result)

                    except Exception as e:
                        logger.warning(f"Failed to analyze App Engine resource {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"App Engine security analysis complete. Analyzed {len(app_results)} resources")
        return app_results

    def query_cloud_functions_security(self, asset_types: Optional[List[str]] = None) -> List[
        GCPCloudFunctionsSecurityResult]:
        """
        Cloud Functions security analysis

        Args:
            asset_types: Optional list of specific asset types to query

        Returns:
            List of Cloud Functions security analysis results
        """
        if asset_types is None:
            asset_types = GCPContainerAnalysisQueries.get_cloud_functions_security_asset_types()

        # Ensure proper type conversion
        if not isinstance(asset_types, list):
            asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []
        asset_types = [str(item) for item in asset_types if item]

        logger.info("Starting Cloud Functions security analysis...")
        function_results = []

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        application = self._get_application_tag(asset)
                        function_name = asset.name.split('/')[-1]
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        # Use Cloud Functions analyzer
                        function_analysis = GCPCloudFunctionsAnalyzer.analyze_cloud_function_security(
                            asset.asset_type, data)

                        result = GCPCloudFunctionsSecurityResult(
                            application=application,
                            function_name=function_name,
                            function_kind=function_analysis['function_kind'],
                            tls_configuration=function_analysis['tls_configuration'],
                            network_security=function_analysis['network_security'],
                            authentication_method=function_analysis['authentication_method'],
                            security_findings=function_analysis['security_findings'],
                            security_risk=function_analysis['security_risk'],
                            compliance_status=function_analysis['compliance_status'],
                            function_details=function_analysis['function_details'],
                            resource_group=project_id,
                            location=getattr(asset.resource, 'location', 'unknown'),
                            resource_id=asset.name
                        )

                        function_results.append(result)

                    except Exception as e:
                        logger.warning(f"Failed to analyze Cloud Function {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"Cloud Functions security analysis complete. Analyzed {len(function_results)} functions")
        return function_results

    def get_container_workloads_compliance_summary(self) -> List[GCPContainerWorkloadsComplianceSummary]:
        """
        Generate container workloads compliance summary by application

        Returns:
            List of container workloads compliance summaries
        """
        logger.info("Generating container workloads compliance summary...")

        # Get all container workload resources
        gke_clusters = self.query_gke_cluster_security()
        artifact_registries = self.query_artifact_registry_security()
        cloud_run_services = self.query_cloud_run_security()
        app_engine_resources = self.query_app_engine_security()
        cloud_functions = self.query_cloud_functions_security()

        # Group by application
        app_summaries = {}

        # Process GKE clusters
        for cluster in gke_clusters:
            app = cluster.application
            if app not in app_summaries:
                app_summaries[app] = {
                    'gke_clusters': 0, 'secure_gke': 0, 'registries': 0, 'secure_registries': 0,
                    'cloud_run': 0, 'secure_cloud_run': 0, 'app_engine': 0, 'secure_app_engine': 0,
                    'functions': 0, 'secure_functions': 0, 'total_issues': 0
                }

            summary = app_summaries[app]
            summary['gke_clusters'] += 1
            if not cluster.is_high_risk:
                summary['secure_gke'] += 1
            else:
                summary['total_issues'] += 1

        # Process Artifact Registries
        for registry in artifact_registries:
            app = registry.application
            if app not in app_summaries:
                app_summaries[app] = {
                    'gke_clusters': 0, 'secure_gke': 0, 'registries': 0, 'secure_registries': 0,
                    'cloud_run': 0, 'secure_cloud_run': 0, 'app_engine': 0, 'secure_app_engine': 0,
                    'functions': 0, 'secure_functions': 0, 'total_issues': 0
                }

            summary = app_summaries[app]
            summary['registries'] += 1
            if not registry.is_high_risk:
                summary['secure_registries'] += 1
            else:
                summary['total_issues'] += 1

        # Process Cloud Run services
        for service in cloud_run_services:
            app = service.application
            if app not in app_summaries:
                app_summaries[app] = {
                    'gke_clusters': 0, 'secure_gke': 0, 'registries': 0, 'secure_registries': 0,
                    'cloud_run': 0, 'secure_cloud_run': 0, 'app_engine': 0, 'secure_app_engine': 0,
                    'functions': 0, 'secure_functions': 0, 'total_issues': 0
                }

            summary = app_summaries[app]
            summary['cloud_run'] += 1
            if not service.is_high_risk:
                summary['secure_cloud_run'] += 1
            else:
                summary['total_issues'] += 1

        # Process App Engine resources
        for app_resource in app_engine_resources:
            app = app_resource.application
            if app not in app_summaries:
                app_summaries[app] = {
                    'gke_clusters': 0, 'secure_gke': 0, 'registries': 0, 'secure_registries': 0,
                    'cloud_run': 0, 'secure_cloud_run': 0, 'app_engine': 0, 'secure_app_engine': 0,
                    'functions': 0, 'secure_functions': 0, 'total_issues': 0
                }

            summary = app_summaries[app]
            summary['app_engine'] += 1
            if not app_resource.is_high_risk:
                summary['secure_app_engine'] += 1
            else:
                summary['total_issues'] += 1

        # Process Cloud Functions
        for function in cloud_functions:
            app = function.application
            if app not in app_summaries:
                app_summaries[app] = {
                    'gke_clusters': 0, 'secure_gke': 0, 'registries': 0, 'secure_registries': 0,
                    'cloud_run': 0, 'secure_cloud_run': 0, 'app_engine': 0, 'secure_app_engine': 0,
                    'functions': 0, 'secure_functions': 0, 'total_issues': 0
                }

            summary = app_summaries[app]
            summary['functions'] += 1
            if not function.is_high_risk:
                summary['secure_functions'] += 1
            else:
                summary['total_issues'] += 1

        # Create summary objects
        summaries = []
        for app, data in app_summaries.items():
            total_workloads = (data['gke_clusters'] + data['registries'] + data['cloud_run'] +
                               data['app_engine'] + data['functions'])

            if total_workloads == 0:
                continue

            compliance_score = ((total_workloads - data['total_issues']) / total_workloads * 100)

            if compliance_score >= 95:
                status = 'Excellent'
            elif compliance_score >= 85:
                status = 'Good'
            elif compliance_score >= 70:
                status = 'Acceptable'
            elif compliance_score >= 50:
                status = 'Needs Improvement'
            else:
                status = 'Critical Issues'

            summary = GCPContainerWorkloadsComplianceSummary(
                application=app,
                total_container_workloads=total_workloads,
                total_gke_clusters=data['gke_clusters'],
                secure_gke_clusters=data['secure_gke'],
                total_artifact_registries=data['registries'],
                secure_artifact_registries=data['secure_registries'],
                total_cloud_run_services=data['cloud_run'],
                secure_cloud_run_services=data['secure_cloud_run'],
                total_app_engine_services=data['app_engine'],
                secure_app_engine_services=data['secure_app_engine'],
                total_cloud_functions=data['functions'],
                secure_cloud_functions=data['secure_functions'],
                container_workloads_with_issues=data['total_issues'],
                container_workloads_compliance_score=round(compliance_score, 1),
                container_workloads_compliance_status=status
            )

            summaries.append(summary)

        logger.info(f"Generated container workloads compliance summary for {len(summaries)} applications")
        return summaries

    def query_comprehensive_container_workloads_analysis(self) -> Dict[str, Any]:
        """
        Perform comprehensive Container & Modern Workloads analysis - equivalent to Azure's comprehensive container analysis

        Returns:
            Dictionary containing all container workloads analysis results
        """
        logger.info("Starting comprehensive Container & Modern Workloads analysis...")

        results = {}

        try:
            logger.info("Analyzing GKE cluster security...")
            results['gke_cluster_security'] = self.query_gke_cluster_security()
            logger.info(f"   Found {len(results['gke_cluster_security'])} GKE clusters")
        except Exception as e:
            logger.error(f"GKE cluster security analysis failed: {e}")
            results['gke_cluster_security'] = []

        try:
            logger.info("Analyzing GKE node pools...")
            results['gke_node_pools'] = self.query_gke_node_pools()
            logger.info(f"   Found {len(results['gke_node_pools'])} node pools")
        except Exception as e:
            logger.error(f"GKE node pool analysis failed: {e}")
            results['gke_node_pools'] = []

        try:
            logger.info("Analyzing Artifact Registry security...")
            results['artifact_registry_security'] = self.query_artifact_registry_security()
            logger.info(f"   Found {len(results['artifact_registry_security'])} registries")
        except Exception as e:
            logger.error(f"Artifact Registry security analysis failed: {e}")
            results['artifact_registry_security'] = []

        try:
            logger.info("Analyzing Cloud Run security...")
            results['cloud_run_security'] = self.query_cloud_run_security()
            logger.info(f"   Found {len(results['cloud_run_security'])} Cloud Run services")
        except Exception as e:
            logger.error(f"Cloud Run security analysis failed: {e}")
            results['cloud_run_security'] = []

        try:
            logger.info("Analyzing App Engine security...")
            results['app_engine_security'] = self.query_app_engine_security()
            logger.info(f"   Found {len(results['app_engine_security'])} App Engine resources")
        except Exception as e:
            logger.error(f"App Engine security analysis failed: {e}")
            results['app_engine_security'] = []

        try:
            logger.info("Analyzing Cloud Functions security...")
            results['cloud_functions_security'] = self.query_cloud_functions_security()
            logger.info(f"   Found {len(results['cloud_functions_security'])} Cloud Functions")
        except Exception as e:
            logger.error(f"Cloud Functions security analysis failed: {e}")
            results['cloud_functions_security'] = []

        try:
            logger.info("Generating compliance summary...")
            results['compliance_summary'] = self.get_container_workloads_compliance_summary()
            logger.info(f"   Generated summary for {len(results['compliance_summary'])} applications")
        except Exception as e:
            logger.error(f"Compliance summary generation failed: {e}")
            results['compliance_summary'] = []

        # Calculate summary statistics
        total_workloads = (len(results['gke_cluster_security']) +
                           len(results['artifact_registry_security']) +
                           len(results['cloud_run_security']) +
                           len(results['app_engine_security']) +
                           len(results['cloud_functions_security']))

        high_risk_count = 0
        high_risk_count += len([r for r in results['gke_cluster_security'] if r.is_high_risk])
        high_risk_count += len([r for r in results['artifact_registry_security'] if r.is_high_risk])
        high_risk_count += len([r for r in results['cloud_run_security'] if r.is_high_risk])
        high_risk_count += len([r for r in results['app_engine_security'] if r.is_high_risk])
        high_risk_count += len([r for r in results['cloud_functions_security'] if r.is_high_risk])

        logger.info(f"Container & Modern Workloads analysis complete!")
        logger.info(f"   Total workloads analyzed: {total_workloads}")
        logger.info(f"   High-risk configurations: {high_risk_count}")
        logger.info(f"   Applications covered: {len(results['compliance_summary'])}")

        return results

    # ==========================================================================
    # Comprehensive Analysis Methods
    # ==========================================================================

    @staticmethod
    def _create_list_assets_request(parent: str, asset_types: List[str],
                                    page_size: int = 1000) -> asset_v1.ListAssetsRequest:
        """
        Create a properly formatted ListAssetsRequest

        Args:
            parent: Parent resource (e.g., "projects/my-project")
            asset_types: List of asset types to query
            page_size: Page size for pagination

        Returns:
            Properly formatted ListAssetsRequest
        """
        request = asset_v1.ListAssetsRequest()
        request.parent = parent
        request.asset_types.extend(asset_types)
        request.page_size = page_size
        return request

    def query_storage_encryption(self, asset_types: Optional[List[str]] = None) -> List[GCPStorageResource]:
        """
        Storage encryption analysis - ALIAS METHOD matching Azure pattern

        Args:
            asset_types: Optional list of specific asset types to query

        Returns:
            List of GCP storage resources with encryption analysis
        """
        logger.info("Starting storage encryption analysis (alias to comprehensive storage analysis)...")
        return self.query_storage_analysis(asset_types)

    def query_enhanced_storage_analysis(self, asset_types: Optional[List[str]] = None) -> List[GCPStorageResource]:
        """
        Enhanced storage security analysis using comprehensive analyzers

        Args:
            asset_types: Optional list of specific asset types to query

        Returns:
            List of GCP storage resources with enhanced security analysis
        """
        if asset_types is None:
            asset_types = GCPStorageAnalysisQueries.get_comprehensive_storage_asset_types()

        # Ensure asset_types is a proper list of strings
        if not isinstance(asset_types, list):
            logger.warning(f"asset_types is not a list, converting: {type(asset_types)}")
            asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []

        # Validate that all items are strings
        asset_types = [str(item) for item in asset_types if item]

        logger.info("Starting enhanced GCP storage security analysis...")
        storage_resources = []

        for project_id in self.project_ids:
            try:
                logger.debug(f"Scanning project: {project_id}")
                parent = f"projects/{project_id}"

                # Create properly formatted request
                request = self._create_list_assets_request(parent, asset_types)

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        application = self._get_application_tag(asset)
                        resource_name = asset.name.split('/')[-1]
                        location = getattr(asset.resource, 'location', 'global')
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        # Use enhanced analyzers
                        encryption_method = GCPStorageSecurityAnalyzer.analyze_encryption_comprehensive(
                            asset.asset_type, data)

                        security_findings, compliance_risk = GCPStorageSecurityAnalyzer.analyze_security_findings_comprehensive(
                            asset.asset_type, data)

                        storage_type = self._get_resource_type_name(asset.asset_type)
                        additional_details = GCPStorageSecurityAnalyzer.get_additional_details_comprehensive(
                            asset.asset_type, data)

                        resource = GCPStorageResource(
                            application=application,
                            storage_resource=resource_name,
                            storage_type=storage_type,
                            encryption_method=encryption_method,
                            security_findings=security_findings,
                            compliance_risk=compliance_risk,
                            resource_group=project_id,
                            location=location,
                            additional_details=additional_details,
                            resource_id=asset.name
                        )

                        storage_resources.append(resource)

                    except Exception as e:
                        logger.warning(f"Failed to analyze asset {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"Enhanced storage analysis complete. Found {len(storage_resources)} resources")
        return storage_resources

    def query_cloud_kms_security(self) -> List[GCPKMSSecurityResult]:
        """
        Cloud KMS security analysis - equivalent to Azure Key Vault analysis

        Returns:
            List of Cloud KMS security analysis results
        """
        logger.info("Starting Cloud KMS security analysis...")
        kms_results = []

        asset_types = GCPStorageAnalysisQueries.get_kms_security_asset_types()

        # Ensure proper type conversion
        if not isinstance(asset_types, list):
            asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []
        asset_types = [str(item) for item in asset_types if item]

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        application = self._get_application_tag(asset)
                        resource_name = asset.name.split('/')[-1]
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        # Use enhanced KMS analyzer
                        kms_analysis = GCPKMSAnalyzer.analyze_kms_security(asset.asset_type, data)

                        result = GCPKMSSecurityResult(
                            application=application,
                            kms_resource=resource_name,
                            resource_type=self._get_resource_type_name(asset.asset_type),
                            rotation_status=kms_analysis['rotation_status'],
                            access_control=kms_analysis['access_control'],
                            security_findings=kms_analysis['security_findings'],
                            security_risk=kms_analysis['security_risk'],
                            kms_details=kms_analysis['kms_details'],
                            resource_group=project_id,
                            location=getattr(asset.resource, 'location', 'global'),
                            resource_id=asset.name
                        )

                        kms_results.append(result)

                    except Exception as e:
                        logger.warning(f"Failed to analyze KMS resource {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"KMS security analysis complete. Analyzed {len(kms_results)} resources")
        return kms_results

    def query_enhanced_storage_backup_analysis(self) -> List[GCPStorageBackupResult]:
        """
        Enhanced backup analysis covering all storage types (matching Azure scope)

        Returns:
            List of comprehensive backup analysis results
        """
        logger.info("Starting enhanced backup configuration analysis...")
        backup_results = []

        asset_types = GCPStorageAnalysisQueries.get_backup_analysis_asset_types()

        # Ensure proper type conversion
        if not isinstance(asset_types, list):
            asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []
        asset_types = [str(item) for item in asset_types if item]

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        application = self._get_application_tag(asset)
                        resource_name = asset.name.split('/')[-1]
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        # Use enhanced backup analyzer
                        backup_analysis = GCPStorageBackupAnalyzer.analyze_backup_configuration_comprehensive(
                            asset.asset_type, data)

                        result = GCPStorageBackupResult(
                            application=application,
                            resource_name=resource_name,
                            resource_type=self._get_resource_type_name(asset.asset_type),
                            backup_configuration=backup_analysis['backup_configuration'],
                            retention_policy=backup_analysis['retention_policy'],
                            compliance_status=backup_analysis['compliance_status'],
                            disaster_recovery_risk=backup_analysis['disaster_recovery_risk'],
                            resource_group=project_id,
                            location=getattr(asset.resource, 'location', 'global'),
                            resource_id=asset.name
                        )

                        backup_results.append(result)

                    except Exception as e:
                        logger.warning(f"Failed to analyze backup for {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"Enhanced backup analysis complete. Analyzed {len(backup_results)} resources")
        return backup_results

    def query_enhanced_storage_optimization(self) -> List[GCPStorageOptimizationResult]:
        """
        Enhanced cost optimization analysis using comprehensive analyzer

        Returns:
            List of enhanced storage optimization results
        """
        logger.info("Starting enhanced cost optimization analysis...")
        optimization_results = []

        asset_types = GCPStorageAnalysisQueries.get_optimization_analysis_asset_types()

        # Ensure proper type conversion
        if not isinstance(asset_types, list):
            asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []
        asset_types = [str(item) for item in asset_types if item]

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        application = self._get_application_tag(asset)
                        resource_name = asset.name.split('/')[-1]
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        # Use enhanced optimization analyzer
                        optimization_analysis = GCPStorageOptimizationAnalyzer.analyze_cost_optimization_comprehensive(
                            asset.asset_type, data)

                        result = GCPStorageOptimizationResult(
                            application=application,
                            resource_name=resource_name,
                            optimization_type=self._get_resource_type_name(asset.asset_type),
                            current_configuration=optimization_analysis['current_configuration'],
                            utilization_status=optimization_analysis['utilization_status'],
                            cost_optimization_potential=optimization_analysis['cost_optimization_potential'],
                            optimization_recommendation=optimization_analysis['optimization_recommendation'],
                            estimated_monthly_cost=optimization_analysis['estimated_monthly_cost'],
                            resource_group=project_id,
                            location=getattr(asset.resource, 'location', 'global'),
                            resource_id=asset.name
                        )

                        optimization_results.append(result)

                    except Exception as e:
                        logger.warning(f"Failed to analyze optimization for {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"Enhanced optimization analysis complete. Analyzed {len(optimization_results)} resources")
        return optimization_results

    def get_enhanced_storage_compliance_summary(self) -> List[GCPEnhancedStorageComplianceSummary]:
        """
        Enhanced storage compliance summary including all storage services and KMS
        Matches Azure's comprehensive approach
        """
        logger.info("Generating enhanced storage compliance summary...")

        # Get all storage resources including KMS
        storage_resources = self.query_enhanced_storage_analysis()
        kms_resources = self.query_cloud_kms_security()

        # Group by application
        app_summaries = {}

        # Process storage resources
        for resource in storage_resources:
            app = resource.application
            if app not in app_summaries:
                app_summaries[app] = {
                    'total': 0, 'buckets': 0, 'disks': 0, 'sql': 0, 'bigquery': 0,
                    'spanner': 0, 'filestore': 0, 'memorystore': 0, 'kms_keys': 0,
                    'encrypted': 0, 'secure_transport': 0, 'network_secured': 0, 'issues': 0
                }

            summary = app_summaries[app]
            summary['total'] += 1

            # Count by type
            storage_type = resource.storage_type.lower()
            if 'bucket' in storage_type:
                summary['buckets'] += 1
            elif 'disk' in storage_type:
                summary['disks'] += 1
            elif 'sql' in storage_type:
                summary['sql'] += 1
            elif 'bigquery' in storage_type:
                summary['bigquery'] += 1
            elif 'spanner' in storage_type:
                summary['spanner'] += 1
            elif 'filestore' in storage_type:
                summary['filestore'] += 1
            elif 'memorystore' in storage_type or 'redis' in storage_type:
                summary['memorystore'] += 1

            # Enhanced security metrics
            if ('Customer Managed' in resource.encryption_method or
                    'Google Managed' in resource.encryption_method or
                    'Transit' in resource.encryption_method):
                summary['encrypted'] += 1

            # Assume secure transport for GCP (HTTPS/TLS by default)
            summary['secure_transport'] += 1

            # Network security (if not high risk)
            if not resource.compliance_risk.startswith('High'):
                summary['network_secured'] += 1

            # Issues
            if resource.is_high_risk:
                summary['issues'] += 1

        # Process KMS resources
        for kms_resource in kms_resources:
            app = kms_resource.application
            if app not in app_summaries:
                app_summaries[app] = {
                    'total': 0, 'buckets': 0, 'disks': 0, 'sql': 0, 'bigquery': 0,
                    'spanner': 0, 'filestore': 0, 'memorystore': 0, 'kms_keys': 0,
                    'encrypted': 0, 'secure_transport': 0, 'network_secured': 0, 'issues': 0
                }

            summary = app_summaries[app]
            summary['total'] += 1
            summary['kms_keys'] += 1
            summary['encrypted'] += 1  # KMS keys are inherently encrypted
            summary['secure_transport'] += 1
            summary['network_secured'] += 1

            if kms_resource.is_high_risk:
                summary['issues'] += 1

        # Create enhanced summary objects
        summaries = []
        for app, data in app_summaries.items():
            compliance_score = ((data['total'] - data['issues']) / data['total'] * 100) if data['total'] > 0 else 100

            # Enhanced status calculation
            if compliance_score >= 95:
                status = 'Excellent'
            elif compliance_score >= 85:
                status = 'Good'
            elif compliance_score >= 70:
                status = 'Acceptable'
            elif compliance_score >= 50:
                status = 'Needs Improvement'
            else:
                status = 'Critical Issues'

            summary = GCPEnhancedStorageComplianceSummary(
                application=app,
                total_storage_resources=data['total'],
                storage_bucket_count=data['buckets'],
                persistent_disk_count=data['disks'],
                cloud_sql_count=data['sql'],
                bigquery_dataset_count=data['bigquery'],
                spanner_instance_count=data['spanner'],
                filestore_count=data['filestore'],
                memorystore_count=data['memorystore'],
                kms_key_count=data['kms_keys'],
                encrypted_resources=data['encrypted'],
                secure_transport_resources=data['secure_transport'],
                network_secured_resources=data['network_secured'],
                resources_with_issues=data['issues'],
                compliance_score=round(compliance_score, 1),
                compliance_status=status
            )

            summaries.append(summary)

        logger.info(f"Generated enhanced compliance summary for {len(summaries)} applications")
        return summaries

    def query_comprehensive_storage_analysis_enhanced(self) -> Dict[str, Any]:
        """
        Comprehensive storage analysis with all enhancements - matches Azure's comprehensive approach
        """
        logger.info("Starting comprehensive GCP storage analysis (enhanced)...")

        results = {}

        try:
            logger.info("Analyzing storage security (enhanced)...")
            results['storage_security'] = self.query_enhanced_storage_analysis()
            logger.info(f"   Found {len(results['storage_security'])} storage resources")
        except Exception as e:
            logger.error(f"Enhanced storage security analysis failed: {e}")
            results['storage_security'] = []

        try:
            logger.info("Analyzing Cloud KMS security...")
            results['kms_security'] = self.query_cloud_kms_security()
            logger.info(f"   Analyzed {len(results['kms_security'])} KMS resources")
        except Exception as e:
            logger.error(f"KMS security analysis failed: {e}")
            results['kms_security'] = []

        try:
            logger.info("Analyzing access control...")
            results['access_control'] = self.query_storage_access_control()
            logger.info(f"   Analyzed {len(results['access_control'])} resources")
        except Exception as e:
            logger.error(f"Access control analysis failed: {e}")
            results['access_control'] = []

        try:
            logger.info("Analyzing backup configurations (enhanced)...")
            results['backup_analysis'] = self.query_enhanced_storage_backup_analysis()
            logger.info(f"   Analyzed {len(results['backup_analysis'])} backup configurations")
        except Exception as e:
            logger.error(f"Enhanced backup analysis failed: {e}")
            results['backup_analysis'] = []

        try:
            logger.info("Analyzing optimization opportunities (enhanced)...")
            results['optimization'] = self.query_enhanced_storage_optimization()
            logger.info(f"   Found {len(results['optimization'])} optimization opportunities")
        except Exception as e:
            logger.error(f"Enhanced optimization analysis failed: {e}")
            results['optimization'] = []

        try:
            logger.info("Generating enhanced compliance summary...")
            results['compliance_summary'] = self.get_enhanced_storage_compliance_summary()
            logger.info(f"   Generated summary for {len(results['compliance_summary'])} applications")
        except Exception as e:
            logger.error(f"Enhanced compliance summary failed: {e}")
            results['compliance_summary'] = []

        # Calculate comprehensive summary statistics
        total_resources = len(results['storage_security']) + len(results['kms_security'])
        high_risk_resources = (
                len([r for r in results['storage_security'] if r.is_high_risk]) +
                len([r for r in results['kms_security'] if r.is_high_risk])
        )
        optimization_opportunities = len([r for r in results['optimization'] if r.has_high_optimization_potential])
        compliance_issues = sum(s.resources_with_issues for s in results['compliance_summary'])

        logger.info(f"Comprehensive GCP storage analysis complete!")
        logger.info(f"   Total storage resources: {total_resources}")
        logger.info(f"   High-risk configurations: {high_risk_resources}")
        logger.info(f"   High-value optimization opportunities: {optimization_opportunities}")
        logger.info(f"   Applications analyzed: {len(results['compliance_summary'])}")

        # Add summary statistics to results
        results['summary_statistics'] = {
            'total_resources': total_resources,
            'high_risk_resources': high_risk_resources,
            'optimization_opportunities': optimization_opportunities,
            'compliance_issues': compliance_issues
        }

        return results

    def query_comprehensive_analysis_enhanced(self) -> GCPComprehensiveAnalysisResult:
        """
        Comprehensive analysis across all resource types (enhanced)

        Returns:
            GCPComprehensiveAnalysisResult with all enhanced analysis data
        """
        logger.info("Starting comprehensive GCP resource analysis (enhanced)...")

        # Enhanced storage analysis
        storage_analysis = self.query_enhanced_storage_analysis()
        kms_analysis = self.query_cloud_kms_security()
        storage_optimization = self.query_enhanced_storage_optimization()
        storage_compliance = self.get_enhanced_storage_compliance_summary()

        # Calculate enhanced statistics
        total_resources = len(storage_analysis) + len(kms_analysis)
        high_risk_resources = (
                len([r for r in storage_analysis if r.is_high_risk]) +
                len([r for r in kms_analysis if r.is_high_risk])
        )
        optimization_opportunities = len([r for r in storage_optimization if r.has_high_optimization_potential])
        compliance_issues = sum(s.resources_with_issues for s in storage_compliance)

        # Calculate overall scores
        overall_security_score = 0.0
        overall_compliance_score = 0.0
        overall_optimization_score = 0.0

        if storage_compliance:
            overall_compliance_score = sum(s.compliance_score for s in storage_compliance) / len(storage_compliance)
            overall_security_score = overall_compliance_score  # For now, use compliance as security proxy

        if total_resources > 0:
            overall_optimization_score = ((total_resources - optimization_opportunities) / total_resources * 100)

        result = GCPComprehensiveAnalysisResult(
            project_ids=self.project_ids,
            storage_analysis=storage_analysis,
            storage_compliance=storage_compliance,
            storage_optimization=storage_optimization,
            kms_analysis=kms_analysis,
            total_resources_analyzed=total_resources,
            high_risk_resources=high_risk_resources,
            optimization_opportunities=optimization_opportunities,
            compliance_issues=compliance_issues,
            overall_security_score=round(overall_security_score, 1),
            overall_compliance_score=round(overall_compliance_score, 1),
            overall_optimization_score=round(overall_optimization_score, 1)
        )

        logger.info("Comprehensive enhanced analysis complete!")
        logger.info(f"   Overall Security Score: {result.overall_security_score}%")
        logger.info(f"   Overall Compliance Score: {result.overall_compliance_score}%")
        logger.info(f"   Overall Optimization Score: {result.overall_optimization_score}%")
        logger.info(f"   Critical Issues: {result.critical_issues_count}")

        return result

    @staticmethod
    def _load_config_from_env() -> Dict[str, Any]:
        """
        Load configuration from environment variables or .env file
        Similar to Azure Resource Graph client configuration loading
        """
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except ImportError:
            pass

        config = {
            'project_ids': [],
            'credentials_path': None,
            'log_level': 'INFO',
            'max_requests_per_minute': 100,
            'default_region': 'us-central1'
        }

        # Load project IDs
        project_ids_str = os.getenv('GCP_PROJECT_IDS', '')
        if project_ids_str:
            config['project_ids'] = [p.strip() for p in project_ids_str.split(',') if p.strip()]

        # Load credentials path
        config['credentials_path'] = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')

        # Load other configuration
        config['log_level'] = os.getenv('GCP_ANALYSIS_LOG_LEVEL', 'INFO').upper()
        config['default_region'] = os.getenv('GCP_ANALYSIS_DEFAULT_REGION', 'us-central1')

        # Load rate limiting
        max_requests = os.getenv('GCP_ANALYSIS_MAX_REQUESTS_PER_MINUTE')
        if max_requests:
            try:
                config['max_requests_per_minute'] = int(max_requests)
            except ValueError:
                pass

        return config

    @staticmethod
    def _setup_credentials(credentials_path: Optional[str]) -> Optional[object]:
        """Set up GCP authentication credentials"""
        if credentials_path:
            if not os.path.exists(credentials_path):
                raise FileNotFoundError(f"Credentials file not found: {credentials_path}")
            try:
                return service_account.Credentials.from_service_account_file(credentials_path)
            except Exception as e:
                logger.error(f"Failed to load service account credentials: {e}")
                raise
        else:
            try:
                # Use default credentials (gcloud auth application-default login)
                credentials, _ = default()
                return credentials
            except google.auth.exceptions.DefaultCredentialsError as e:
                logger.warning(f"No default credentials found: {e}")
                return None

    def _make_rate_limited_request(self, request_func, *args, **kwargs):
        """Make a rate-limited request to GCP APIs"""
        with self._request_lock:
            self.rate_limiter.wait_if_needed()

            try:
                result = request_func(*args, **kwargs)
                self.rate_limiter.record_request()
                return result
            except Exception as e:
                logger.error(f"API request failed: {e}")
                raise

    @staticmethod
    def _get_application_tag(asset) -> str:
        """Extract application name from asset labels/tags"""
        try:
            if hasattr(asset.resource, 'data') and asset.resource.data is not None:
                data = dict(asset.resource.data)
                labels = data.get('labels', {})

                # Check common application tag patterns
                for key in ['application', 'app', 'app-name', 'project', 'service', 'component']:
                    if key in labels:
                        return labels[key]

            # Fallback to project ID
            project_id = asset.name.split('/')[1] if '/' in asset.name else 'Unknown'
            return f"Project-{project_id}"
        except Exception as e:
            logger.warning(f"Failed to extract application tag from {asset.name}: {e}")
            return "Untagged"

    @staticmethod
    def _analyze_storage_encryption(asset) -> str:
        """Analyze encryption configuration for storage resources"""
        try:
            resource_type = asset.asset_type
            data = dict(asset.resource.data) if (
                    hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

            if 'storage.googleapis.com/Bucket' in resource_type:
                encryption = data.get('encryption', {})
                if encryption.get('defaultKmsKeyName'):
                    return 'Customer Managed Key (CMEK)'
                else:
                    return 'Google Managed Key (Default)'

            elif 'compute.googleapis.com/Disk' in resource_type:
                disk_encryption_key = data.get('diskEncryptionKey', {})
                if disk_encryption_key.get('kmsKeyName'):
                    return 'Customer Managed Key (CMEK)'
                elif disk_encryption_key.get('sha256'):
                    return 'Customer Supplied Key (CSEK)'
                else:
                    return 'Google Managed Key (Default)'

            elif 'sqladmin.googleapis.com/Instance' in resource_type:
                disk_encryption_config = data.get('diskEncryptionConfiguration', {})
                if disk_encryption_config.get('kmsKeyName'):
                    return 'Customer Managed Key (CMEK)'
                else:
                    return 'Google Managed Key (Default)'

            elif 'bigquery.googleapis.com/Dataset' in resource_type:
                default_encryption_config = data.get('defaultEncryptionConfiguration', {})
                if default_encryption_config.get('kmsKeyName'):
                    return 'Customer Managed Key (CMEK)'
                else:
                    return 'Google Managed Key (Default)'

            return 'Unknown Encryption'
        except Exception as e:
            logger.warning(f"Failed to analyze encryption for {asset.name}: {e}")
            return 'Unknown Encryption'

    @staticmethod
    def _analyze_storage_security(asset) -> tuple:
        """Analyze security configuration and return (findings, risk)"""
        try:
            resource_type = asset.asset_type
            data = dict(asset.resource.data) if (
                    hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

            if 'storage.googleapis.com/Bucket' in resource_type:
                iam_config = data.get('iamConfiguration', {})
                public_access_prevention = iam_config.get('publicAccessPrevention', 'inherited')
                uniform_bucket_level_access = iam_config.get('uniformBucketLevelAccess', {}).get('enabled', False)

                if public_access_prevention == 'inherited' and not uniform_bucket_level_access:
                    return 'Public access possible', 'High - Public access risk'
                elif not uniform_bucket_level_access:
                    return 'ACL-based access control', 'Medium - Legacy access control'
                else:
                    return 'Uniform bucket access enabled', 'Low - Secured'

            elif 'sqladmin.googleapis.com/Instance' in resource_type:
                settings = data.get('settings', {})
                ip_config = settings.get('ipConfiguration', {})

                if ip_config.get('ipv4Enabled', True) and not ip_config.get('authorizedNetworks'):
                    return 'Public IP with no restrictions', 'High - Public access'
                elif ip_config.get('ipv4Enabled', True):
                    return 'Public IP with authorized networks', 'Medium - Network restricted'
                else:
                    return 'Private IP only', 'Low - Private access'

            elif 'compute.googleapis.com/Disk' in resource_type:
                status = data.get('status', 'READY')
                users = data.get('users', [])

                if status == 'READY' and not users:
                    return 'Disk not attached to any instance', 'Medium - Orphaned resource'
                else:
                    return 'Disk attached and in use', 'Low - Normal usage'

            return 'Review required', 'Manual review needed'
        except Exception as e:
            logger.warning(f"Failed to analyze security for {asset.name}: {e}")
            return 'Analysis failed', 'Unknown risk'

    @staticmethod
    def _get_additional_details(asset_type: str, data: Dict) -> str:
        """Get additional details specific to resource type"""
        try:
            if data is None:
                return "No resource data available"

            if 'storage.googleapis.com/Bucket' in asset_type:
                storage_class = data.get('storageClass', 'STANDARD')
                versioning = data.get('versioning', {}).get('enabled', False)
                return f"Class: {storage_class} | Versioning: {'Enabled' if versioning else 'Disabled'}"

            elif 'compute.googleapis.com/Disk' in asset_type:
                size_gb = data.get('sizeGb', 'Unknown')
                disk_type = data.get('type', 'Unknown').split('/')[-1]
                status = data.get('status', 'Unknown')
                return f"Size: {size_gb}GB | Type: {disk_type} | Status: {status}"

            elif 'sqladmin.googleapis.com/Instance' in asset_type:
                database_version = data.get('databaseVersion', 'Unknown')
                tier = data.get('settings', {}).get('tier', 'Unknown')
                return f"Version: {database_version} | Tier: {tier}"

            elif 'bigquery.googleapis.com/Dataset' in asset_type:
                location = data.get('location', 'Unknown')
                default_table_expiration = data.get('defaultTableExpirationMs')
                expiration_info = f" | TTL: {int(default_table_expiration) // 86400000}d" if default_table_expiration else ""
                return f"Location: {location}{expiration_info}"

            return "Standard configuration"
        except Exception as e:
            logger.warning(f"Failed to get additional details for {asset_type}: {e}")
            return "Configuration details unavailable"

    @staticmethod
    def _get_resource_type_name(asset_type: str) -> str:
        """Convert asset type to friendly name"""
        type_map = {
            'storage.googleapis.com/Bucket': 'Cloud Storage Bucket',
            'sqladmin.googleapis.com/Instance': 'Cloud SQL Instance',
            'bigquery.googleapis.com/Dataset': 'BigQuery Dataset',
            'compute.googleapis.com/Disk': 'Persistent Disk',
            'spanner.googleapis.com/Instance': 'Cloud Spanner Instance',
            'compute.googleapis.com/Instance': 'Compute Engine VM',
            'container.googleapis.com/Cluster': 'GKE Cluster',
            'run.googleapis.com/Service': 'Cloud Run Service',
            'appengine.googleapis.com/Application': 'App Engine Application'
        }
        return type_map.get(asset_type, asset_type.split('/')[-1])

    # ==========================================================================
    # Storage Analysis Methods
    # ==========================================================================

    def query_storage_analysis(self, asset_types: Optional[List[str]] = None) -> List[GCPStorageResource]:
        """
        Main storage security analysis - equivalent to Azure's query_storage_analysis

        Args:
            asset_types: Optional list of specific asset types to query

        Returns:
            List of GCP storage resources with security analysis
        """
        if asset_types is None:
            asset_types = [
                "storage.googleapis.com/Bucket",
                "compute.googleapis.com/Disk",
                "sqladmin.googleapis.com/Instance",
                "bigquery.googleapis.com/Dataset",
                "spanner.googleapis.com/Instance"
            ]

        # Ensure asset_types is properly typed
        if not isinstance(asset_types, list):
            logger.warning(f"asset_types is not a list, converting: {type(asset_types)}")
            asset_types = list(asset_types) if hasattr(asset_types, '__iter__') else []

        # Validate that all items are strings
        asset_types = [str(item) for item in asset_types if item]

        logger.info("Starting GCP storage security analysis...")
        storage_resources = []

        for project_id in self.project_ids:
            try:
                logger.debug(f"Scanning project: {project_id}")
                parent = f"projects/{project_id}"

                # Create properly formatted request
                request = self._create_list_assets_request(parent, asset_types)

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        application = self._get_application_tag(asset)
                        encryption_method = self._analyze_storage_encryption(asset)
                        security_findings, compliance_risk = self._analyze_storage_security(asset)

                        # Extract resource details
                        resource_name = asset.name.split('/')[-1]
                        location = getattr(asset.resource, 'location', 'global')

                        # Determine storage type
                        storage_type = self._get_resource_type_name(asset.asset_type)

                        # Additional details based on type
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}
                        additional_details = self._get_additional_details(asset.asset_type, data)

                        resource = GCPStorageResource(
                            application=application,
                            storage_resource=resource_name,
                            storage_type=storage_type,
                            encryption_method=encryption_method,
                            security_findings=security_findings,
                            compliance_risk=compliance_risk,
                            resource_group=project_id,
                            location=location,
                            additional_details=additional_details,
                            resource_id=asset.name
                        )

                        storage_resources.append(resource)

                    except Exception as e:
                        logger.warning(f"Failed to analyze asset {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"Storage analysis complete. Found {len(storage_resources)} resources")
        return storage_resources

    def query_storage_access_control(self) -> List[GCPStorageAccessControlResult]:
        """Analyze storage access control configurations"""
        logger.info("Starting storage access control analysis...")
        access_results = []

        asset_types = [
            "storage.googleapis.com/Bucket",
            "sqladmin.googleapis.com/Instance",
            "bigquery.googleapis.com/Dataset"
        ]

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        application = self._get_application_tag(asset)
                        resource_name = asset.name.split('/')[-1]
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        public_access, network_restrictions, auth_method, security_risk, access_details = \
                            self._analyze_access_control(asset.asset_type, data)

                        result = GCPStorageAccessControlResult(
                            application=application,
                            resource_name=resource_name,
                            resource_type=self._get_resource_type_name(asset.asset_type),
                            public_access=public_access,
                            network_restrictions=network_restrictions,
                            authentication_method=auth_method,
                            security_risk=security_risk,
                            access_details=access_details,
                            resource_group=project_id,
                            location=getattr(asset.resource, 'location', 'global'),
                            resource_id=asset.name
                        )

                        access_results.append(result)

                    except Exception as e:
                        logger.warning(f"Failed to analyze access control for {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"Access control analysis complete. Analyzed {len(access_results)} resources")
        return access_results

    @staticmethod
    def _analyze_access_control(asset_type: str, data: Dict) -> tuple:
        """Analyze access control configuration for different resource types"""
        try:
            if data is None:
                return "Unknown", "Unknown", "Unknown", "Analysis Failed", "Error occurred"

            if 'storage.googleapis.com/Bucket' in asset_type:
                iam_config = data.get('iamConfiguration', {})
                public_prevention = iam_config.get('publicAccessPrevention', 'inherited')
                uniform_access = iam_config.get('uniformBucketLevelAccess', {}).get('enabled', False)

                public_access = f"Public Prevention: {public_prevention}"
                network_restrictions = "Uniform Access" if uniform_access else "ACL-based"
                auth_method = "IAM + ACLs" if not uniform_access else "IAM Only"

                if public_prevention == 'inherited' and not uniform_access:
                    security_risk = "High - Public access possible"
                elif not uniform_access:
                    security_risk = "Medium - ACL-based access"
                else:
                    security_risk = "Low - IAM controlled"

                access_details = f"Uniform: {uniform_access} | Prevention: {public_prevention}"

            elif 'sqladmin.googleapis.com/Instance' in asset_type:
                settings = data.get('settings', {})
                ip_config = settings.get('ipConfiguration', {})

                public_ip = ip_config.get('ipv4Enabled', True)
                authorized_networks = ip_config.get('authorizedNetworks', [])
                require_ssl = ip_config.get('requireSsl', False)

                public_access = "Public IP Enabled" if public_ip else "Private IP Only"
                network_restrictions = f"Authorized Networks: {len(authorized_networks)}"
                auth_method = f"SSL Required: {require_ssl}"

                if public_ip and not authorized_networks:
                    security_risk = "High - Public with no restrictions"
                elif public_ip:
                    security_risk = "Medium - Public with restrictions"
                else:
                    security_risk = "Low - Private access only"

                access_details = f"SSL: {require_ssl} | Networks: {len(authorized_networks)}"

            else:
                public_access = "Review Required"
                network_restrictions = "Unknown"
                auth_method = "Unknown"
                security_risk = "Manual Review Needed"
                access_details = "Configuration review required"

            return public_access, network_restrictions, auth_method, security_risk, access_details
        except Exception as e:
            logger.warning(f"Failed to analyze access control for {asset_type}: {e}")
            return "Unknown", "Unknown", "Unknown", "Analysis Failed", "Error occurred"

    def query_storage_backup_analysis(self) -> List[GCPStorageBackupResult]:
        """Analyze backup and disaster recovery configurations"""
        logger.info("Starting backup configuration analysis...")
        backup_results = []

        # Focus on Cloud SQL instances which have clear backup policies
        asset_types = ["sqladmin.googleapis.com/Instance"]

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        application = self._get_application_tag(asset)
                        resource_name = asset.name.split('/')[-1]
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        backup_config, retention_policy, compliance_status, dr_risk = \
                            self._analyze_backup_config(data)

                        result = GCPStorageBackupResult(
                            application=application,
                            resource_name=resource_name,
                            resource_type='Cloud SQL Instance',
                            backup_configuration=backup_config,
                            retention_policy=retention_policy,
                            compliance_status=compliance_status,
                            disaster_recovery_risk=dr_risk,
                            resource_group=project_id,
                            location=getattr(asset.resource, 'location', 'unknown'),
                            resource_id=asset.name
                        )

                        backup_results.append(result)

                    except Exception as e:
                        logger.warning(f"Failed to analyze backup for {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"Backup analysis complete. Analyzed {len(backup_results)} resources")
        return backup_results

    @staticmethod
    def _analyze_backup_config(data: Dict) -> tuple:
        """Analyze backup configuration for Cloud SQL"""
        try:
            if data is None:
                return "No data available", "Unknown", "Analysis Failed", "Unknown"

            settings = data.get('settings', {})
            backup_config = settings.get('backupConfiguration', {})

            enabled = backup_config.get('enabled', False)
            point_in_time_recovery = backup_config.get('pointInTimeRecoveryEnabled', False)
            backup_retention_settings = backup_config.get('backupRetentionSettings', {})
            retained_backups = backup_retention_settings.get('retainedBackups', 0)

            if enabled:
                backup_configuration = f"Automated backups enabled"
                if point_in_time_recovery:
                    backup_configuration += " with PITR"
            else:
                backup_configuration = "No automated backups"

            retention_policy = f"Retained backups: {retained_backups}" if retained_backups else "Default retention"

            if not enabled:
                compliance_status = "Non-Compliant - No backups"
                dr_risk = "High - No backup protection"
            elif point_in_time_recovery:
                compliance_status = "Compliant - Full backup with PITR"
                dr_risk = "Low - Comprehensive protection"
            else:
                compliance_status = "Partially Compliant - Basic backups"
                dr_risk = "Medium - Basic protection"

            return backup_configuration, retention_policy, compliance_status, dr_risk
        except Exception as e:
            logger.warning(f"Failed to analyze backup configuration: {e}")
            return "Unknown", "Unknown", "Analysis Failed", "Unknown"

    def query_storage_optimization(self) -> List[GCPStorageOptimizationResult]:
        """Analyze cost optimization opportunities"""
        logger.info("Starting cost optimization analysis...")
        optimization_results = []

        asset_types = [
            "storage.googleapis.com/Bucket",
            "compute.googleapis.com/Disk"
        ]

        for project_id in self.project_ids:
            try:
                parent = f"projects/{project_id}"
                request = self._create_list_assets_request(parent, asset_types)

                response = self._make_rate_limited_request(
                    self.asset_client.list_assets,
                    request=request
                )

                for asset in response:
                    try:
                        application = self._get_application_tag(asset)
                        resource_name = asset.name.split('/')[-1]
                        data = dict(asset.resource.data) if (
                                hasattr(asset.resource, 'data') and asset.resource.data is not None) else {}

                        optimization_analysis = self._analyze_cost_optimization(asset.asset_type, data)

                        result = GCPStorageOptimizationResult(
                            application=application,
                            resource_name=resource_name,
                            optimization_type=self._get_resource_type_name(asset.asset_type),
                            current_configuration=optimization_analysis['current_config'],
                            utilization_status=optimization_analysis['utilization'],
                            cost_optimization_potential=optimization_analysis['potential'],
                            optimization_recommendation=optimization_analysis['recommendation'],
                            estimated_monthly_cost=optimization_analysis['cost_estimate'],
                            resource_group=project_id,
                            location=getattr(asset.resource, 'location', 'global'),
                            resource_id=asset.name
                        )

                        optimization_results.append(result)

                    except Exception as e:
                        logger.warning(f"Failed to analyze optimization for {asset.name}: {e}")
                        continue

            except Exception as e:
                logger.error(f"Failed to scan project {project_id}: {e}")
                continue

        logger.info(f"Optimization analysis complete. Analyzed {len(optimization_results)} resources")
        return optimization_results

    @staticmethod
    def _analyze_cost_optimization(asset_type: str, data: Dict) -> Dict[str, str]:
        """Analyze cost optimization potential"""
        try:
            if data is None:
                return {
                    'current_config': 'No data available',
                    'utilization': 'Unknown',
                    'potential': 'Unknown',
                    'recommendation': 'Manual review needed',
                    'cost_estimate': 'Unknown'
                }

            if 'storage.googleapis.com/Bucket' in asset_type:
                storage_class = data.get('storageClass', 'STANDARD')
                lifecycle = data.get('lifecycle', {})

                current_config = f"Storage Class: {storage_class}"

                if storage_class == 'STANDARD' and not lifecycle.get('rule'):
                    utilization = "No lifecycle management"
                    potential = "Medium - Consider lifecycle policies"
                    recommendation = "Implement lifecycle policies to move old data to cheaper storage classes"
                    cost_estimate = "Medium"
                elif storage_class in ['NEARLINE', 'COLDLINE', 'ARCHIVE']:
                    utilization = "Cost-optimized storage class"
                    potential = "Low - Already optimized"
                    recommendation = "Configuration appears optimal"
                    cost_estimate = "Low"
                else:
                    utilization = "Active storage"
                    potential = "Low - Monitor usage patterns"
                    recommendation = "Monitor access patterns for optimization opportunities"
                    cost_estimate = "Medium"

            elif 'compute.googleapis.com/Disk' in asset_type:
                disk_type = data.get('type', '').split('/')[-1]
                size_gb = data.get('sizeGb', 0)
                status = data.get('status', 'READY')
                users = data.get('users', [])

                current_config = f"Type: {disk_type} | Size: {size_gb}GB"

                if status == 'READY' and not users:
                    utilization = "Unused - Not attached"
                    potential = "High - Delete or snapshot unused disk"
                    recommendation = "Delete unused disk or create snapshot for backup"
                    cost_estimate = "Wasted"
                elif 'pd-ssd' in disk_type and int(size_gb) < 100:
                    utilization = "Small SSD disk"
                    potential = "Medium - Consider pd-standard for small workloads"
                    recommendation = "Consider pd-standard for cost savings on small disks"
                    cost_estimate = "Medium"
                else:
                    utilization = "In use"
                    potential = "Low - Appropriately sized"
                    recommendation = "Monitor for rightsizing opportunities"
                    cost_estimate = "Appropriate"
            else:
                current_config = "Unknown configuration"
                utilization = "Unknown"
                potential = "Manual review required"
                recommendation = "Manual analysis needed"
                cost_estimate = "Unknown"

            return {
                'current_config': current_config,
                'utilization': utilization,
                'potential': potential,
                'recommendation': recommendation,
                'cost_estimate': cost_estimate
            }
        except Exception as e:
            logger.warning(f"Failed to analyze cost optimization for {asset_type}: {e}")
            return {
                'current_config': 'Analysis failed',
                'utilization': 'Unknown',
                'potential': 'Unknown',
                'recommendation': 'Manual review needed',
                'cost_estimate': 'Unknown'
            }

    def get_storage_compliance_summary(self) -> List[GCPStorageComplianceSummary]:
        """Generate storage compliance summary by application"""
        logger.info("Generating storage compliance summary...")

        # Get all storage resources
        storage_resources = self.query_storage_analysis()

        # Group by application
        app_summaries = {}

        for resource in storage_resources:
            app = resource.application
            if app not in app_summaries:
                app_summaries[app] = {
                    'total': 0,
                    'buckets': 0,
                    'disks': 0,
                    'sql': 0,
                    'bigquery': 0,
                    'encrypted': 0,
                    'secure_transport': 0,
                    'network_secured': 0,
                    'issues': 0
                }

            summary = app_summaries[app]
            summary['total'] += 1

            # Count by type
            if 'Bucket' in resource.storage_type:
                summary['buckets'] += 1
            elif 'Disk' in resource.storage_type:
                summary['disks'] += 1
            elif 'SQL' in resource.storage_type:
                summary['sql'] += 1
            elif 'BigQuery' in resource.storage_type:
                summary['bigquery'] += 1

            # Security metrics
            if 'Customer Managed' in resource.encryption_method or 'Google Managed' in resource.encryption_method:
                summary['encrypted'] += 1

            # Assume secure transport for GCP (HTTPS/TLS by default)
            summary['secure_transport'] += 1

            # Network security (if not high risk)
            if not resource.compliance_risk.startswith('High'):
                summary['network_secured'] += 1

            # Issues
            if resource.is_high_risk:
                summary['issues'] += 1

        # Create summary objects
        summaries = []
        for app, data in app_summaries.items():
            compliance_score = ((data['total'] - data['issues']) / data['total'] * 100) if data['total'] > 0 else 100

            if compliance_score >= 95:
                status = 'Excellent'
            elif compliance_score >= 85:
                status = 'Good'
            elif compliance_score >= 70:
                status = 'Acceptable'
            elif compliance_score >= 50:
                status = 'Needs Improvement'
            else:
                status = 'Critical Issues'

            summary = GCPStorageComplianceSummary(
                application=app,
                total_storage_resources=data['total'],
                storage_bucket_count=data['buckets'],
                persistent_disk_count=data['disks'],
                cloud_sql_count=data['sql'],
                bigquery_dataset_count=data['bigquery'],
                encrypted_resources=data['encrypted'],
                secure_transport_resources=data['secure_transport'],
                network_secured_resources=data['network_secured'],
                resources_with_issues=data['issues'],
                compliance_score=round(compliance_score, 1),
                compliance_status=status
            )

            summaries.append(summary)

        logger.info(f"Generated compliance summary for {len(summaries)} applications")
        return summaries

    # ==========================================================================
    # Comprehensive Analysis Methods
    # ==========================================================================

    def query_comprehensive_storage_analysis(self) -> Dict[str, Any]:
        """
        Perform comprehensive storage analysis - equivalent to Azure's comprehensive analysis
        """
        logger.info("Starting comprehensive GCP storage analysis...")

        results = {}

        try:
            logger.info("Analyzing storage security...")
            results['storage_security'] = self.query_storage_analysis()
            logger.info(f"   Found {len(results['storage_security'])} storage resources")
        except Exception as e:
            logger.error(f"Storage security analysis failed: {e}")
            results['storage_security'] = []

        try:
            logger.info("Analyzing access control...")
            results['access_control'] = self.query_storage_access_control()
            logger.info(f"   Analyzed {len(results['access_control'])} resources")
        except Exception as e:
            logger.error(f"Access control analysis failed: {e}")
            results['access_control'] = []

        try:
            logger.info("Analyzing backup configurations...")
            results['backup_analysis'] = self.query_storage_backup_analysis()
            logger.info(f"   Analyzed {len(results['backup_analysis'])} backup configurations")
        except Exception as e:
            logger.error(f"Backup analysis failed: {e}")
            results['backup_analysis'] = []

        try:
            logger.info("Analyzing optimization opportunities...")
            results['optimization'] = self.query_storage_optimization()
            logger.info(f"   Found {len(results['optimization'])} optimization opportunities")
        except Exception as e:
            logger.error(f"Optimization analysis failed: {e}")
            results['optimization'] = []

        try:
            logger.info("Generating compliance summary...")
            results['compliance_summary'] = self.get_storage_compliance_summary()
            logger.info(f"   Generated summary for {len(results['compliance_summary'])} applications")
        except Exception as e:
            logger.error(f"Compliance summary failed: {e}")
            results['compliance_summary'] = []

        # Calculate summary statistics
        total_resources = len(results['storage_security'])
        high_risk_resources = len([r for r in results['storage_security'] if r.is_high_risk])

        logger.info(f"GCP storage analysis complete!")
        logger.info(f"   Total storage resources: {total_resources}")
        logger.info(f"   High-risk configurations: {high_risk_resources}")
        logger.info(f"   Applications analyzed: {len(results['compliance_summary'])}")

        return results


def main():
    """
    Example usage of GCP Resource Analysis Client
    """
    import sys

    try:
        # Initialize with your project ID
        project_ids = ["concise-volt-436619-g5"]  # Replace with your project IDs

        logger.info("Initializing GCP Resource Analysis Client...")
        client = GCPResourceAnalysisClient(project_ids)

        logger.info("Running comprehensive storage analysis...")
        results = client.query_comprehensive_storage_analysis()

        print("\n" + "=" * 80)
        print("📋 STORAGE SECURITY ANALYSIS RESULTS")
        print("=" * 80)

        for resource in results['storage_security'][:10]:  # Show first 10
            print(f"""
📦 {resource.storage_resource} ({resource.storage_type})
   🏷️  Application: {resource.application}
   🔐 Encryption: {resource.encryption_method}
   🔍 Security: {resource.security_findings}
   ⚠️  Risk: {resource.compliance_risk}
   📍 Location: {resource.location}
   ℹ️  Details: {resource.additional_details}
            """)

        print("\n" + "=" * 80)
        print("📊 COMPLIANCE SUMMARY BY APPLICATION")
        print("=" * 80)

        for summary in results['compliance_summary']:
            print(f"""
🎯 {summary.application}
   📊 Total Resources: {summary.total_storage_resources}
   🪣 Cloud Storage: {summary.storage_bucket_count}
   💾 Persistent Disks: {summary.persistent_disk_count}
   🗄️  Cloud SQL: {summary.cloud_sql_count}
   📈 BigQuery: {summary.bigquery_dataset_count}
   ✅ Compliance Score: {summary.compliance_score}%
   🏆 Status: {summary.compliance_status}
   ⚠️  Issues: {summary.resources_with_issues}
            """)

    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    main()
