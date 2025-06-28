#!/usr/bin/env python3
"""
GCP IAM Analysis Module

Provides comprehensive analysis of Google Cloud Platform Identity and Access Management resources
including service accounts, IAM policy bindings, custom roles, and access patterns.

This module follows the same pattern as the Azure IAM analysis but adapted for GCP services.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class GCPIAMAnalysisQueries:
    """
    GCP IAM Analysis Query Definitions
    Equivalent to Azure's IAMAnalysisQueries but for Google Cloud Asset Inventory
    """

    @staticmethod
    def get_service_account_security_asset_types() -> List[str]:
        """
        Get asset types for service account security analysis

        Returns:
            List of GCP asset types for service account analysis
        """
        return [
            "iam.googleapis.com/ServiceAccount",
            "iam.googleapis.com/ServiceAccountKey"
        ]

    @staticmethod
    def get_iam_policy_bindings_asset_types() -> List[str]:
        """
        Get asset types for IAM policy bindings analysis

        Returns:
            List of GCP asset types for IAM policy analysis
        """
        return [
            "cloudresourcemanager.googleapis.com/Project",
            "storage.googleapis.com/Bucket",
            "compute.googleapis.com/Instance",
            "container.googleapis.com/Cluster"
        ]

    @staticmethod
    def get_custom_roles_asset_types() -> List[str]:
        """
        Get asset types for custom roles analysis

        Returns:
            List of GCP asset types for custom roles analysis
        """
        return [
            "iam.googleapis.com/Role"
        ]

    @staticmethod
    def get_workload_identity_asset_types() -> List[str]:
        """
        Get asset types for Workload Identity analysis

        Returns:
            List of GCP asset types for Workload Identity analysis
        """
        return [
            "iam.googleapis.com/ServiceAccount",
            "container.googleapis.com/Cluster"
        ]


class GCPServiceAccountSecurityAnalyzer:
    """
    Analyze GCP Service Account security configurations
    Equivalent to Azure's Managed Identity analyzer
    """

    @staticmethod
    def analyze_service_account_security_comprehensive(asset_type: str, data: Dict) -> Dict[str, str]:
        """
        Comprehensive service account security analysis

        Args:
            asset_type: GCP asset type
            data: Asset data from Cloud Asset Inventory

        Returns:
            Dictionary with security analysis results
        """
        try:
            if 'iam.googleapis.com/ServiceAccount' not in asset_type:
                return {
                    'usage_pattern': 'Not a service account',
                    'orphaned_status': 'N/A',
                    'security_risk': 'N/A',
                    'service_account_details': 'Invalid asset type',
                    'key_management': 'N/A',
                    'access_pattern': 'N/A'
                }

            # Extract service account information
            display_name = data.get('displayName', 'Unknown')
            email = data.get('email', '')
            description = data.get('description', '')
            disabled = data.get('disabled', False)

            # Analyze email pattern to determine type
            if '@developer.gserviceaccount.com' in email:
                account_type = 'Default Service Account'
                usage_pattern = 'System Service Account'
            elif '@appspot.gserviceaccount.com' in email:
                account_type = 'App Engine Service Account'
                usage_pattern = 'Application Service Account'
            elif 'compute@developer.gserviceaccount.com' in email:
                account_type = 'Compute Engine Service Account'
                usage_pattern = 'Compute Service Account'
            else:
                account_type = 'User-Created Service Account'
                usage_pattern = 'Custom Service Account'

            # Determine orphaned status
            if disabled:
                orphaned_status = 'Disabled'
            elif not description and account_type == 'User-Created Service Account':
                orphaned_status = 'Potentially Orphaned - No description'
            else:
                orphaned_status = 'In Use'

            # Security risk assessment
            if disabled:
                security_risk = 'Medium - Account disabled but still exists'
            elif account_type == 'Default Service Account':
                security_risk = 'Medium - Default service account (broad permissions)'
            elif 'compute@developer.gserviceaccount.com' in email:
                security_risk = 'High - Compute Engine default (excessive permissions)'
            elif not description and account_type == 'User-Created Service Account':
                security_risk = 'High - Undocumented custom service account'
            else:
                security_risk = 'Low - Custom service account with documentation'

            # Key management analysis (would need separate key asset analysis)
            key_management = 'Google-managed keys (recommended)'

            # Access pattern analysis
            if disabled:
                access_pattern = 'No access - Disabled'
            elif account_type == 'Default Service Account':
                access_pattern = 'Broad service access'
            else:
                access_pattern = 'Custom access pattern'

            service_account_details = f"Type: {account_type} | Email: {email}"
            if description:
                service_account_details += f" | Description: {description[:50]}"

            return {
                'usage_pattern': usage_pattern,
                'orphaned_status': orphaned_status,
                'security_risk': security_risk,
                'service_account_details': service_account_details,
                'key_management': key_management,
                'access_pattern': access_pattern
            }

        except Exception as e:
            logger.warning(f"Failed to analyze service account security: {e}")
            return {
                'usage_pattern': 'Analysis failed',
                'orphaned_status': 'Manual review needed',
                'security_risk': 'Unknown - Analysis failed',
                'service_account_details': 'Error in analysis',
                'key_management': 'Unknown',
                'access_pattern': 'Unknown'
            }


class GCPIAMPolicyAnalyzer:
    """
    Analyze GCP IAM Policy configurations and bindings
    Equivalent to Azure's Role Assignment analyzer
    """

    @staticmethod
    def analyze_iam_policy_bindings_comprehensive(asset_type: str, data: Dict, iam_policy: Dict = None) -> Dict[
        str, str]:
        """
        Comprehensive IAM policy bindings analysis

        Args:
            asset_type: GCP asset type
            data: Asset data from Cloud Asset Inventory
            iam_policy: IAM policy data if available

        Returns:
            Dictionary with IAM policy analysis results
        """
        try:
            if not iam_policy:
                iam_policy = data.get('iamPolicy', {})

            bindings = iam_policy.get('bindings', [])

            if not bindings:
                return {
                    'policy_scope': 'No IAM bindings',
                    'privilege_level': 'No privileges',
                    'external_user_risk': 'No external users',
                    'security_risk': 'Low - No bindings',
                    'binding_details': 'No IAM policy bindings found',
                    'member_count': 0,
                    'role_types': 'None'
                }

            # Analyze resource scope
            resource_name = data.get('name', '')
            if 'projects/' in resource_name:
                if resource_name.count('/') == 1:
                    policy_scope = 'Project Level'
                else:
                    policy_scope = 'Resource Level'
            else:
                policy_scope = 'Resource Level'

            # Analyze privilege levels and members
            high_privilege_roles = []
            external_members = []
            service_accounts = []
            users = []
            groups = []

            for binding in bindings:
                role = binding.get('role', '')
                members = binding.get('members', [])

                # Check for high privilege roles
                if any(keyword in role.lower() for keyword in ['owner', 'editor', 'admin']):
                    high_privilege_roles.append(role)

                # Analyze member types
                for member in members:
                    if member.startswith('user:'):
                        users.append(member)
                        # Check for external users (non-organizational domains)
                        if '@gmail.com' in member or '@outlook.com' in member or '@yahoo.com' in member:
                            external_members.append(member)
                    elif member.startswith('serviceAccount:'):
                        service_accounts.append(member)
                    elif member.startswith('group:'):
                        groups.append(member)

            # Determine privilege level
            if high_privilege_roles:
                privilege_level = f"High Privilege - {len(high_privilege_roles)} admin roles"
            elif len(bindings) > 10:
                privilege_level = f"Multiple Roles - {len(bindings)} bindings"
            else:
                privilege_level = f"Standard Privilege - {len(bindings)} bindings"

            # External user risk assessment
            if external_members:
                external_user_risk = f"High - {len(external_members)} external users"
            elif users and not external_members:
                external_user_risk = f"Medium - {len(users)} organizational users"
            else:
                external_user_risk = "Low - Service accounts and groups only"

            # Overall security risk
            if external_members and high_privilege_roles:
                security_risk = "Critical - External users with admin roles"
            elif external_members:
                security_risk = "High - External users with access"
            elif high_privilege_roles:
                security_risk = "Medium - High privilege roles assigned"
            else:
                security_risk = "Low - Standard access configuration"

            # Binding details
            total_members = len(users) + len(service_accounts) + len(groups)
            member_count = total_members

            role_types = []
            if users:
                role_types.append(f"{len(users)} users")
            if service_accounts:
                role_types.append(f"{len(service_accounts)} service accounts")
            if groups:
                role_types.append(f"{len(groups)} groups")

            role_types_str = ", ".join(role_types) if role_types else "No members"

            binding_details = f"Scope: {policy_scope} | Members: {member_count} | Bindings: {len(bindings)}"

            return {
                'policy_scope': policy_scope,
                'privilege_level': privilege_level,
                'external_user_risk': external_user_risk,
                'security_risk': security_risk,
                'binding_details': binding_details,
                'member_count': member_count,
                'role_types': role_types_str
            }

        except Exception as e:
            logger.warning(f"Failed to analyze IAM policy bindings: {e}")
            return {
                'policy_scope': 'Analysis failed',
                'privilege_level': 'Unknown',
                'external_user_risk': 'Unknown',
                'security_risk': 'Manual review needed',
                'binding_details': 'Error in analysis',
                'member_count': 0,
                'role_types': 'Unknown'
            }


class GCPCustomRoleAnalyzer:
    """
    Analyze GCP Custom Role configurations
    Equivalent to Azure's Custom Role analyzer
    """

    @staticmethod
    def analyze_custom_role_comprehensive(asset_type: str, data: Dict) -> Dict[str, str]:
        """
        Comprehensive custom role analysis

        Args:
            asset_type: GCP asset type
            data: Asset data from Cloud Asset Inventory

        Returns:
            Dictionary with custom role analysis results
        """
        try:
            if 'iam.googleapis.com/Role' not in asset_type:
                return {
                    'role_type': 'Not a custom role',
                    'permission_scope': 'N/A',
                    'security_risk': 'N/A',
                    'role_details': 'Invalid asset type',
                    'permission_count': 0,
                    'usage_status': 'N/A'
                }

            # Extract role information
            title = data.get('title', 'Unknown')
            description = data.get('description', '')
            stage = data.get('stage', 'GA')
            deleted = data.get('deleted', False)
            included_permissions = data.get('includedPermissions', [])

            # Determine role type
            role_name = data.get('name', '')
            if '/roles/' in role_name and 'projects/' in role_name:
                role_type = 'Project Custom Role'
            elif '/roles/' in role_name and 'organizations/' in role_name:
                role_type = 'Organization Custom Role'
            else:
                role_type = 'Custom Role'

            # Analyze permission scope
            permission_count = len(included_permissions)
            if permission_count == 0:
                permission_scope = 'No permissions'
            elif permission_count > 50:
                permission_scope = f'Broad scope - {permission_count} permissions'
            elif permission_count > 20:
                permission_scope = f'Medium scope - {permission_count} permissions'
            else:
                permission_scope = f'Limited scope - {permission_count} permissions'

            # Security risk assessment
            dangerous_permissions = [perm for perm in included_permissions
                                     if any(keyword in perm.lower() for keyword in
                                            ['admin', 'owner', 'delete', 'setiam', 'impersonate'])]

            if deleted:
                security_risk = 'Low - Role deleted'
            elif stage == 'DEPRECATED':
                security_risk = 'Medium - Deprecated role'
            elif dangerous_permissions:
                security_risk = f'High - {len(dangerous_permissions)} dangerous permissions'
            elif permission_count > 50:
                security_risk = 'Medium - Overly broad permissions'
            else:
                security_risk = 'Low - Limited permissions'

            # Usage status
            if deleted:
                usage_status = 'Deleted'
            elif stage == 'DEPRECATED':
                usage_status = 'Deprecated'
            elif stage == 'DISABLED':
                usage_status = 'Disabled'
            else:
                usage_status = 'Active'

            # Role details
            role_details = f"Title: {title}"
            if description:
                role_details += f" | Description: {description[:50]}"
            role_details += f" | Stage: {stage}"

            return {
                'role_type': role_type,
                'permission_scope': permission_scope,
                'security_risk': security_risk,
                'role_details': role_details,
                'permission_count': permission_count,
                'usage_status': usage_status
            }

        except Exception as e:
            logger.warning(f"Failed to analyze custom role: {e}")
            return {
                'role_type': 'Analysis failed',
                'permission_scope': 'Unknown',
                'security_risk': 'Manual review needed',
                'role_details': 'Error in analysis',
                'permission_count': 0,
                'usage_status': 'Unknown'
            }


class GCPWorkloadIdentityAnalyzer:
    """
    Analyze GCP Workload Identity configurations
    GCP-specific analyzer for Kubernetes workload identity federation
    """

    @staticmethod
    def analyze_workload_identity_comprehensive(service_account_data: Dict, cluster_data: Dict = None) -> Dict[
        str, str]:
        """
        Comprehensive Workload Identity analysis

        Args:
            service_account_data: Service account asset data
            cluster_data: Optional GKE cluster data

        Returns:
            Dictionary with Workload Identity analysis results
        """
        try:
            # Check if service account is configured for Workload Identity
            email = service_account_data.get('email', '')
            annotations = service_account_data.get('annotations', {})

            workload_identity_annotation = 'iam.gke.io/gcp-service-account'
            is_workload_identity = workload_identity_annotation in annotations

            if not is_workload_identity:
                return {
                    'configuration_type': 'Standard Service Account',
                    'workload_binding': 'No Workload Identity binding',
                    'security_configuration': 'Standard IAM only',
                    'security_risk': 'Low - Standard service account',
                    'workload_details': 'Not configured for Workload Identity',
                    'kubernetes_integration': 'Not integrated'
                }

            # Extract Workload Identity configuration
            gcp_service_account = annotations.get(workload_identity_annotation, '')

            # Analyze configuration
            if gcp_service_account == email:
                workload_binding = 'Correctly bound to GCP service account'
                security_configuration = 'Workload Identity enabled'
                security_risk = 'Low - Secure workload identity configuration'
            elif gcp_service_account:
                workload_binding = f'Bound to different service account: {gcp_service_account}'
                security_configuration = 'Workload Identity with cross-account binding'
                security_risk = 'Medium - Cross-account binding requires review'
            else:
                workload_binding = 'Workload Identity annotation present but empty'
                security_configuration = 'Incomplete Workload Identity setup'
                security_risk = 'High - Misconfigured Workload Identity'

            configuration_type = 'Workload Identity Service Account'
            kubernetes_integration = 'Integrated with GKE Workload Identity'

            workload_details = f"GCP SA: {email} | Annotation: {gcp_service_account}"

            return {
                'configuration_type': configuration_type,
                'workload_binding': workload_binding,
                'security_configuration': security_configuration,
                'security_risk': security_risk,
                'workload_details': workload_details,
                'kubernetes_integration': kubernetes_integration
            }

        except Exception as e:
            logger.warning(f"Failed to analyze Workload Identity: {e}")
            return {
                'configuration_type': 'Analysis failed',
                'workload_binding': 'Unknown',
                'security_configuration': 'Unknown',
                'security_risk': 'Manual review needed',
                'workload_details': 'Error in analysis',
                'kubernetes_integration': 'Unknown'
            }


class GCPServiceAccountKeyAnalyzer:
    """
    Analyze GCP Service Account Key security
    Critical for understanding key management practices
    """

    @staticmethod
    def analyze_service_account_key_security(asset_type: str, data: Dict) -> Dict[str, str]:
        """
        Analyze service account key security

        Args:
            asset_type: GCP asset type
            data: Asset data from Cloud Asset Inventory

        Returns:
            Dictionary with key security analysis results
        """
        try:
            if 'iam.googleapis.com/ServiceAccountKey' not in asset_type:
                return {
                    'key_type': 'Not a service account key',
                    'key_age': 'N/A',
                    'key_usage': 'N/A',
                    'security_risk': 'N/A',
                    'key_details': 'Invalid asset type'
                }

            # Extract key information
            key_algorithm = data.get('keyAlgorithm', 'UNKNOWN')
            key_origin = data.get('keyOrigin', 'UNKNOWN')
            key_type_val = data.get('keyType', 'UNKNOWN')
            private_key_type = data.get('privateKeyType', 'UNKNOWN')
            valid_after_time = data.get('validAfterTime')
            valid_before_time = data.get('validBeforeTime')

            # Determine key type and origin
            if key_origin == 'GOOGLE_PROVIDED':
                key_type = 'Google-managed key (recommended)'
                key_usage = 'System-managed authentication'
                security_risk = 'Low - Google-managed key'
            elif key_origin == 'USER_PROVIDED':
                key_type = 'User-managed key'
                key_usage = 'External authentication'

                # Calculate key age if possible
                if valid_after_time:
                    try:
                        # Parse timestamp and calculate age
                        from datetime import datetime
                        valid_after = datetime.fromisoformat(valid_after_time.replace('Z', '+00:00'))
                        age_days = (datetime.now().replace(tzinfo=valid_after.tzinfo) - valid_after).days

                        if age_days > 365:
                            key_age = f'{age_days} days (>1 year old)'
                            security_risk = 'High - Key older than 1 year'
                        elif age_days > 90:
                            key_age = f'{age_days} days (>90 days old)'
                            security_risk = 'Medium - Key older than 90 days'
                        else:
                            key_age = f'{age_days} days'
                            security_risk = 'Low - Recent key'
                    except Exception:
                        key_age = 'Unable to determine age'
                        security_risk = 'Medium - Manual review of key age needed'
                else:
                    key_age = 'Unknown age'
                    security_risk = 'Medium - User-managed key age unknown'
            else:
                key_type = f'Unknown origin: {key_origin}'
                key_usage = 'Unknown usage pattern'
                key_age = 'Unknown'
                security_risk = 'High - Unknown key origin'

            key_details = f"Algorithm: {key_algorithm} | Type: {key_type_val} | Origin: {key_origin}"

            return {
                'key_type': key_type,
                'key_age': key_age,
                'key_usage': key_usage,
                'security_risk': security_risk,
                'key_details': key_details
            }

        except Exception as e:
            logger.warning(f"Failed to analyze service account key: {e}")
            return {
                'key_type': 'Analysis failed',
                'key_age': 'Unknown',
                'key_usage': 'Unknown',
                'security_risk': 'Manual review needed',
                'key_details': 'Error in analysis'
            }
