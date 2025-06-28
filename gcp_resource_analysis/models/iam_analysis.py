#!/usr/bin/env python3
"""
GCP IAM Analysis Models - FULLY FIXED VERSION

Pydantic data models for GCP Identity and Access Management analysis results.
These models provide type safety and data validation for IAM analysis operations.

COMPREHENSIVE FIXES APPLIED:
1. Fixed field types and validators for proper type conversion
2. Added missing required fields to compliance summary
3. Fixed computed field implementations
4. Corrected property logic and naming
5. Added proper field defaults and validation
6. Fixed emoji representations and string methods
7. Resolved all Pydantic v2 compatibility issues
"""

from pydantic import BaseModel, Field, field_validator, computed_field
from typing import Optional, Union


class GCPServiceAccountSecurityResult(BaseModel):
    """
    GCP Service Account security analysis result
    """
    application: str = Field(..., description="Application tag or identifier")
    service_account_name: str = Field(..., description="Service account name")
    service_account_email: str = Field(..., description="Service account email")
    usage_pattern: str = Field(..., description="Service account usage pattern")
    orphaned_status: str = Field(..., description="Whether the service account appears orphaned")
    security_risk: str = Field(..., description="Security risk assessment")
    service_account_details: str = Field(..., description="Additional service account details")
    key_management: str = Field(..., description="Key management configuration")
    access_pattern: str = Field(..., description="Access pattern analysis")
    project_id: str = Field(..., description="GCP project ID")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_active(self) -> bool:
        """Check if service account is active"""
        return "Active" in self.usage_pattern or "Custom" in self.usage_pattern

    @property
    def has_user_managed_keys(self) -> bool:
        """Check if has user-managed keys"""
        return "user-managed" in self.key_management.lower() or "Mixed" in self.key_management

    @property
    def security_risk_level(self) -> str:
        """Extract security risk level"""
        if self.security_risk.startswith("High"):
            return "High"
        elif self.security_risk.startswith("Medium"):
            return "Medium"
        else:
            return "Low"

    @property
    def is_high_risk(self) -> bool:
        """Check if this service account has high security risk"""
        return self.security_risk.lower().startswith('high') or self.security_risk.lower().startswith('critical')

    @property
    def is_orphaned(self) -> bool:
        """Check if this service account appears to be orphaned"""
        return 'orphaned' in self.orphaned_status.lower() or self.orphaned_status.lower() == 'disabled'

    @property
    def is_default_service_account(self) -> bool:
        """Check if this is a default service account"""
        return ('default' in self.usage_pattern.lower() or
                'compute@developer.gserviceaccount.com' in self.service_account_email)

    def __str__(self) -> str:
        status_emoji = "✅" if not self.is_high_risk else "⚠️"
        return (f"{status_emoji} {self.application}/{self.service_account_name}\n"
                f"   📧 Email: {self.service_account_email}\n"
                f"   🏷️  Usage: {self.usage_pattern}\n"
                f"   ⚠️  Risk: {self.security_risk}\n"
                f"   📋 Status: {self.orphaned_status}\n"
                f"   🔐 Keys: {self.key_management}")


class GCPIAMPolicyBindingResult(BaseModel):
    """
    GCP IAM Policy Binding analysis result - FIXED VERSION
    """
    application: str = Field(..., description="Application tag or identifier")
    resource_name: str = Field(..., description="Resource name with IAM bindings")
    resource_type: str = Field(..., description="Type of GCP resource")
    policy_scope: str = Field(..., description="Scope level of the IAM policy")
    privilege_level: str = Field(..., description="Privilege level assessment")
    external_user_risk: str = Field(..., description="External user access risk")
    security_risk: str = Field(..., description="Overall security risk assessment")
    binding_details: str = Field(..., description="Details of IAM bindings")
    member_count: int = Field(..., description="Number of members with access")
    role_types: str = Field(..., description="Types of roles assigned")
    project_id: str = Field(..., description="GCP project ID")
    location: str = Field(..., description="GCP resource location")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this IAM policy has high security risk"""
        return (self.security_risk.lower().startswith('high') or
                self.security_risk.lower().startswith('critical'))

    @property
    def has_external_users(self) -> bool:
        """Check if this policy grants access to external users"""
        return ('external' in self.external_user_risk.lower() and
                'none' not in self.external_user_risk.lower() and
                'low' not in self.external_user_risk.lower())

    @property
    def has_high_privileges(self) -> bool:
        """Check if this policy includes high privilege roles"""
        return ('high privilege' in self.privilege_level.lower() or
                'admin' in self.privilege_level.lower() or
                'administrative' in self.privilege_level.lower())

    @property
    def has_public_access(self) -> bool:
        """Check if has public access"""
        return ("public access" in self.security_risk.lower() or
                "allUsers" in self.binding_details)

    @property
    def privilege_risk_level(self) -> str:
        """Extract privilege risk level"""
        if "Administrative" in self.privilege_level:
            return "High"
        elif "Limited" in self.privilege_level:
            return "Low"
        else:
            return "Medium"

    def __str__(self) -> str:
        risk_emoji = "🔴" if self.is_high_risk else "🟡" if "medium" in self.security_risk.lower() else "🟢"
        return (f"🔗 {self.application}/{self.resource_name}\n"
                f"   📦 Type: {self.resource_type}\n"
                f"   🎯 Scope: {self.policy_scope}\n"
                f"   ⚡ Privileges: {self.privilege_level}\n"
                f"   👥 Members: {self.member_count}\n"
                f"   {risk_emoji} Risk: {self.security_risk}")


class GCPCustomRoleResult(BaseModel):
    """
    GCP Custom Role analysis result - FIXED VERSION
    """
    application: str = Field(..., description="Application tag or identifier")
    role_name: str = Field(..., description="Custom role name")
    role_type: str = Field(..., description="Type of custom role")
    permission_scope: str = Field(..., description="Scope of permissions")
    security_risk: str = Field(..., description="Security risk assessment")
    role_details: str = Field(..., description="Additional role details")
    permission_count: int = Field(..., description="Number of permissions")
    usage_status: str = Field(..., description="Role usage status")
    project_id: str = Field(..., description="GCP project ID")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def has_limited_scope(self) -> bool:
        """Check if role has limited scope"""
        try:
            count = int(self.permission_count)
            return count <= 10
        except (ValueError, TypeError):
            return "limited" in self.permission_scope.lower()

    @property
    def has_wildcard_permissions(self) -> bool:
        """Check if role has wildcard permissions"""
        return "wildcard" in self.security_risk.lower() or "wildcard" in self.role_details.lower()

    @property
    def is_high_risk(self) -> bool:
        """Check if this custom role has high security risk"""
        return self.security_risk.lower().startswith('high') or self.security_risk.lower().startswith('critical')

    @property
    def is_overly_broad(self) -> bool:
        """Check if this role has overly broad permissions"""
        return 'broad' in self.permission_scope.lower()

    @property
    def is_active(self) -> bool:
        """Check if this role is currently active"""
        return self.usage_status.lower() == 'active'

    def __str__(self) -> str:
        risk_emoji = "🔴" if self.is_high_risk else "🟡" if "medium" in self.security_risk.lower() else "🟢"
        return (f"🎭 {self.application}/{self.role_name}\n"
                f"   🏷️  Type: {self.role_type}\n"
                f"   🔢 Permissions: {self.permission_count}\n"
                f"   📊 Scope: {self.permission_scope}\n"
                f"   {risk_emoji} Risk: {self.security_risk}\n"
                f"   📋 Status: {self.usage_status}")


class GCPWorkloadIdentityResult(BaseModel):
    """
    GCP Workload Identity analysis result
    """
    application: str = Field(..., description="Application tag or identifier")
    service_account_name: str = Field(..., description="Service account name")
    configuration_type: str = Field(..., description="Type of workload identity configuration")
    workload_binding: str = Field(..., description="Workload identity binding status")
    security_configuration: str = Field(..., description="Security configuration details")
    security_risk: str = Field(..., description="Security risk assessment")
    workload_details: str = Field(..., description="Workload identity details")
    kubernetes_integration: str = Field(..., description="Kubernetes integration status")
    project_id: str = Field(..., description="GCP project ID")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this workload identity has high security risk"""
        return self.security_risk.lower().startswith('high') or self.security_risk.lower().startswith('critical')

    @property
    def is_properly_configured(self) -> bool:
        """Check if Workload Identity is properly configured"""
        return "Enabled" in self.kubernetes_integration and "Low" in self.security_risk

    @property
    def has_gke_integration(self) -> bool:
        """Check if has GKE integration"""
        return "GKE" in self.configuration_type

    def __str__(self) -> str:
        risk_emoji = "🔴" if self.is_high_risk else "🟡" if "medium" in self.security_risk.lower() else "🟢"
        return (f"🔄 {self.application}/{self.service_account_name}\n"
                f"   ⚙️  Type: {self.configuration_type}\n"
                f"   🔗 Binding: {self.workload_binding}\n"
                f"   🔐 Security: {self.security_configuration}\n"
                f"   {risk_emoji} Risk: {self.security_risk}\n"
                f"   ☸️  K8s: {self.kubernetes_integration}")


class GCPServiceAccountKeyResult(BaseModel):
    """
    GCP Service Account Key analysis result
    """
    application: str = Field(..., description="Application tag or identifier")
    service_account_name: str = Field(..., description="Service account name")
    key_id: str = Field(..., description="Service account key ID")
    key_type: str = Field(..., description="Type of service account key")
    key_age: str = Field(..., description="Age of the service account key")
    key_usage: str = Field(..., description="Usage pattern of the key")
    security_risk: str = Field(..., description="Security risk assessment")
    key_details: str = Field(..., description="Additional key details")
    project_id: str = Field(..., description="GCP project ID")
    resource_id: str = Field(..., description="Full GCP resource ID")

    @property
    def is_high_risk(self) -> bool:
        """Check if this service account key has high security risk"""
        return self.security_risk.lower().startswith('high') or self.security_risk.lower().startswith('critical')

    @property
    def is_user_managed(self) -> bool:
        """Check if this is a user-managed key"""
        return 'user-managed' in self.key_type.lower() or 'USER_MANAGED' in self.key_details

    @property
    def is_old_key(self) -> bool:
        """Check if this key is considered old"""
        return ('year' in self.key_age.lower() or
                '90 days' in self.key_age.lower() or
                'old' in self.security_risk.lower())

    @property
    def has_weak_algorithm(self) -> bool:
        """Check if key has weak algorithm"""
        return "weak algorithm" in self.security_risk.lower() or "RSA-1024" in self.key_details

    def __str__(self) -> str:
        risk_emoji = "🔴" if self.is_high_risk else "🟡" if "medium" in self.security_risk.lower() else "🟢"
        return (f"🗝️ {self.application}/{self.service_account_name} Key\n"
                f"   🆔 Key ID: {self.key_id}\n"
                f"   🏷️  Type: {self.key_type}\n"
                f"   📅 Age: {self.key_age}\n"
                f"   🎯 Usage: {self.key_usage}\n"
                f"   {risk_emoji} Risk: {self.security_risk}")


class GCPIAMComplianceSummary(BaseModel):
    """
    GCP IAM compliance summary by application - FULLY FIXED VERSION
    """
    application: str = Field(..., description="Application name")

    # Core IAM resource counts - FIXED REQUIRED FIELDS
    total_iam_resources: int = Field(..., description="Total IAM resources analyzed")

    # Service Account fields
    total_service_accounts: int = Field(..., description="Total service accounts")
    secure_service_accounts: int = Field(..., description="Securely configured service accounts")
    orphaned_service_accounts: int = Field(..., description="Potentially orphaned service accounts")

    # Custom Role fields
    total_custom_roles: int = Field(..., description="Total custom roles")
    secure_custom_roles: int = Field(..., description="Securely configured custom roles")

    # IAM Binding fields
    total_iam_bindings: int = Field(..., description="Total IAM policy bindings")
    high_privilege_bindings: int = Field(..., description="High privilege IAM bindings")
    external_user_bindings: int = Field(..., description="Bindings with external users")

    # Key Management fields
    user_managed_keys: int = Field(..., description="User-managed service account keys")
    old_keys: int = Field(..., description="Old service account keys")

    # Summary fields
    total_issues: int = Field(..., description="Total IAM security issues")
    iam_compliance_score: float = Field(..., description="IAM compliance score (0-100)")
    iam_compliance_status: str = Field(..., description="IAM compliance status")

    @field_validator('iam_compliance_score')
    @classmethod
    def validate_compliance_score(cls, v):
        """Ensure compliance score is between 0 and 100"""
        return max(0.0, min(100.0, v))

    # COMPUTED PROPERTIES using @computed_field
    @computed_field
    @property
    def service_account_compliance_rate(self) -> float:
        """Calculate service account compliance rate"""
        if self.total_service_accounts == 0:
            return 0.0
        return (self.secure_service_accounts / self.total_service_accounts) * 100.0

    @computed_field
    @property
    def custom_role_compliance_rate(self) -> float:
        """Calculate custom role compliance rate"""
        if self.total_custom_roles == 0:
            return 0.0
        return (self.secure_custom_roles / self.total_custom_roles) * 100.0

    @computed_field
    @property
    def has_external_access(self) -> bool:
        """Check if there are bindings with external users"""
        return self.external_user_bindings > 0

    @computed_field
    @property
    def has_orphaned_accounts(self) -> bool:
        """Check if there are orphaned service accounts"""
        return self.orphaned_service_accounts > 0

    @computed_field
    @property
    def key_management_risk_level(self) -> str:
        """Assess key management risk level"""
        if self.total_service_accounts == 0:
            return "Unknown"

        user_managed_ratio = self.user_managed_keys / self.total_service_accounts
        if user_managed_ratio > 0.5:
            return "High"
        elif user_managed_ratio > 0.2:
            return "Medium"
        else:
            return "Low"

    @computed_field
    @property
    def overall_compliance_grade(self) -> str:
        """Get overall compliance grade"""
        score = self.iam_compliance_score
        if score >= 95:
            return "A+"
        elif score >= 90:
            return "A"
        elif score >= 85:
            return "B+"
        elif score >= 80:
            return "B"
        elif score >= 75:
            return "C+"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    @computed_field
    @property
    def is_iam_compliant(self) -> bool:
        """Check if IAM is compliant (>= 90%)"""
        return self.iam_compliance_score >= 90.0

    @property
    def is_excellent(self) -> bool:
        """Check if IAM compliance is excellent (>= 95%)"""
        return self.iam_compliance_score >= 95.0

    @property
    def needs_attention(self) -> bool:
        """Check if IAM compliance needs attention (< 70%)"""
        return self.iam_compliance_score < 70.0

    @property
    def has_critical_issues(self) -> bool:
        """Check if there are critical IAM issues"""
        return (self.external_user_bindings > 0 or
                self.high_privilege_bindings > 3 or
                self.orphaned_service_accounts > 0)

    def __str__(self) -> str:
        status_emoji = "🟢" if self.is_iam_compliant else "🟡" if self.iam_compliance_score >= 70 else "🔴"
        return (f"{status_emoji} {self.application} IAM Compliance\n"
                f"   🔑 Service Accounts: {self.total_service_accounts} "
                f"({self.secure_service_accounts} secure, {self.orphaned_service_accounts} orphaned)\n"
                f"   👤 Custom Roles: {self.total_custom_roles} ({self.secure_custom_roles} secure)\n"
                f"   🔐 IAM Bindings: {self.total_iam_bindings} "
                f"({self.high_privilege_bindings} high privilege, {self.external_user_bindings} external)\n"
                f"   🗝️  User Keys: {self.user_managed_keys} ({self.old_keys} old keys)\n"
                f"   ⚠️  Issues: {self.total_issues}\n"
                f"   📈 Score: {self.iam_compliance_score:.1f}% ({self.iam_compliance_status})")


# Enhanced compliance summary with additional GCP-specific metrics
class GCPEnhancedIAMComplianceSummary(GCPIAMComplianceSummary):
    """
    Enhanced GCP IAM compliance summary with additional metrics
    """
    workload_identity_service_accounts: int = Field(0, description="Service accounts using Workload Identity")
    default_service_accounts_in_use: int = Field(0, description="Default service accounts still in use")
    cross_project_bindings: int = Field(0, description="Cross-project IAM bindings")
    service_account_impersonation_grants: int = Field(0, description="Service account impersonation grants")

    @computed_field
    @property
    def workload_identity_adoption_rate(self) -> float:
        """Calculate Workload Identity adoption rate"""
        if self.total_service_accounts == 0:
            return 0.0
        return (self.workload_identity_service_accounts / self.total_service_accounts) * 100.0

    @computed_field
    @property
    def has_default_service_account_usage(self) -> bool:
        """Check if default service accounts are still in use"""
        return self.default_service_accounts_in_use > 0

    def __str__(self) -> str:
        base_str = super().__str__()
        return (f"{base_str}\n"
                f"   🔗 Workload Identity: {self.workload_identity_service_accounts} "
                f"({self.workload_identity_adoption_rate:.1f}% adoption)\n"
                f"   ⚙️  Default SAs: {self.default_service_accounts_in_use}\n"
                f"   🌐 Cross-project: {self.cross_project_bindings}")
