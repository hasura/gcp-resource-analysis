#!/usr/bin/env python3
"""
Enhanced GCP Storage Analysis Module
Comprehensive storage security, compliance, optimization, and governance analysis
Equivalent to Azure Storage Analysis with full feature parity
"""

from typing import List, Dict, Any


class GCPStorageAnalysisQueries:
    """Enhanced GCP storage analysis queries matching Azure functionality"""

    @staticmethod
    def get_comprehensive_storage_asset_types() -> List[str]:
        """
        Get comprehensive list of storage asset types for analysis
        Expanded to match Azure's coverage
        """
        return [
            # Core storage services
            "storage.googleapis.com/Bucket",
            "compute.googleapis.com/Disk",
            "sqladmin.googleapis.com/Instance",
            "bigquery.googleapis.com/Dataset",
            "spanner.googleapis.com/Instance",

            # Additional storage services (new)
            "file.googleapis.com/Instance",  # Cloud Filestore
            "redis.googleapis.com/Instance",  # Memorystore Redis
            "memcache.googleapis.com/Instance",  # Memorystore Memcached

            # Key management (new)
            "cloudkms.googleapis.com/KeyRing",
            "cloudkms.googleapis.com/CryptoKey",
        ]

    @staticmethod
    def get_storage_security_filter() -> str:
        """
        Get asset filter for storage security analysis
        Matches Azure's comprehensive filtering approach
        """
        asset_types = GCPStorageAnalysisQueries.get_comprehensive_storage_asset_types()
        return " OR ".join([f'asset_type="{asset_type}"' for asset_type in asset_types])

    @staticmethod
    def get_backup_analysis_asset_types() -> List[str]:
        """
        Asset types for comprehensive backup analysis
        Expanded beyond just Cloud SQL
        """
        return [
            "sqladmin.googleapis.com/Instance",  # Cloud SQL backups
            "storage.googleapis.com/Bucket",  # Object versioning
            "bigquery.googleapis.com/Dataset",  # BigQuery snapshots
            "spanner.googleapis.com/Instance",  # Spanner automatic backups
            "file.googleapis.com/Instance",  # Filestore snapshots
        ]

    @staticmethod
    def get_optimization_analysis_asset_types() -> List[str]:
        """
        Asset types for cost optimization analysis
        Expanded coverage like Azure
        """
        return [
            "storage.googleapis.com/Bucket",
            "compute.googleapis.com/Disk",
            "sqladmin.googleapis.com/Instance",
            "bigquery.googleapis.com/Dataset",
            "redis.googleapis.com/Instance",
            "memcache.googleapis.com/Instance",
            "file.googleapis.com/Instance",
        ]

    @staticmethod
    def get_kms_security_asset_types() -> List[str]:
        """
        Asset types for KMS security analysis (equivalent to Azure Key Vault)
        """
        return [
            "cloudkms.googleapis.com/KeyRing",
            "cloudkms.googleapis.com/CryptoKey",
        ]


class GCPStorageSecurityAnalyzer:
    """Enhanced storage security analysis logic"""

    @staticmethod
    def analyze_encryption_comprehensive(asset_type: str, data: Dict[str, Any]) -> str:
        """
        Comprehensive encryption analysis matching Azure's sophistication
        """
        try:
            if data is None:
                return 'No data available for analysis'

            if 'storage.googleapis.com/Bucket' in asset_type:
                encryption = data.get('encryption', {})
                if encryption.get('defaultKmsKeyName'):
                    return 'Customer Managed Key (CMEK)'
                else:
                    return 'Google Managed Key (Default)'

            elif 'compute.googleapis.com/Disk' in asset_type:
                disk_encryption_key = data.get('diskEncryptionKey', {})
                if disk_encryption_key.get('kmsKeyName'):
                    return 'Customer Managed Key (CMEK)'
                elif disk_encryption_key.get('sha256'):
                    return 'Customer Supplied Key (CSEK)'
                else:
                    return 'Google Managed Key (Default)'

            elif 'sqladmin.googleapis.com/Instance' in asset_type:
                disk_encryption_config = data.get('diskEncryptionConfiguration', {})
                if disk_encryption_config.get('kmsKeyName'):
                    return 'Customer Managed Key (CMEK)'
                else:
                    return 'Google Managed Key (Default)'

            elif 'bigquery.googleapis.com/Dataset' in asset_type:
                default_encryption_config = data.get('defaultEncryptionConfiguration', {})
                if default_encryption_config.get('kmsKeyName'):
                    return 'Customer Managed Key (CMEK)'
                else:
                    return 'Google Managed Key (Default)'

            elif 'spanner.googleapis.com/Instance' in asset_type:
                encryption_config = data.get('encryptionConfig', {})
                if encryption_config.get('kmsKeyName'):
                    return 'Customer Managed Key (CMEK)'
                else:
                    return 'Google Managed Key (Default)'

            elif 'file.googleapis.com/Instance' in asset_type:
                # Cloud Filestore - always encrypted
                return 'Google Managed Key (Default)'

            elif 'redis.googleapis.com/Instance' in asset_type:
                # Memorystore Redis
                transit_encryption = data.get('transitEncryptionMode', 'DISABLED')
                auth_enabled = data.get('authEnabled', False)

                if transit_encryption != 'DISABLED' and auth_enabled:
                    return 'Transit + Auth Encryption'
                elif transit_encryption != 'DISABLED':
                    return 'Transit Encryption Only'
                elif auth_enabled:
                    return 'Authentication Only'
                else:
                    return 'No Encryption'

            elif 'memcache.googleapis.com/Instance' in asset_type:
                # Memorystore Memcached - in-transit encryption
                return 'Google Managed (In-transit)'

            elif 'cloudkms.googleapis.com/CryptoKey' in asset_type:
                algorithm = data.get('versionTemplate', {}).get('algorithm', 'Unknown')
                return f'Hardware Security Module - {algorithm}'

            return 'Unknown Encryption'
        except Exception as e:
            return f'Analysis Failed: {str(e)}'

    @staticmethod
    def analyze_security_findings_comprehensive(asset_type: str, data: Dict[str, Any]) -> tuple:
        """
        Comprehensive security findings analysis matching Azure's depth
        Returns (security_findings, compliance_risk)
        """
        try:
            if data is None:
                return 'No data available for analysis', 'Analysis Failed - No data'

            if 'storage.googleapis.com/Bucket' in asset_type:
                iam_config = data.get('iamConfiguration', {})
                public_access_prevention = iam_config.get('publicAccessPrevention', 'inherited')
                uniform_bucket_level_access = iam_config.get('uniformBucketLevelAccess', {}).get('enabled', False)

                # Enhanced risk assessment
                if public_access_prevention == 'inherited' and not uniform_bucket_level_access:
                    return 'Public access possible + ACL-based control', 'High - Public access + Legacy ACLs'
                elif public_access_prevention == 'inherited':
                    return 'Public access prevention inherited', 'Medium - Inherited public access policy'
                elif not uniform_bucket_level_access:
                    return 'ACL-based access control enabled', 'Medium - Legacy access control'
                else:
                    return 'Uniform bucket access + public prevention', 'Low - Secured access'

            elif 'sqladmin.googleapis.com/Instance' in asset_type:
                settings = data.get('settings', {})
                ip_config = settings.get('ipConfiguration', {})
                database_flags = settings.get('databaseFlags', [])

                # Enhanced SQL security analysis
                public_ip = ip_config.get('ipv4Enabled', True)
                authorized_networks = ip_config.get('authorizedNetworks', [])
                require_ssl = ip_config.get('requireSsl', False)

                findings = []
                if public_ip and not authorized_networks:
                    findings.append('Public IP with no network restrictions')
                    risk = 'High - Public access with no restrictions'
                elif public_ip and not require_ssl:
                    findings.append('Public IP without SSL requirement')
                    risk = 'Medium - Public access without SSL enforcement'
                elif public_ip:
                    findings.append('Public IP with authorized networks')
                    risk = 'Medium - Network restricted public access'
                else:
                    findings.append('Private IP configuration')
                    risk = 'Low - Private access only'

                # Check for security flags
                security_flags = [flag.get('name', '') for flag in database_flags
                                  if 'log' in flag.get('name', '').lower() or 'audit' in flag.get('name', '').lower()]
                if security_flags:
                    findings.append(f'Security flags configured: {len(security_flags)}')

                return ' | '.join(findings), risk

            elif 'compute.googleapis.com/Disk' in asset_type:
                status = data.get('status', 'READY')
                users = data.get('users', [])
                source_image = data.get('sourceImage', '')

                if status == 'READY' and not users:
                    return 'Disk not attached to any instance', 'Medium - Orphaned resource with storage costs'
                elif not source_image and not users:
                    return 'Empty disk not in use', 'Medium - Unused storage resource'
                elif len(users) > 1:
                    return 'Disk attached to multiple instances', 'Low - Shared disk usage'
                else:
                    return 'Disk attached and in use', 'Low - Normal usage pattern'

            elif 'bigquery.googleapis.com/Dataset' in asset_type:
                access_entries = data.get('access', [])
                default_table_expiration = data.get('defaultTableExpirationMs')

                public_access = any(entry.get('specialGroup') == 'allAuthenticatedUsers' or
                                    entry.get('domain') for entry in access_entries)

                if public_access and not default_table_expiration:
                    return 'Public access with no data expiration', 'High - Public data with no TTL'
                elif public_access:
                    return 'Public access with data expiration', 'Medium - Public data with TTL controls'
                elif not default_table_expiration:
                    return 'Private access without expiration policy', 'Low - Private data, consider TTL'
                else:
                    return 'Private access with expiration policy', 'Low - Well-configured dataset'

            elif 'redis.googleapis.com/Instance' in asset_type:
                tier = data.get('tier', 'BASIC')
                auth_enabled = data.get('authEnabled', False)
                transit_encryption = data.get('transitEncryptionMode', 'DISABLED')

                if not auth_enabled and transit_encryption == 'DISABLED':
                    return 'No authentication or encryption configured', 'High - Unprotected cache service'
                elif not auth_enabled:
                    return 'Transit encryption without authentication', 'Medium - Missing authentication'
                elif transit_encryption == 'DISABLED':
                    return 'Authentication without transit encryption', 'Medium - Missing transit protection'
                else:
                    return 'Authentication and encryption enabled', 'Low - Secured cache configuration'

            elif 'file.googleapis.com/Instance' in asset_type:
                tier = data.get('tier', 'STANDARD')
                networks = data.get('networks', [])

                if not networks:
                    return 'No network configuration found', 'Medium - Network configuration review needed'
                elif tier == 'BASIC':
                    return 'Basic tier without high availability', 'Medium - No HA configuration'
                else:
                    return 'Standard/Premium tier with network access', 'Low - Standard file service'

            elif 'cloudkms.googleapis.com/CryptoKey' in asset_type:
                purpose = data.get('purpose', 'ENCRYPT_DECRYPT')
                rotation_schedule = data.get('rotationSchedule', {})

                if not rotation_schedule:
                    return 'Manual key rotation only', 'Medium - No automatic rotation'
                else:
                    rotation_period = rotation_schedule.get('rotationPeriod', '')
                    return f'Automatic rotation: {rotation_period}', 'Low - Automated key management'

            return 'Configuration review required', 'Manual review needed'
        except Exception as e:
            return f'Security analysis failed: {str(e)}', 'Analysis error - manual review required'

    @staticmethod
    def get_additional_details_comprehensive(asset_type: str, data: Dict[str, Any]) -> str:
        """
        Comprehensive additional details matching Azure's level of information
        """
        try:
            if data is None:
                return "No resource data available"

            if 'storage.googleapis.com/Bucket' in asset_type:
                storage_class = data.get('storageClass', 'STANDARD')
                versioning = data.get('versioning', {}).get('enabled', False)
                lifecycle_rules = len(data.get('lifecycle', {}).get('rule', []))
                return f"Class: {storage_class} | Versioning: {'On' if versioning else 'Off'} | Lifecycle Rules: {lifecycle_rules}"

            elif 'compute.googleapis.com/Disk' in asset_type:
                size_gb = data.get('sizeGb', 'Unknown')
                disk_type = data.get('type', 'Unknown').split('/')[-1] if data.get('type') else 'Unknown'
                status = data.get('status', 'Unknown')
                zone = data.get('zone', '').split('/')[-1] if data.get('zone') else 'Unknown'
                return f"Size: {size_gb}GB | Type: {disk_type} | Status: {status} | Zone: {zone}"

            elif 'sqladmin.googleapis.com/Instance' in asset_type:
                database_version = data.get('databaseVersion', 'Unknown')
                tier = data.get('settings', {}).get('tier', 'Unknown')
                availability_type = data.get('settings', {}).get('availabilityType', 'ZONAL')
                backup_enabled = data.get('settings', {}).get('backupConfiguration', {}).get('enabled', False)
                return f"Version: {database_version} | Tier: {tier} | HA: {availability_type} | Backup: {'On' if backup_enabled else 'Off'}"

            elif 'bigquery.googleapis.com/Dataset' in asset_type:
                location = data.get('location', 'Unknown')
                default_table_expiration = data.get('defaultTableExpirationMs')
                access_count = len(data.get('access', []))
                expiration_info = f" | TTL: {int(default_table_expiration) // 86400000}d" if default_table_expiration else " | TTL: None"
                return f"Location: {location} | Access Entries: {access_count}{expiration_info}"

            elif 'spanner.googleapis.com/Instance' in asset_type:
                config = data.get('config', '').split('/')[-1] if data.get('config') else 'Unknown'
                node_count = data.get('nodeCount', 'Unknown')
                processing_units = data.get('processingUnits', 'Unknown')
                return f"Config: {config} | Nodes: {node_count} | Processing Units: {processing_units}"

            elif 'redis.googleapis.com/Instance' in asset_type:
                tier = data.get('tier', 'BASIC')
                memory_size_gb = data.get('memorySizeGb', 'Unknown')
                redis_version = data.get('redisVersion', 'Unknown')
                replica_count = data.get('replicaCount', 0)
                return f"Tier: {tier} | Memory: {memory_size_gb}GB | Version: {redis_version} | Replicas: {replica_count}"

            elif 'file.googleapis.com/Instance' in asset_type:
                tier = data.get('tier', 'STANDARD')
                file_shares = data.get('fileShares', [])
                capacity = file_shares[0].get('capacityGb', 'Unknown') if file_shares else 'Unknown'
                networks = len(data.get('networks', []))
                return f"Tier: {tier} | Capacity: {capacity}GB | Networks: {networks}"

            elif 'cloudkms.googleapis.com/CryptoKey' in asset_type:
                purpose = data.get('purpose', 'ENCRYPT_DECRYPT')
                algorithm = data.get('versionTemplate', {}).get('algorithm', 'Unknown')
                rotation_period = data.get('rotationSchedule', {}).get('rotationPeriod', 'Manual')
                return f"Purpose: {purpose} | Algorithm: {algorithm} | Rotation: {rotation_period}"

            return "Standard configuration"
        except Exception as e:
            return f"Configuration details unavailable: {str(e)}"


class GCPStorageBackupAnalyzer:
    """Enhanced backup analysis for comprehensive storage services"""

    @staticmethod
    def analyze_backup_configuration_comprehensive(asset_type: str, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Comprehensive backup analysis across all storage services
        Matches Azure's backup analysis depth
        """
        try:
            if data is None:
                return {
                    'backup_configuration': 'No data available for analysis',
                    'retention_policy': 'Unknown',
                    'compliance_status': 'Analysis Failed - No data',
                    'disaster_recovery_risk': 'Unknown'
                }

            if 'storage.googleapis.com/Bucket' in asset_type:
                versioning = data.get('versioning', {}).get('enabled', False)
                lifecycle = data.get('lifecycle', {})
                lifecycle_rules = lifecycle.get('rule', [])

                if versioning and lifecycle_rules:
                    backup_config = f"Object versioning + {len(lifecycle_rules)} lifecycle rules"
                    retention_policy = "Automated lifecycle management"
                    compliance_status = "Compliant - Comprehensive data protection"
                    dr_risk = "Low - Versioning with automated cleanup"
                elif versioning:
                    backup_config = "Object versioning enabled"
                    retention_policy = "Manual version management required"
                    compliance_status = "Partially Compliant - Versioning without lifecycle"
                    dr_risk = "Medium - Manual cleanup required"
                else:
                    backup_config = "No versioning or backup"
                    retention_policy = "No data protection"
                    compliance_status = "Non-Compliant - No backup protection"
                    dr_risk = "High - Data loss risk"

            elif 'sqladmin.googleapis.com/Instance' in asset_type:
                settings = data.get('settings', {})
                backup_config = settings.get('backupConfiguration', {})

                enabled = backup_config.get('enabled', False)
                point_in_time_recovery = backup_config.get('pointInTimeRecoveryEnabled', False)
                backup_retention_settings = backup_config.get('backupRetentionSettings', {})
                retained_backups = backup_retention_settings.get('retainedBackups', 0)

                if enabled and point_in_time_recovery:
                    backup_config_desc = "Automated backups with point-in-time recovery"
                    compliance_status = "Compliant - Full backup with PITR"
                    dr_risk = "Low - Comprehensive protection"
                elif enabled:
                    backup_config_desc = "Automated backups enabled"
                    compliance_status = "Partially Compliant - Basic backups"
                    dr_risk = "Medium - Basic protection"
                else:
                    backup_config_desc = "No automated backups"
                    compliance_status = "Non-Compliant - No backups"
                    dr_risk = "High - No backup protection"

                retention_policy = f"Retained backups: {retained_backups}" if retained_backups else "Default retention"

            elif 'bigquery.googleapis.com/Dataset' in asset_type:
                default_table_expiration = data.get('defaultTableExpirationMs')

                if default_table_expiration:
                    days = int(default_table_expiration) // 86400000
                    backup_config_desc = f"Table expiration policy: {days} days"
                    retention_policy = f"Automatic cleanup after {days} days"
                    compliance_status = "Compliant - Automated data lifecycle"
                    dr_risk = "Medium - Time-based retention"
                else:
                    backup_config_desc = "No automatic expiration"
                    retention_policy = "Manual data management"
                    compliance_status = "Review Required - No automated cleanup"
                    dr_risk = "Low - Persistent storage"

            elif 'spanner.googleapis.com/Instance' in asset_type:
                # Cloud Spanner has built-in automatic backups
                backup_config_desc = "Automatic backups (built-in 7-day retention)"
                retention_policy = "7 days automatic retention"
                compliance_status = "Compliant - Automatic backups"
                dr_risk = "Low - Automatic protection"

            elif 'file.googleapis.com/Instance' in asset_type:
                # Cloud Filestore supports snapshots (would need separate API call)
                backup_config_desc = "Snapshot capability available (manual)"
                retention_policy = "Manual snapshot management"
                compliance_status = "Review Required - Manual backup process"
                dr_risk = "Medium - Manual backup dependency"

            else:
                backup_config_desc = "Unknown backup configuration"
                retention_policy = "Unknown retention policy"
                compliance_status = "Manual review required"
                dr_risk = "Unknown risk level"

            return {
                'backup_configuration': backup_config_desc,
                'retention_policy': retention_policy,
                'compliance_status': compliance_status,
                'disaster_recovery_risk': dr_risk
            }
        except Exception as e:
            return {
                'backup_configuration': f'Analysis failed: {str(e)}',
                'retention_policy': 'Unknown',
                'compliance_status': 'Analysis error',
                'disaster_recovery_risk': 'Unknown'
            }


class GCPStorageOptimizationAnalyzer:
    """Enhanced cost optimization analysis"""

    @staticmethod
    def analyze_cost_optimization_comprehensive(asset_type: str, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Comprehensive cost optimization analysis matching Azure's sophistication
        """
        try:
            if data is None:
                return {
                    'current_configuration': 'No data available for analysis',
                    'utilization_status': 'Unknown',
                    'cost_optimization_potential': 'Unknown',
                    'optimization_recommendation': 'Manual review needed - no data',
                    'estimated_monthly_cost': 'Unknown'
                }

            if 'storage.googleapis.com/Bucket' in asset_type:
                storage_class = data.get('storageClass', 'STANDARD')
                lifecycle = data.get('lifecycle', {})
                versioning = data.get('versioning', {}).get('enabled', False)

                current_config = f"Storage Class: {storage_class}"

                if storage_class == 'STANDARD' and not lifecycle.get('rule'):
                    utilization = "No lifecycle management - potential for optimization"
                    potential = "High - Implement lifecycle policies for cost savings"
                    recommendation = "Set up lifecycle rules to transition older data to Nearline/Coldline/Archive"
                    cost_estimate = "High optimization potential"
                elif storage_class in ['NEARLINE', 'COLDLINE', 'ARCHIVE']:
                    utilization = "Cost-optimized storage class in use"
                    potential = "Low - Already using appropriate storage class"
                    recommendation = "Monitor access patterns for further optimization"
                    cost_estimate = "Already optimized"
                elif versioning and not lifecycle.get('rule'):
                    utilization = "Versioning enabled without lifecycle cleanup"
                    potential = "Medium - Versioned objects may accumulate costs"
                    recommendation = "Implement lifecycle rules to clean up old versions"
                    cost_estimate = "Medium optimization potential"
                else:
                    utilization = "Standard storage configuration"
                    potential = "Low - Monitor usage patterns"
                    recommendation = "Review access patterns for optimization opportunities"
                    cost_estimate = "Monitor and optimize"

            elif 'compute.googleapis.com/Disk' in asset_type:
                disk_type = data.get('type', '').split('/')[-1] if data.get('type') else 'unknown'
                size_gb = int(data.get('sizeGb', 0))
                status = data.get('status', 'READY')
                users = data.get('users', [])

                current_config = f"Type: {disk_type} | Size: {size_gb}GB"

                if status == 'READY' and not users:
                    utilization = "Unused disk - not attached to any instance"
                    potential = "High - Delete unused disk or create snapshot"
                    recommendation = "Delete unused disk after creating snapshot for backup"
                    cost_estimate = "High - eliminate ongoing costs"
                elif 'pd-ssd' in disk_type and size_gb < 100:
                    utilization = "Small SSD disk - may be over-provisioned"
                    potential = "Medium - Consider pd-standard for cost savings"
                    recommendation = "Evaluate if SSD performance is required for small disk"
                    cost_estimate = "Medium - switch to standard disk"
                elif 'pd-ssd' in disk_type and size_gb > 1000:
                    utilization = "Large SSD disk - review performance requirements"
                    potential = "Medium - Validate SSD requirement for large storage"
                    recommendation = "Consider pd-standard for portions not requiring SSD performance"
                    cost_estimate = "Medium - hybrid storage approach"
                else:
                    utilization = "Disk appropriately configured and in use"
                    potential = "Low - Monitor for rightsizing opportunities"
                    recommendation = "Monitor IOPS and throughput for rightsizing"
                    cost_estimate = "Appropriately sized"

            elif 'sqladmin.googleapis.com/Instance' in asset_type:
                settings = data.get('settings', {})
                tier = settings.get('tier', 'Unknown')
                availability_type = settings.get('availabilityType', 'ZONAL')

                current_config = f"Tier: {tier} | Availability: {availability_type}"

                if availability_type == 'REGIONAL' and 'db-f1-micro' in tier:
                    utilization = "Regional HA on small instance"
                    potential = "Medium - HA may be over-provisioned for small workload"
                    recommendation = "Evaluate if regional HA is required for development/test"
                    cost_estimate = "Medium - consider zonal for non-production"
                elif 'db-custom' in tier:
                    utilization = "Custom machine type in use"
                    potential = "Low - Custom sizing suggests optimization"
                    recommendation = "Monitor CPU and memory utilization for rightsizing"
                    cost_estimate = "Monitor for fine-tuning"
                elif tier.startswith('db-n1-highmem'):
                    utilization = "High-memory instance configuration"
                    potential = "Medium - Validate memory requirements"
                    recommendation = "Monitor memory utilization to ensure optimal sizing"
                    cost_estimate = "Medium - validate memory needs"
                else:
                    utilization = "Standard database configuration"
                    potential = "Low - Monitor performance metrics"
                    recommendation = "Regular monitoring for rightsizing opportunities"
                    cost_estimate = "Standard monitoring"

            elif 'redis.googleapis.com/Instance' in asset_type:
                tier = data.get('tier', 'BASIC')
                memory_size_gb = data.get('memorySizeGb', 0)
                replica_count = data.get('replicaCount', 0)

                current_config = f"Tier: {tier} | Memory: {memory_size_gb}GB | Replicas: {replica_count}"

                if tier == 'STANDARD_HA' and replica_count == 0:
                    utilization = "HA tier without read replicas"
                    potential = "Medium - HA tier may be underutilized"
                    recommendation = "Consider BASIC tier if HA is not required"
                    cost_estimate = "Medium - potential tier downgrade"
                elif memory_size_gb > 100:
                    utilization = "Large memory allocation"
                    potential = "Medium - Validate memory requirements"
                    recommendation = "Monitor memory utilization for rightsizing"
                    cost_estimate = "Medium - validate memory usage"
                else:
                    utilization = "Standard cache configuration"
                    potential = "Low - Monitor usage patterns"
                    recommendation = "Monitor cache hit rates and memory usage"
                    cost_estimate = "Standard monitoring"

            else:
                current_config = "Unknown configuration"
                utilization = "Unknown utilization"
                potential = "Manual review required"
                recommendation = "Manual analysis needed for optimization"
                cost_estimate = "Unknown"

            return {
                'current_configuration': current_config,
                'utilization_status': utilization,
                'cost_optimization_potential': potential,
                'optimization_recommendation': recommendation,
                'estimated_monthly_cost': cost_estimate
            }
        except Exception as e:
            return {
                'current_configuration': f'Analysis failed: {str(e)}',
                'utilization_status': 'Unknown',
                'cost_optimization_potential': 'Unknown',
                'optimization_recommendation': 'Manual review needed',
                'estimated_monthly_cost': 'Unknown'
            }


class GCPKMSAnalyzer:
    """Cloud KMS analysis - equivalent to Azure Key Vault"""

    @staticmethod
    def analyze_kms_security(asset_type: str, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Comprehensive KMS security analysis matching Azure Key Vault analysis
        """
        try:
            if data is None:
                return {
                    'rotation_status': 'No data available for analysis',
                    'access_control': 'Unknown',
                    'security_findings': 'Error - no data available',
                    'security_risk': 'Unknown',
                    'kms_details': 'Analysis error - no data'
                }

            if 'cloudkms.googleapis.com/CryptoKey' in asset_type:
                purpose = data.get('purpose', 'ENCRYPT_DECRYPT')
                rotation_schedule = data.get('rotationSchedule', {})
                version_template = data.get('versionTemplate', {})
                algorithm = version_template.get('algorithm', 'Unknown')
                protection_level = version_template.get('protectionLevel', 'SOFTWARE')

                # Key rotation analysis
                if rotation_schedule:
                    rotation_period = rotation_schedule.get('rotationPeriod', 'Unknown')
                    rotation_status = f"Automatic rotation: {rotation_period}"
                    if 'P90D' in rotation_period or 'P30D' in rotation_period:
                        security_risk = "Low - Frequent automatic rotation"
                    elif 'P365D' in rotation_period:
                        security_risk = "Medium - Annual rotation"
                    else:
                        security_risk = "Medium - Long rotation period"
                else:
                    rotation_status = "Manual rotation only"
                    security_risk = "Medium - No automatic rotation"

                # Access control analysis
                access_control = f"Purpose: {purpose} | Protection: {protection_level}"

                # Security findings
                findings = [f"Algorithm: {algorithm}", f"Protection: {protection_level}"]
                if rotation_schedule:
                    findings.append(f"Auto-rotation: {rotation_schedule.get('rotationPeriod', 'Unknown')}")
                else:
                    findings.append("Manual rotation")

                security_findings = " | ".join(findings)

                # Additional details
                kms_details = f"Algorithm: {algorithm} | Protection: {protection_level} | Purpose: {purpose}"

            elif 'cloudkms.googleapis.com/KeyRing' in asset_type:
                # Key ring analysis
                rotation_status = "Key ring container"
                access_control = "IAM controlled key ring"
                security_findings = "Key ring for organizing crypto keys"
                security_risk = "Low - Container resource"
                kms_details = f"Key ring location and organization"

            else:
                rotation_status = "Unknown KMS resource"
                access_control = "Unknown access pattern"
                security_findings = "Manual review required"
                security_risk = "Manual review needed"
                kms_details = "Configuration analysis required"

            return {
                'rotation_status': rotation_status,
                'access_control': access_control,
                'security_findings': security_findings,
                'security_risk': security_risk,
                'kms_details': kms_details
            }
        except Exception as e:
            return {
                'rotation_status': f'Analysis failed: {str(e)}',
                'access_control': 'Unknown',
                'security_findings': 'Error occurred',
                'security_risk': 'Unknown',
                'kms_details': 'Analysis error'
            }
