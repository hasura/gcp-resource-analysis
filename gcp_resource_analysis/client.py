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
from typing import List, Dict, Any, Optional, Union

import google.auth.exceptions
from google.auth import default
# Google Cloud imports
from google.cloud import asset_v1
from google.oauth2 import service_account

from gcp_storage_analysis import GCPStorageAnalysisQueries, GCPStorageSecurityAnalyzer, GCPKMSAnalyzer, \
    GCPStorageBackupAnalyzer, GCPStorageOptimizationAnalyzer
# Local imports
from .models import (
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

    @staticmethod
    def _create_list_assets_request(parent: str, asset_types: List[str], page_size: int = 1000) -> asset_v1.ListAssetsRequest:
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

    def query_comprehensive_analysis(self) -> GCPComprehensiveAnalysisResult:
        """
        Perform comprehensive analysis across all resource types

        Returns:
            GCPComprehensiveAnalysisResult with all analysis data
        """
        logger.info("Starting comprehensive GCP resource analysis...")

        # Storage analysis
        storage_analysis = self.query_storage_analysis()
        storage_compliance = self.get_storage_compliance_summary()

        # TODO: Add other analysis types as they are implemented
        # compute_analysis = self.query_compute_analysis()
        # network_analysis = self.query_network_analysis()
        # iam_analysis = self.query_iam_analysis()
        # container_analysis = self.query_container_analysis()

        # Calculate statistics
        total_resources = len(storage_analysis)
        high_risk_resources = len([r for r in storage_analysis if r.is_high_risk])
        optimization_opportunities = len([r for r in self.query_storage_optimization()
                                          if 'High' in r.cost_optimization_potential])
        compliance_issues = sum(s.resources_with_issues for s in storage_compliance)

        result = GCPComprehensiveAnalysisResult(
            project_ids=self.project_ids,
            storage_analysis=storage_analysis,
            storage_compliance=storage_compliance,
            total_resources_analyzed=total_resources,
            high_risk_resources=high_risk_resources,
            optimization_opportunities=optimization_opportunities,
            compliance_issues=compliance_issues
        )

        logger.info("Comprehensive analysis complete!")
        return result


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
