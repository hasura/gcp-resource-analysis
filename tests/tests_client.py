#!/usr/bin/env python3
"""
Comprehensive Test Suite for GCP Resource Analysis Client

This module contains comprehensive tests for the GCP Resource Analysis Client,
including unit tests, integration tests, and mock tests for various scenarios.

Test Categories:
- Unit tests: Test individual methods and functions
- Integration tests: Test with real GCP resources (requires credentials)
- Mock tests: Test with mocked GCP responses
- Error handling tests: Test error scenarios and edge cases
- Enhanced tests: Test new enhanced analysis methods
- Performance tests: Test performance characteristics

Run with: pytest tests_client.py -v --cov=gcp_resource_analysis
"""

import os
from datetime import datetime
from typing import Dict, Any
from unittest.mock import Mock, patch

import pytest

# Import the classes we're testing
from gcp_resource_analysis import GCPResourceAnalysisClient
from gcp_resource_analysis.models import (
    GCPStorageResource,
    GCPStorageBackupResult,
    GCPStorageOptimizationResult,
    GCPStorageComplianceSummary,
    GCPEnhancedStorageComplianceSummary,
    GCPKMSSecurityResult,
    GCPComprehensiveAnalysisResult,
    RateLimitTracker
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def sample_project_ids():
    """Sample project IDs for testing"""
    return ["test-project-1", "test-project-2"]


@pytest.fixture
def mock_credentials():
    """Mock GCP credentials"""
    mock_creds = Mock()
    mock_creds.valid = True
    mock_creds.expired = False
    return mock_creds


@pytest.fixture
def sample_storage_asset():
    """Sample Cloud Storage asset for testing"""
    return {
        "name": "//storage.googleapis.com/projects/test-project-1/buckets/test-bucket",
        "asset_type": "storage.googleapis.com/Bucket",
        "resource": {
            "location": "us-central1",
            "data": {
                "name": "test-bucket",
                "storageClass": "STANDARD",
                "labels": {"application": "test-app"},
                "iamConfiguration": {
                    "publicAccessPrevention": "enforced",
                    "uniformBucketLevelAccess": {"enabled": True}
                },
                "encryption": {
                    "defaultKmsKeyName": "projects/test-project-1/locations/global/keyRings/test-ring/cryptoKeys/test-key"
                }
            }
        }
    }


@pytest.fixture
def sample_sql_asset():
    """Sample Cloud SQL asset for testing"""
    return {
        "name": "//sqladmin.googleapis.com/projects/test-project-1/instances/test-instance",
        "asset_type": "sqladmin.googleapis.com/Instance",
        "resource": {
            "location": "us-central1",
            "data": {
                "name": "test-instance",
                "databaseVersion": "MYSQL_8_0",
                "labels": {"application": "test-app"},
                "settings": {
                    "tier": "db-f1-micro",
                    "ipConfiguration": {
                        "ipv4Enabled": False,
                        "requireSsl": True,
                        "authorizedNetworks": []
                    },
                    "backupConfiguration": {
                        "enabled": True,
                        "pointInTimeRecoveryEnabled": True
                    }
                }
            }
        }
    }


@pytest.fixture
def mock_enhanced_storage_response():
    """Enhanced mock response for comprehensive storage analysis"""
    mock_assets = []

    # Cloud Storage bucket
    bucket_asset = Mock()
    bucket_asset.name = "//storage.googleapis.com/projects/test-project/buckets/test-bucket"
    bucket_asset.asset_type = "storage.googleapis.com/Bucket"
    bucket_asset.resource.location = "us-central1"
    bucket_asset.resource.data = {
        "name": "test-bucket",
        "storageClass": "STANDARD",
        "labels": {"application": "web-app", "env": "production"},
        "iamConfiguration": {
            "publicAccessPrevention": "enforced",
            "uniformBucketLevelAccess": {"enabled": True}
        },
        "encryption": {
            "defaultKmsKeyName": "projects/test/locations/global/keyRings/ring/cryptoKeys/key"
        },
        "versioning": {"enabled": True},
        "lifecycle": {"rule": [{"action": {"type": "Delete"}, "condition": {"age": 30}}]}
    }
    mock_assets.append(bucket_asset)

    # Cloud SQL instance
    sql_asset = Mock()
    sql_asset.name = "//sqladmin.googleapis.com/projects/test-project/instances/test-sql"
    sql_asset.asset_type = "sqladmin.googleapis.com/Instance"
    sql_asset.resource.location = "us-central1"
    sql_asset.resource.data = {
        "name": "test-sql",
        "databaseVersion": "MYSQL_8_0",
        "labels": {"application": "backend-api"},
        "settings": {
            "tier": "db-n1-standard-2",
            "availabilityType": "REGIONAL",
            "ipConfiguration": {
                "ipv4Enabled": False,
                "requireSsl": True,
                "authorizedNetworks": []
            },
            "backupConfiguration": {
                "enabled": True,
                "pointInTimeRecoveryEnabled": True,
                "backupRetentionSettings": {"retainedBackups": 7}
            }
        },
        "diskEncryptionConfiguration": {
            "kmsKeyName": "projects/test/locations/global/keyRings/ring/cryptoKeys/sql-key"
        }
    }
    mock_assets.append(sql_asset)

    # Persistent Disk
    disk_asset = Mock()
    disk_asset.name = "//compute.googleapis.com/projects/test-project/zones/us-central1-a/disks/test-disk"
    disk_asset.asset_type = "compute.googleapis.com/Disk"
    disk_asset.resource.location = "us-central1-a"
    disk_asset.resource.data = {
        "name": "test-disk",
        "sizeGb": "100",
        "type": "projects/test-project/zones/us-central1-a/diskTypes/pd-ssd",
        "status": "READY",
        "users": ["projects/test-project/zones/us-central1-a/instances/test-vm"],
        "diskEncryptionKey": {
            "kmsKeyName": "projects/test/locations/global/keyRings/ring/cryptoKeys/disk-key"
        }
    }
    mock_assets.append(disk_asset)

    return mock_assets


@pytest.fixture
def mock_kms_response():
    """Mock response for KMS security analysis"""
    mock_kms_assets = []

    # KMS CryptoKey
    crypto_key = Mock()
    crypto_key.name = "//cloudkms.googleapis.com/projects/test-project/locations/global/keyRings/test-ring/cryptoKeys/test-key"
    crypto_key.asset_type = "cloudkms.googleapis.com/CryptoKey"
    crypto_key.resource.location = "global"
    crypto_key.resource.data = {
        "name": "test-key",
        "purpose": "ENCRYPT_DECRYPT",
        "labels": {"application": "secure-app"},
        "versionTemplate": {
            "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
            "protectionLevel": "SOFTWARE"
        },
        "rotationSchedule": {
            "rotationPeriod": "P90D",
            "nextRotationTime": "2024-12-01T00:00:00Z"
        }
    }
    mock_kms_assets.append(crypto_key)

    # KMS KeyRing
    key_ring = Mock()
    key_ring.name = "//cloudkms.googleapis.com/projects/test-project/locations/global/keyRings/test-ring"
    key_ring.asset_type = "cloudkms.googleapis.com/KeyRing"
    key_ring.resource.location = "global"
    key_ring.resource.data = {
        "name": "test-ring",
        "labels": {"team": "security"}
    }
    mock_kms_assets.append(key_ring)

    return mock_kms_assets


@pytest.fixture
def mock_asset_client():
    """Mock Asset Service Client"""
    with patch('gcp_resource_analysis.client.asset_v1.AssetServiceClient') as mock_client:
        yield mock_client


@pytest.fixture
def gcp_client(sample_project_ids, mock_asset_client):
    """GCP Resource Analysis Client with mocked dependencies"""
    with patch('gcp_resource_analysis.client.service_account') as mock_sa:
        mock_sa.Credentials.from_service_account_file.return_value = Mock()
        client = GCPResourceAnalysisClient(project_ids=sample_project_ids)
        return client


@pytest.fixture
def enhanced_gcp_client():
    """Enhanced mock GCP client with all dependencies for comprehensive testing"""
    with patch('gcp_resource_analysis.client.asset_v1') as mock_asset_v1, \
            patch('gcp_resource_analysis.client.service_account') as mock_sa, \
            patch('gcp_resource_analysis.client.default') as mock_default:
        # Mock Asset Service Client
        mock_asset_client = Mock()
        mock_asset_v1.AssetServiceClient.return_value = mock_asset_client

        # Mock credentials
        mock_creds = Mock()
        mock_sa.Credentials.from_service_account_file.return_value = mock_creds
        mock_default.return_value = (mock_creds, None)

        # Create a function that returns a new mock request each time
        def create_mock_request():
            mock_request = Mock()
            mock_request.parent = ""
            mock_request.page_size = 1000

            # Create a mock for asset_types with a properly mocked extend method
            mock_asset_types = Mock()
            mock_extend = Mock()
            mock_asset_types.extend = mock_extend
            mock_request.asset_types = mock_asset_types

            return mock_request

        # Set up ListAssetsRequest to return new mock each time
        mock_asset_v1.ListAssetsRequest.side_effect = create_mock_request

        client = GCPResourceAnalysisClient(project_ids=["test-project-1", "test-project-2"])

        # Create a reference mock for testing
        reference_mock = create_mock_request()

        yield client, mock_asset_client, reference_mock


# =============================================================================
# Unit Tests - Basic Functionality
# =============================================================================

class TestGCPResourceAnalysisClient:
    """Test the main GCP Resource Analysis Client"""

    def test_client_initialization(self, sample_project_ids):
        """Test client initialization with different configurations"""
        # Test with project IDs only (mock no default credentials and no env config)
        with patch('gcp_resource_analysis.client.default') as mock_default, \
                patch('gcp_resource_analysis.client.asset_v1.AssetServiceClient'), \
                patch.object(GCPResourceAnalysisClient, '_load_config_from_env') as mock_config:
            from google.auth.exceptions import DefaultCredentialsError
            mock_default.side_effect = DefaultCredentialsError("No default credentials")
            mock_config.return_value = {
                'project_ids': [],
                'credentials_path': None,
                'log_level': 'INFO',
                'max_requests_per_minute': 100
            }
            client = GCPResourceAnalysisClient(project_ids=sample_project_ids)
            assert client.project_ids == sample_project_ids
            assert client.credentials is None

        # Test with credentials path
        with patch('gcp_resource_analysis.client.service_account') as mock_sa, \
                patch('gcp_resource_analysis.client.asset_v1.AssetServiceClient'), \
                patch('os.path.exists', return_value=True):
            mock_creds = Mock()
            mock_sa.Credentials.from_service_account_file.return_value = mock_creds

            client = GCPResourceAnalysisClient(
                project_ids=sample_project_ids,
                credentials_path="/path/to/creds.json"
            )
            assert client.credentials == mock_creds
            mock_sa.Credentials.from_service_account_file.assert_called_once_with("/path/to/creds.json")

    def test_initialization_without_project_ids(self):
        """Test client initialization fails without project IDs"""
        with patch.object(GCPResourceAnalysisClient, '_load_config_from_env',
                          return_value={'project_ids': [], 'credentials_path': None, 'log_level': 'INFO',
                                        'max_requests_per_minute': 100}):
            with pytest.raises(ValueError, match="No project IDs provided"):
                GCPResourceAnalysisClient()

    def test_get_application_tag(self, gcp_client, sample_storage_asset):
        """Test application tag extraction from asset labels"""
        # Create a mock asset object
        mock_asset = Mock()
        mock_asset.name = sample_storage_asset["name"]
        mock_asset.resource.data = sample_storage_asset["resource"]["data"]

        app_name = gcp_client._get_application_tag(mock_asset)
        assert app_name == "test-app"

        # Test with no labels
        mock_asset.resource.data = {"name": "test-bucket"}
        app_name = gcp_client._get_application_tag(mock_asset)
        assert app_name.startswith("Project-")

    def test_analyze_storage_encryption(self, gcp_client, sample_storage_asset):
        """Test storage encryption analysis"""
        mock_asset = Mock()
        mock_asset.asset_type = sample_storage_asset["asset_type"]
        mock_asset.resource.data = sample_storage_asset["resource"]["data"]

        encryption_method = gcp_client._analyze_storage_encryption(mock_asset)
        assert encryption_method == "Customer Managed Key (CMEK)"

        # Test with no CMEK
        mock_asset.resource.data = {"name": "test-bucket"}
        encryption_method = gcp_client._analyze_storage_encryption(mock_asset)
        assert encryption_method == "Google Managed Key (Default)"

    def test_analyze_storage_security(self, gcp_client, sample_storage_asset):
        """Test storage security analysis"""
        mock_asset = Mock()
        mock_asset.asset_type = sample_storage_asset["asset_type"]
        mock_asset.resource.data = sample_storage_asset["resource"]["data"]

        findings, risk = gcp_client._analyze_storage_security(mock_asset)
        assert findings == "Uniform bucket access enabled"
        assert risk == "Low - Secured"


# =============================================================================
# Critical Test - Request Creation Fix
# =============================================================================

class TestRequestCreationFix:
    """Test the critical ListAssetsRequest format fix"""

    def test_create_list_assets_request_method_exists(self, enhanced_gcp_client):
        """Test that _create_list_assets_request method exists and is callable"""
        client, _, _ = enhanced_gcp_client

        # Verify the method exists
        assert hasattr(client, '_create_list_assets_request')
        assert callable(getattr(client, '_create_list_assets_request'))

    def test_create_list_assets_request_format(self, enhanced_gcp_client):
        """Test that _create_list_assets_request uses correct format"""
        client, mock_asset_client, reference_mock = enhanced_gcp_client

        parent = "projects/test-project"
        asset_types = ["storage.googleapis.com/Bucket", "compute.googleapis.com/Disk"]
        page_size = 500

        # Test the new helper method
        result = client._create_list_assets_request(parent, asset_types, page_size)

        # Verify request was created correctly
        assert result is not None
        assert result.parent == parent
        assert result.page_size == page_size

        # Verify the asset_types attribute exists and extend method was called
        assert hasattr(result, 'asset_types')
        assert hasattr(result.asset_types, 'extend')

        # Fix: Use getattr to access the call_count properly
        extend_mock = getattr(result.asset_types, 'extend')
        assert hasattr(extend_mock, 'call_count')
        assert extend_mock.call_count > 0

    def test_create_list_assets_request_default_page_size(self, enhanced_gcp_client):
        """Test default page size in request creation"""
        client, _, reference_mock = enhanced_gcp_client

        result = client._create_list_assets_request(
            "projects/test",
            ["storage.googleapis.com/Bucket"]
        )

        assert result.page_size == 1000  # Default page size

    def test_create_list_assets_request_type_safety(self, enhanced_gcp_client):
        """Test that asset types are properly handled regardless of input type"""
        client, _, _ = enhanced_gcp_client

        # Test with different input types
        test_cases = [
            ["type1", "type2"],  # List
            ("type1", "type2"),  # Tuple
            {"type1", "type2"},  # Set
        ]

        for asset_types in test_cases:
            # Convert as the client would
            if not isinstance(asset_types, list):
                asset_types = list(asset_types)
            asset_types = [str(item) for item in asset_types if item]

            result = client._create_list_assets_request("projects/test", asset_types)
            assert result is not None

    def test_create_list_assets_request_integration(self):
        """Test request creation without complex mocking"""
        # This test verifies the method can be called without complex mock setup
        with patch('gcp_resource_analysis.client.asset_v1') as mock_asset_v1:
            # Simple mock setup
            mock_request = Mock()
            mock_request.parent = ""
            mock_request.page_size = 1000
            mock_request.asset_types = Mock()
            mock_asset_v1.ListAssetsRequest.return_value = mock_request

            # Create client with minimal setup
            with patch('gcp_resource_analysis.client.service_account'), \
                    patch('gcp_resource_analysis.client.default'):
                client = GCPResourceAnalysisClient(project_ids=["test-project"])

                # Test the method
                result = client._create_list_assets_request(
                    "projects/test",
                    ["storage.googleapis.com/Bucket"],
                    1000
                )

                # Basic assertions
                assert result is not None
                assert result.parent == "projects/test"
                assert result.page_size == 1000


# =============================================================================
# Enhanced Analysis Methods Testing
# =============================================================================

class TestEnhancedAnalysisMethods:
    """Test the new enhanced analysis methods"""

    def test_query_enhanced_storage_analysis(self, enhanced_gcp_client, mock_enhanced_storage_response):
        """Test enhanced storage analysis with comprehensive analyzers"""
        client, mock_asset_client, _ = enhanced_gcp_client

        # Mock the rate-limited request
        with patch.object(client, '_make_rate_limited_request', return_value=mock_enhanced_storage_response):
            results = client.query_enhanced_storage_analysis()

            # Verify results
            assert len(results) == 6  # 3 assets × 2 projects
            assert all(isinstance(r, GCPStorageResource) for r in results)

            # Check that enhanced analyzers were used
            bucket_results = [r for r in results if r.storage_type == "Cloud Storage Bucket"]
            assert len(bucket_results) == 2

            sql_results = [r for r in results if r.storage_type == "Cloud SQL Instance"]
            assert len(sql_results) == 2

            disk_results = [r for r in results if r.storage_type == "Persistent Disk"]
            assert len(disk_results) == 2

    def test_query_cloud_kms_security(self, enhanced_gcp_client, mock_kms_response):
        """Test Cloud KMS security analysis"""
        client, _, _ = enhanced_gcp_client

        with patch.object(client, '_make_rate_limited_request', return_value=mock_kms_response):
            results = client.query_cloud_kms_security()

            # Verify KMS results
            assert len(results) == 4  # 2 KMS assets × 2 projects
            assert all(isinstance(r, GCPKMSSecurityResult) for r in results)

            # Check crypto key results
            crypto_key_results = [r for r in results if "CryptoKey" in r.resource_type]
            assert len(crypto_key_results) == 2

            # Verify security analysis was performed
            for result in crypto_key_results:
                assert result.rotation_status is not None
                assert result.access_control is not None
                assert result.security_risk is not None

    def test_query_enhanced_storage_backup_analysis(self, enhanced_gcp_client, mock_enhanced_storage_response):
        """Test enhanced backup analysis"""
        client, _, _ = enhanced_gcp_client

        with patch.object(client, '_make_rate_limited_request', return_value=mock_enhanced_storage_response):
            results = client.query_enhanced_storage_backup_analysis()

            assert len(results) > 0
            assert all(isinstance(r, GCPStorageBackupResult) for r in results)

            # Verify backup analysis fields
            for result in results:
                assert result.backup_configuration is not None
                assert result.retention_policy is not None
                assert result.compliance_status is not None
                assert result.disaster_recovery_risk is not None

    def test_query_enhanced_storage_optimization(self, enhanced_gcp_client, mock_enhanced_storage_response):
        """Test enhanced optimization analysis"""
        client, _, _ = enhanced_gcp_client

        with patch.object(client, '_make_rate_limited_request', return_value=mock_enhanced_storage_response):
            results = client.query_enhanced_storage_optimization()

            assert len(results) > 0
            assert all(isinstance(r, GCPStorageOptimizationResult) for r in results)

            # Verify optimization analysis fields
            for result in results:
                assert result.current_configuration is not None
                assert result.utilization_status is not None
                assert result.cost_optimization_potential is not None
                assert result.optimization_recommendation is not None

    def test_get_enhanced_storage_compliance_summary(self, enhanced_gcp_client):
        """Test enhanced compliance summary generation"""
        client, _, _ = enhanced_gcp_client

        # Mock the dependency methods
        mock_storage_resources = [
            GCPStorageResource(
                application="test-app",
                storage_resource="test-bucket",
                storage_type="Cloud Storage Bucket",
                encryption_method="Customer Managed Key (CMEK)",
                security_findings="Secure configuration",
                compliance_risk="Low - Secured",
                resource_group="test-project",
                location="us-central1",
                additional_details="Test bucket",
                resource_id="//storage.googleapis.com/projects/test/buckets/test-bucket"
            )
        ]

        mock_kms_resources = [
            GCPKMSSecurityResult(
                application="test-app",
                kms_resource="test-key",
                resource_type="CryptoKey",
                rotation_status="Automatic rotation: P90D",
                access_control="Purpose: ENCRYPT_DECRYPT",
                security_findings="Algorithm: GOOGLE_SYMMETRIC_ENCRYPTION",
                security_risk="Low - Automated key management",
                kms_details="Software protection level",
                resource_group="test-project",
                location="global",
                resource_id="//cloudkms.googleapis.com/projects/test/locations/global/keyRings/ring/cryptoKeys/key"
            )
        ]

        with patch.object(client, 'query_enhanced_storage_analysis', return_value=mock_storage_resources), \
                patch.object(client, 'query_cloud_kms_security', return_value=mock_kms_resources):
            results = client.get_enhanced_storage_compliance_summary()

            assert len(results) == 1
            assert isinstance(results[0], GCPEnhancedStorageComplianceSummary)

            summary = results[0]
            assert summary.application == "test-app"
            assert summary.total_storage_resources == 2  # 1 storage + 1 KMS
            assert summary.kms_key_count == 1
            assert summary.compliance_score > 0

    def test_query_comprehensive_analysis_enhanced(self, enhanced_gcp_client):
        """Test comprehensive enhanced analysis"""
        client, _, _ = enhanced_gcp_client

        # Mock all the dependency methods
        mock_storage = [Mock(spec=GCPStorageResource)]
        mock_kms = [Mock(spec=GCPKMSSecurityResult)]
        mock_optimization = [Mock(spec=GCPStorageOptimizationResult)]
        mock_compliance = [Mock(spec=GCPEnhancedStorageComplianceSummary)]

        # Set up the mocks to return expected values
        mock_storage[0].is_high_risk = False
        mock_kms[0].is_high_risk = False
        mock_optimization[0].has_high_optimization_potential = False
        mock_compliance[0].resources_with_issues = 0
        mock_compliance[0].compliance_score = 95.0

        with patch.object(client, 'query_enhanced_storage_analysis', return_value=mock_storage), \
                patch.object(client, 'query_cloud_kms_security', return_value=mock_kms), \
                patch.object(client, 'query_enhanced_storage_optimization', return_value=mock_optimization), \
                patch.object(client, 'get_enhanced_storage_compliance_summary', return_value=mock_compliance):
            result = client.query_comprehensive_analysis_enhanced()

            assert isinstance(result, GCPComprehensiveAnalysisResult)
            assert result.total_resources_analyzed == 2  # 1 storage + 1 KMS
            assert result.overall_compliance_score == 95.0
            assert result.critical_issues_count == 0


# =============================================================================
# Unit Tests - Rate Limiting
# =============================================================================

class TestRateLimitTracker:
    """Test rate limiting functionality"""

    def test_rate_limit_initialization(self):
        """Test rate limiter initialization"""
        tracker = RateLimitTracker()
        assert tracker.requests_made == 0
        assert tracker.max_requests_per_minute == 100

    def test_can_make_request(self):
        """Test request permission logic"""
        tracker = RateLimitTracker()

        # First request should be allowed
        assert tracker.can_make_request() is True

        # Set up scenario where limit is reached
        tracker.requests_made = 100
        tracker.window_start = datetime.now()
        assert tracker.can_make_request() is False

    def test_record_request(self):
        """Test request recording"""
        tracker = RateLimitTracker()
        initial_count = tracker.requests_made

        tracker.record_request()
        assert tracker.requests_made == initial_count + 1

    def test_rate_limit_exceeded_scenario(self):
        """Test rate limiting behavior when limits are exceeded"""
        tracker = RateLimitTracker()
        tracker.max_requests_per_minute = 5

        # Make requests up to the limit
        for i in range(5):
            assert tracker.can_make_request() is True
            tracker.record_request()

        # Next request should be blocked
        assert tracker.can_make_request() is False


# =============================================================================
# Unit Tests - Data Models
# =============================================================================

class TestDataModels:
    """Test Pydantic data models"""

    def test_gcp_storage_resource_model(self):
        """Test GCP Storage Resource model"""
        data = {
            "application": "test-app",
            "storage_resource": "test-bucket",
            "storage_type": "Cloud Storage Bucket",
            "encryption_method": "Customer Managed Key (CMEK)",
            "security_findings": "Secure configuration",
            "compliance_risk": "Low - Encrypted",
            "resource_group": "test-project-1",
            "location": "us-central1",
            "additional_details": "STANDARD storage class",
            "resource_id": "//storage.googleapis.com/projects/test-project-1/buckets/test-bucket"
        }

        resource = GCPStorageResource(**data)
        assert resource.application == "test-app"
        assert resource.is_high_risk is False

    def test_gcp_storage_resource_high_risk(self):
        """Test high risk detection in storage resource"""
        data = {
            "application": "test-app",
            "storage_resource": "test-bucket",
            "storage_type": "Cloud Storage Bucket",
            "encryption_method": "No encryption configured",
            "security_findings": "Public access enabled",
            "compliance_risk": "High - Public access with no encryption",
            "resource_group": "test-project-1",
            "location": "us-central1",
            "additional_details": "",
            "resource_id": "//storage.googleapis.com/projects/test-project-1/buckets/test-bucket"
        }

        resource = GCPStorageResource(**data)
        assert resource.is_high_risk is True

    def test_gcp_kms_security_result_model(self):
        """Test GCPKMSSecurityResult model"""
        data = {
            "application": "secure-app",
            "kms_resource": "test-key",
            "resource_type": "CryptoKey",
            "rotation_status": "Automatic rotation: P90D",
            "access_control": "Purpose: ENCRYPT_DECRYPT",
            "security_findings": "Algorithm: GOOGLE_SYMMETRIC_ENCRYPTION",
            "security_risk": "Low - Automated key management",
            "kms_details": "Software protection level",
            "resource_group": "test-project",
            "location": "global",
            "resource_id": "//cloudkms.googleapis.com/projects/test/locations/global/keyRings/ring/cryptoKeys/key"
        }

        result = GCPKMSSecurityResult(**data)
        assert result.application == "secure-app"
        assert result.is_high_risk is False  # Low risk

        # Test high risk detection
        data["security_risk"] = "High - No automatic rotation"
        high_risk_result = GCPKMSSecurityResult(**data)
        assert high_risk_result.is_high_risk is True

    def test_enhanced_storage_compliance_summary_model(self):
        """Test GCPEnhancedStorageComplianceSummary model"""
        data = {
            "application": "test-app",
            "total_storage_resources": 10,
            "storage_bucket_count": 3,
            "persistent_disk_count": 2,
            "cloud_sql_count": 1,
            "bigquery_dataset_count": 1,
            "spanner_instance_count": 1,
            "filestore_count": 1,
            "memorystore_count": 1,
            "kms_key_count": 2,
            "encrypted_resources": 9,
            "secure_transport_resources": 10,
            "network_secured_resources": 8,
            "resources_with_issues": 1,
            "compliance_score": 90.0,
            "compliance_status": "Good"
        }

        summary = GCPEnhancedStorageComplianceSummary(**data)
        assert summary.total_storage_resources == 10
        assert summary.kms_key_count == 2
        assert summary.compliance_score == 90.0

    def test_storage_backup_result_model(self):
        """Test GCPStorageBackupResult model"""
        data = {
            "application": "backup-app",
            "resource_name": "test-sql",
            "resource_type": "Cloud SQL Instance",
            "backup_configuration": "Automated backups with PITR",
            "retention_policy": "7 days retention",
            "compliance_status": "Compliant - Full backup with PITR",
            "disaster_recovery_risk": "Low - Comprehensive protection",
            "resource_group": "test-project",
            "location": "us-central1",
            "resource_id": "//sqladmin.googleapis.com/projects/test/instances/test-sql"
        }

        result = GCPStorageBackupResult(**data)
        assert result.is_high_risk is False  # Low disaster recovery risk

        # Test high risk
        data["disaster_recovery_risk"] = "High - No backup protection"
        high_risk_result = GCPStorageBackupResult(**data)
        assert high_risk_result.is_high_risk is True

    def test_storage_optimization_result_model(self):
        """Test GCPStorageOptimizationResult model"""
        data = {
            "application": "cost-app",
            "resource_name": "test-disk",
            "optimization_type": "Persistent Disk",
            "current_configuration": "Type: pd-ssd | Size: 100GB",
            "utilization_status": "Unused - Not attached",
            "cost_optimization_potential": "High - Delete or snapshot unused disk",
            "optimization_recommendation": "Delete unused disk",
            "estimated_monthly_cost": "High - eliminate ongoing costs",
            "resource_group": "test-project",
            "location": "us-central1",
            "resource_id": "//compute.googleapis.com/projects/test/zones/us-central1-a/disks/test-disk"
        }

        result = GCPStorageOptimizationResult(**data)
        assert result.has_high_optimization_potential is True

        # Test low optimization potential
        data["cost_optimization_potential"] = "Low - Already optimized"
        low_opt_result = GCPStorageOptimizationResult(**data)
        assert low_opt_result.has_high_optimization_potential is False

    def test_compliance_summary_validation(self):
        """Test compliance summary validation"""
        data = {
            "application": "test-app",
            "total_storage_resources": 10,
            "storage_bucket_count": 5,
            "persistent_disk_count": 3,
            "cloud_sql_count": 1,
            "bigquery_dataset_count": 1,
            "encrypted_resources": 9,
            "secure_transport_resources": 10,
            "network_secured_resources": 8,
            "resources_with_issues": 1,
            "compliance_score": 90.0,
            "compliance_status": "Good"
        }

        summary = GCPStorageComplianceSummary(**data)
        assert summary.compliance_score == 90.0

    def test_comprehensive_analysis_result_model(self):
        """Test GCPComprehensiveAnalysisResult model"""
        # Create mock high-risk storage resources
        high_risk_storage = [
            GCPStorageResource(
                application="risky-app",
                storage_resource="public-bucket",
                storage_type="Cloud Storage Bucket",
                encryption_method="No encryption",
                security_findings="Public access enabled",
                compliance_risk="High - Public access with no encryption",
                resource_group="test-project-1",
                location="us-central1",
                additional_details="",
                resource_id="//storage.googleapis.com/projects/test/buckets/public-bucket"
            ),
            GCPStorageResource(
                application="risky-app-2",
                storage_resource="unencrypted-disk",
                storage_type="Persistent Disk",
                encryption_method="No encryption",
                security_findings="Unencrypted disk",
                compliance_risk="High - No encryption",
                resource_group="test-project-2",
                location="us-central1",
                additional_details="",
                resource_id="//compute.googleapis.com/projects/test/zones/us-central1-a/disks/unencrypted-disk"
            )
        ]

        # Create mock high-risk KMS resources
        high_risk_kms = [
            GCPKMSSecurityResult(
                application="insecure-app",
                kms_resource="weak-key",
                resource_type="CryptoKey",
                rotation_status="No automatic rotation",
                access_control="Purpose: ENCRYPT_DECRYPT",
                security_findings="No rotation schedule configured",
                security_risk="High - No automatic rotation",
                kms_details="Manual key management",
                resource_group="test-project",
                location="global",
                resource_id="//cloudkms.googleapis.com/projects/test/locations/global/keyRings/ring/cryptoKeys/weak-key"
            )
        ]

        # Create mock optimization opportunities
        high_optimization_storage = [
            GCPStorageOptimizationResult(
                application="wasteful-app",
                resource_name="unused-disk",
                optimization_type="Persistent Disk",
                current_configuration="Type: pd-ssd | Size: 100GB",
                utilization_status="Unused - Not attached",
                cost_optimization_potential="High - Delete or snapshot unused disk",
                optimization_recommendation="Delete unused disk",
                estimated_monthly_cost="High - eliminate ongoing costs",
                resource_group="test-project",
                location="us-central1",
                resource_id="//compute.googleapis.com/projects/test/zones/us-central1-a/disks/unused-disk"
            ),
            GCPStorageOptimizationResult(
                application="oversized-app",
                resource_name="oversized-bucket",
                optimization_type="Cloud Storage",
                current_configuration="Storage Class: STANDARD",
                utilization_status="Low usage - Consider archival",
                cost_optimization_potential="High - Move to nearline/coldline",
                optimization_recommendation="Change to nearline storage class",
                estimated_monthly_cost="High - reduce storage costs",
                resource_group="test-project",
                location="us-central1",
                resource_id="//storage.googleapis.com/projects/test/buckets/oversized-bucket"
            )
        ]

        # Create mock low-risk items to ensure proper counting
        low_risk_storage = [
            GCPStorageResource(
                application="secure-app",
                storage_resource="secure-bucket",
                storage_type="Cloud Storage Bucket",
                encryption_method="Customer Managed Key (CMEK)",
                security_findings="Secure configuration",
                compliance_risk="Low - Secured",
                resource_group="test-project",
                location="us-central1",
                additional_details="",
                resource_id="//storage.googleapis.com/projects/test/buckets/secure-bucket"
            )
        ]

        # Test with actual analysis data
        data_with_analysis = {
            "project_ids": ["test-project-1", "test-project-2"],
            "storage_analysis": high_risk_storage + low_risk_storage,  # 2 high-risk + 1 low-risk
            "kms_analysis": high_risk_kms,  # 1 high-risk
            "storage_optimization": high_optimization_storage,  # 2 high optimization opportunities
            "total_resources_analyzed": 100,
            "high_risk_resources": 5,
            "optimization_opportunities": 10,
            "compliance_issues": 3,
            "overall_security_score": 85.0,
            "overall_compliance_score": 90.0,
            "overall_optimization_score": 75.0
        }

        result_with_analysis = GCPComprehensiveAnalysisResult(**data_with_analysis)
        assert result_with_analysis.total_resources_analyzed == 100
        # critical_issues_count should count actual high-risk items from analysis arrays
        assert result_with_analysis.critical_issues_count == 3  # 2 storage + 1 KMS high-risk items
        # total_optimization_savings_opportunities counts high optimization potential items
        assert result_with_analysis.total_optimization_savings_opportunities == 2  # 2 high optimization items from storage_optimization

        # Test with empty arrays to ensure computed properties return 0
        empty_data = {
            "project_ids": ["test-project-1"],
            "total_resources_analyzed": 10,
            "high_risk_resources": 5,  # This is just a summary field, not used for computation
            "optimization_opportunities": 10,  # This is just a summary field, not used for computation
            "compliance_issues": 0,
            "overall_security_score": 100.0,
            "overall_compliance_score": 100.0,
            "overall_optimization_score": 100.0
        }

        empty_result = GCPComprehensiveAnalysisResult(**empty_data)
        # When analysis arrays are empty, computed properties should return 0
        assert empty_result.critical_issues_count == 0  # No high-risk items in analysis arrays
        assert empty_result.total_optimization_savings_opportunities == 0  # No optimization items in analysis arrays

        # Verify that summary fields are preserved but don't affect computed properties
        assert empty_result.high_risk_resources == 5  # Summary field preserved
        assert empty_result.optimization_opportunities == 10  # Summary field preserved


# =============================================================================
# Configuration and Setup Testing
# =============================================================================

class TestConfigurationAndSetup:
    """Test configuration loading and credential setup"""

    def test_load_config_from_env(self):
        """Test environment configuration loading"""
        # Mock environment variables
        env_vars = {
            'GCP_PROJECT_IDS': 'project1,project2,project3',
            'GOOGLE_APPLICATION_CREDENTIALS': '/path/to/creds.json',
            'GCP_ANALYSIS_LOG_LEVEL': 'DEBUG',
            'GCP_ANALYSIS_MAX_REQUESTS_PER_MINUTE': '150'
        }

        with patch.dict(os.environ, env_vars):
            config = GCPResourceAnalysisClient._load_config_from_env()

            assert config['project_ids'] == ['project1', 'project2', 'project3']
            assert config['credentials_path'] == '/path/to/creds.json'
            assert config['log_level'] == 'DEBUG'
            assert config['max_requests_per_minute'] == 150

    def test_load_config_from_env_defaults(self):
        """Test configuration defaults when environment variables are not set"""
        with patch.dict(os.environ, {}, clear=True), \
                patch('os.path.exists', return_value=False), \
                patch('builtins.open', side_effect=FileNotFoundError), \
                patch('dotenv.load_dotenv'):  # Mock load_dotenv to prevent directory walking
            config = GCPResourceAnalysisClient._load_config_from_env()

            assert config['project_ids'] == []
            assert config['credentials_path'] is None
            assert config['log_level'] == 'INFO'
            assert config['max_requests_per_minute'] == 100

    @patch('os.path.exists')
    @patch('gcp_resource_analysis.client.service_account')
    def test_setup_credentials_with_file(self, mock_sa, mock_exists):
        """Test credential setup with service account file"""
        mock_exists.return_value = True
        mock_creds = Mock()
        mock_sa.Credentials.from_service_account_file.return_value = mock_creds

        creds = GCPResourceAnalysisClient._setup_credentials('/path/to/creds.json')

        assert creds == mock_creds
        mock_sa.Credentials.from_service_account_file.assert_called_once_with('/path/to/creds.json')

    @patch('gcp_resource_analysis.client.default')
    def test_setup_credentials_default(self, mock_default):
        """Test credential setup with default credentials"""
        mock_creds = Mock()
        mock_default.return_value = (mock_creds, None)

        creds = GCPResourceAnalysisClient._setup_credentials(None)

        assert creds == mock_creds
        mock_default.assert_called_once()


# =============================================================================
# Integration Tests (require real GCP credentials)
# =============================================================================

class TestIntegration:
    """Integration tests with real GCP resources"""

    @pytest.mark.integration
    @pytest.mark.gcp
    def test_real_storage_analysis(self):
        """Test storage analysis with real GCP resources"""
        # Skip if no credentials available
        if not os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
            pytest.skip("No GCP credentials available for integration test")

        project_ids = [os.getenv("GCP_TEST_PROJECT_ID", "concise-volt-436619-g5")]
        client = GCPResourceAnalysisClient(project_ids=project_ids)

        try:
            print(f"\n🔍 Running storage analysis on project: {project_ids[0]}")

            # First, let's check what APIs are enabled
            print(f"🔧 Debug: Checking if Cloud Asset API is enabled...")
            try:
                import subprocess
                result = subprocess.run([
                    'gcloud', 'services', 'list', '--enabled',
                    '--filter=name:cloudasset.googleapis.com',
                    f'--project={project_ids[0]}', '--quiet'
                ], capture_output=True, text=True, timeout=30)

                if 'cloudasset.googleapis.com' in result.stdout:
                    print(f"✅ Cloud Asset API is enabled")
                else:
                    print(f"❌ Cloud Asset API is NOT enabled - this is likely the problem!")
                    print(f"💡 Run: gcloud services enable cloudasset.googleapis.com --project={project_ids[0]}")

            except Exception as e:
                print(f"⚠️  Could not check API status: {e}")

            # Now try the Asset Inventory analysis
            print(f"\n🔧 Debug: Testing Asset Inventory API directly...")
            asset_types = [
                "storage.googleapis.com/Bucket",
                "compute.googleapis.com/Disk",
                "sqladmin.googleapis.com/Instance",
                "bigquery.googleapis.com/Dataset",
                "spanner.googleapis.com/Instance"
            ]
            print(f"🔍 Searching for asset types: {asset_types}")

            # Test basic Asset Inventory connectivity
            try:
                from google.cloud import asset_v1
                parent = f"projects/{project_ids[0]}"
                print(f"🔧 Debug: Querying parent: {parent}")

                request = client._create_list_assets_request(parent, asset_types, 100)
                print(f"🔧 Debug: Making Asset Inventory API call...")
                response = client._make_rate_limited_request(
                    client.asset_client.list_assets,
                    request=request
                )

                assets_found = list(response)
                print(f"🔧 Debug: Raw Asset Inventory API returned {len(assets_found)} assets")

                if assets_found:
                    print(f"🔧 Debug: Asset details:")
                    for i, asset in enumerate(assets_found[:3]):
                        print(f"     {i + 1}. Name: {asset.name}")
                        print(f"        Type: {asset.asset_type}")
                        print(f"        Location: {getattr(asset.resource, 'location', 'N/A')}")
                        if hasattr(asset.resource, 'data'):
                            data = dict(asset.resource.data)
                            print(f"        Data keys: {list(data.keys())[:5]}")
                        print()

            except Exception as api_error:
                print(f"❌ Asset Inventory API Error: {api_error}")
                print(f"   This could indicate:")
                print(f"   - Asset Inventory API not enabled: gcloud services enable cloudasset.googleapis.com")
                print(f"   - Insufficient permissions: Need roles/cloudasset.viewer")
                print(f"   - Service account configuration issues")

            # Now run the full analysis
            print(f"\n📊 Running full storage analysis...")
            results = client.query_storage_analysis()
            assert isinstance(results, list)

            print(f"📊 Analysis result: Found {len(results)} storage resources")

            if results:
                print("\n" + "=" * 80)
                for i, result in enumerate(results[:5]):  # Show first 5 results
                    assert isinstance(result, GCPStorageResource)
                    assert result.application is not None
                    assert result.storage_resource is not None
                    assert result.storage_type is not None

                    print(f"\n📦 Resource {i + 1}:")
                    print(f"   🏷️  Name: {result.storage_resource}")
                    print(f"   📁 Type: {result.storage_type}")
                    print(f"   🎯 Application: {result.application}")
                    print(f"   🔐 Encryption: {result.encryption_method}")
                    print(f"   🛡️  Security: {result.security_findings}")
                    print(f"   ⚠️  Risk Level: {result.compliance_risk}")
                    print(f"   📍 Location: {result.location}")
                    print(f"   ℹ️  Details: {result.additional_details}")
                    print(f"   🆔 Resource ID: {result.resource_id}")

                if len(results) > 5:
                    print(f"\n... and {len(results) - 5} more resources")
                print("=" * 80)
            else:
                print("\n💡 TROUBLESHOOTING STEPS:")
                print("1. Enable Cloud Asset API:")
                print(f"   gcloud services enable cloudasset.googleapis.com --project={project_ids[0]}")
                print("2. Grant permissions to service account:")
                print(f"   gcloud projects add-iam-policy-binding {project_ids[0]} \\")
                print(f"       --member='serviceAccount:[YOUR_SA_EMAIL]' \\")
                print(f"       --role='roles/cloudasset.viewer'")
                print("3. Wait 5-10 minutes for Asset Inventory to index new resources")
                print("4. Test manually:")
                print(f"   gcloud asset search-all-resources --scope=projects/{project_ids[0]}")

        except Exception as e:
            print(f"❌ Integration test failed: {e}")
            import traceback
            traceback.print_exc()
            pytest.fail(f"Integration test failed: {e}")

    @pytest.mark.integration
    @pytest.mark.gcp
    def test_real_compliance_summary(self):
        """Test compliance summary with real GCP resources"""
        if not os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
            pytest.skip("No GCP credentials available for integration test")

        project_ids = [os.getenv("GCP_TEST_PROJECT_ID", "concise-volt-436619-g5")]
        client = GCPResourceAnalysisClient(project_ids=project_ids)

        try:
            print(f"\n📈 Generating compliance summary for project: {project_ids[0]}")
            summaries = client.get_storage_compliance_summary()
            assert isinstance(summaries, list)

            print(f"📋 Generated {len(summaries)} application summaries:")

            if summaries:
                print("\n" + "=" * 60)
                for i, summary in enumerate(summaries):
                    assert isinstance(summary, GCPStorageComplianceSummary)
                    assert 0 <= summary.compliance_score <= 100

                    # Choose emoji based on compliance score
                    if summary.compliance_score >= 90:
                        status_emoji = "🟢"
                    elif summary.compliance_score >= 75:
                        status_emoji = "🟡"
                    else:
                        status_emoji = "🔴"

                    print(f"\n{status_emoji} Application: {summary.application}")
                    print(f"   📊 Compliance Score: {summary.compliance_score}%")
                    print(f"   🏆 Status: {summary.compliance_status}")
                    print(f"   📦 Total Resources: {summary.total_storage_resources}")
                    print(f"   🪣 Cloud Storage: {summary.storage_bucket_count}")
                    print(f"   💾 Persistent Disks: {summary.persistent_disk_count}")
                    print(f"   🗄️  Cloud SQL: {summary.cloud_sql_count}")
                    print(f"   📈 BigQuery: {summary.bigquery_dataset_count}")
                    print(f"   🔐 Encrypted: {summary.encrypted_resources}")
                    print(f"   🔒 Secure Transport: {summary.secure_transport_resources}")
                    print(f"   🛡️  Network Secured: {summary.network_secured_resources}")
                    print(f"   ⚠️  Issues Found: {summary.resources_with_issues}")

                print("=" * 60)

                # Calculate overall statistics
                total_resources = sum(s.total_storage_resources for s in summaries)
                total_issues = sum(s.resources_with_issues for s in summaries)
                avg_compliance = sum(s.compliance_score for s in summaries) / len(summaries)

                print(f"\n📊 OVERALL PROJECT SUMMARY:")
                print(f"   📦 Total Storage Resources: {total_resources}")
                print(f"   ⚠️  Total Issues: {total_issues}")
                print(f"   📈 Average Compliance Score: {avg_compliance:.1f}%")
                print(f"   🎯 Applications: {len(summaries)}")
            else:
                print("   ℹ️  No applications found or no resources to summarize")

        except Exception as e:
            print(f"❌ Integration test failed: {e}")
            pytest.fail(f"Integration test failed: {e}")


# =============================================================================
# Mock Tests - External API Responses
# =============================================================================

class TestMockedResponses:
    """Test with mocked GCP API responses"""

    def test_query_storage_analysis_mocked(self, gcp_client, sample_storage_asset):
        """Test storage analysis with mocked Asset Inventory response"""

        # Mock the Asset Service response
        mock_response = [Mock()]
        mock_response[0].name = sample_storage_asset["name"]
        mock_response[0].asset_type = sample_storage_asset["asset_type"]
        mock_response[0].resource.data = sample_storage_asset["resource"]["data"]
        mock_response[0].resource.location = sample_storage_asset["resource"]["location"]

        with patch.object(gcp_client, '_make_rate_limited_request', return_value=mock_response):
            results = gcp_client.query_storage_analysis()

            # Should get 2 results (1 for each project in gcp_client.project_ids)
            assert len(results) == 2
            result = results[0]
            assert isinstance(result, GCPStorageResource)
            assert result.application == "test-app"
            assert result.storage_type == "Cloud Storage Bucket"
            assert "Customer Managed" in result.encryption_method

    def test_error_handling_api_failure(self, gcp_client):
        """Test error handling when API calls fail"""

        # Mock an API failure
        with patch.object(gcp_client, '_make_rate_limited_request', side_effect=Exception("API Error")):
            # The method should handle the error gracefully and return empty results
            results = gcp_client.query_storage_analysis()
            assert results == []  # Should return empty list when all API calls fail

    def test_empty_response_handling(self, gcp_client):
        """Test handling of empty API responses"""

        # Mock an empty response
        with patch.object(gcp_client, '_make_rate_limited_request', return_value=[]):
            results = gcp_client.query_storage_analysis()
            assert results == []

    def test_malformed_asset_data_handling(self, gcp_client):
        """Test handling of malformed asset data"""
        # Create malformed asset data
        malformed_asset = Mock()
        malformed_asset.name = "//invalid/resource/path"
        malformed_asset.asset_type = "unknown.service.com/Resource"
        malformed_asset.resource.data = None  # Missing data
        malformed_asset.resource.location = None

        with patch.object(gcp_client, '_make_rate_limited_request', return_value=[malformed_asset]):
            # Should handle malformed data without crashing
            results = gcp_client.query_storage_analysis()
            # May return empty or partial results, but shouldn't crash
            assert isinstance(results, list)


# =============================================================================
# Performance Tests
# =============================================================================

class TestPerformance:
    """Test performance characteristics"""

    @pytest.mark.slow
    def test_large_dataset_handling(self, gcp_client):
        """Test handling of large datasets"""

        # Create a large mock response
        large_response = []
        for i in range(1000):
            mock_asset = Mock()
            mock_asset.name = f"//storage.googleapis.com/projects/test/buckets/bucket-{i}"
            mock_asset.asset_type = "storage.googleapis.com/Bucket"
            mock_asset.resource.data = {"name": f"bucket-{i}", "labels": {"application": "test"}}
            mock_asset.resource.location = "us-central1"
            large_response.append(mock_asset)

        with patch.object(gcp_client, '_make_rate_limited_request', return_value=large_response):
            start_time = datetime.now()
            results = gcp_client.query_storage_analysis()
            end_time = datetime.now()

            # Verify results (2 projects × 1000 assets each = 2000 total)
            assert len(results) == 2000

            # Performance assertion (should complete within reasonable time)
            duration = (end_time - start_time).total_seconds()
            assert duration < 30.0, f"Analysis took too long: {duration} seconds"

    def test_enhanced_analysis_performance(self, enhanced_gcp_client, mock_enhanced_storage_response):
        """Test performance of enhanced analysis methods"""
        client, _, _ = enhanced_gcp_client

        # Create large dataset
        large_response = mock_enhanced_storage_response * 100  # 300 assets

        with patch.object(client, '_make_rate_limited_request', return_value=large_response):
            start_time = datetime.now()
            results = client.query_enhanced_storage_analysis()
            end_time = datetime.now()

            duration = (end_time - start_time).total_seconds()

            # Should handle large datasets efficiently
            assert len(results) == 600  # 300 assets × 2 projects
            assert duration < 10.0  # Should complete within 10 seconds


# =============================================================================
# Utility Functions for Tests
# =============================================================================

def create_mock_asset(asset_type: str, name: str, data: Dict[str, Any], location: str = "us-central1"):
    """Helper function to create mock assets for testing"""
    mock_asset = Mock()
    mock_asset.name = name
    mock_asset.asset_type = asset_type
    mock_asset.resource.data = data
    mock_asset.resource.location = location
    return mock_asset


def assert_valid_storage_resource(resource: GCPStorageResource):
    """Helper function to assert storage resource validity"""
    assert resource.application is not None
    assert resource.storage_resource is not None
    assert resource.storage_type is not None
    assert resource.encryption_method is not None
    assert resource.compliance_risk is not None
    assert resource.resource_id is not None


def test_all_enhanced_methods_exist():
    """Verify all enhanced methods exist and are callable"""
    client_methods = [
        'query_enhanced_storage_analysis',
        'query_cloud_kms_security',
        'query_enhanced_storage_backup_analysis',
        'query_enhanced_storage_optimization',
        'get_enhanced_storage_compliance_summary',
        'query_comprehensive_storage_analysis_enhanced',
        'query_comprehensive_analysis_enhanced',
        '_create_list_assets_request'
    ]

    for method_name in client_methods:
        assert hasattr(GCPResourceAnalysisClient, method_name), f"Method {method_name} not found"
        method = getattr(GCPResourceAnalysisClient, method_name)
        assert callable(method), f"Method {method_name} is not callable"


# =============================================================================
# Test Configuration and Fixtures
# =============================================================================

@pytest.fixture(autouse=True)
def setup_test_environment():
    """Set up test environment before each test"""
    # Set test environment variables
    os.environ["GCP_TEST_MODE"] = "true"
    yield
    # Clean up after test
    if "GCP_TEST_MODE" in os.environ:
        del os.environ["GCP_TEST_MODE"]


# Test execution
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=gcp_resource_analysis", "--cov-report=html"])
