# GCP Resource Analysis

🔍 **Comprehensive Google Cloud Platform resource analysis for security, compliance, and optimization**

A Python package that provides deep analysis of your GCP resources using Cloud Asset Inventory API, enabling comprehensive security assessments, compliance monitoring, and cost optimization across your Google Cloud infrastructure.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Google Cloud](https://img.shields.io/badge/Google%20Cloud-4285F4?logo=google-cloud&logoColor=white)](https://cloud.google.com/)

## 🎯 Features

### 📊 **Comprehensive Resource Analysis**
- **Storage Analysis**: Cloud Storage, Cloud SQL, BigQuery, Persistent Disks, Cloud Spanner
- **Encryption Analysis**: CMEK vs Google-managed encryption detection
- **KMS Analysis**: Cloud KMS key management and rotation policies
- **Access Control**: Public access configuration and IAM security
- **Backup Analysis**: Backup policies and disaster recovery readiness
- **Cost Optimization**: Unused resources and right-sizing opportunities

### 🛡️ **Security & Compliance**
- Encryption method detection and analysis
- Public access configuration assessment
- Network security evaluation
- IAM privilege and access control review
- Compliance scoring with detailed findings
- Risk-based resource prioritization

### 💰 **Cost Optimization**
- Unused and orphaned resource identification
- Storage class optimization recommendations
- Right-sizing analysis for compute resources
- Lifecycle policy suggestions
- Cost-saving opportunity assessment

### 📈 **Reporting & Analytics**
- Application-based compliance summaries
- Risk-based resource categorization
- CSV/JSON/HTML export capabilities
- Comprehensive compliance reports
- Resource utilization analytics

## 🚀 Quick Start

### Installation

```bash
pip install gcp-resource-analysis
```

### Basic Usage

```python
from gcp_resource_analysis import GCPResourceAnalysisClient

# Initialize client
client = GCPResourceAnalysisClient(
    project_ids=["your-project-id-1", "your-project-id-2"]
)

# Run comprehensive analysis
results = client.query_comprehensive_storage_analysis()

# View high-risk resources
for resource in results['storage_security']:
    if resource.is_high_risk:
        print(f"⚠️ {resource.storage_resource}: {resource.compliance_risk}")

# Get compliance summary
summaries = client.get_enhanced_storage_compliance_summary()
for summary in summaries:
    print(f"📊 {summary.application}: {summary.compliance_score}% compliance")
```

### Environment Configuration

```bash
# Set up environment variables
export GCP_PROJECT_IDS="project1,project2,project3"
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
export GCP_ANALYSIS_LOG_LEVEL="INFO"
```

## 📋 Prerequisites

### 1. Authentication Setup

**Option A: Service Account (Recommended)**
```bash
# Create service account
gcloud iam service-accounts create gcp-resource-analyzer \
    --description="GCP Resource Analysis Service Account" \
    --display-name="GCP Resource Analyzer"

# Grant permissions
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:gcp-resource-analyzer@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/cloudasset.viewer"

# Create and download key
gcloud iam service-accounts keys create ~/gcp-analyzer-key.json \
    --iam-account=gcp-resource-analyzer@YOUR_PROJECT_ID.iam.gserviceaccount.com

# Set environment variable
export GOOGLE_APPLICATION_CREDENTIALS=~/gcp-analyzer-key.json
```

**Option B: User Account**
```bash
gcloud auth application-default login
```

### 2. Enable Required APIs

```bash
# Enable Cloud Asset Inventory API (required)
gcloud services enable cloudasset.googleapis.com

# Enable additional APIs for enhanced analysis
gcloud services enable storage.googleapis.com
gcloud services enable sqladmin.googleapis.com
gcloud services enable compute.googleapis.com
gcloud services enable bigquery.googleapis.com
gcloud services enable cloudkms.googleapis.com
```

### 3. IAM Permissions

Your service account or user needs these roles:
- `roles/cloudasset.viewer` - View resource inventory (required)
- `roles/storage.objectViewer` - Analyze storage resources
- `roles/cloudsql.viewer` - Analyze Cloud SQL instances
- `roles/compute.viewer` - Analyze compute resources
- `roles/bigquery.metadataViewer` - Analyze BigQuery datasets
- `roles/cloudkms.viewer` - Analyze KMS keys

## 📚 API Reference

### 🏗️ **GCPResourceAnalysisClient**

Main client class providing all analysis functionality.

```python
from gcp_resource_analysis import GCPResourceAnalysisClient

client = GCPResourceAnalysisClient(
    project_ids=["project-1", "project-2"],
    credentials_path="/path/to/service-account.json"  # Optional
)
```

### 📦 **Storage Analysis Methods**

#### Enhanced Storage Security Analysis
```python
# Comprehensive storage security analysis
storage_resources = client.query_enhanced_storage_analysis()

# Basic storage analysis
storage_resources = client.query_storage_analysis()

# Access control analysis
access_results = client.query_storage_access_control()

# Backup configuration analysis
backup_results = client.query_enhanced_storage_backup_analysis()

# Cost optimization analysis
optimization_results = client.query_enhanced_storage_optimization()

# Enhanced compliance summary
compliance_summaries = client.get_enhanced_storage_compliance_summary()
```

#### Cloud KMS Analysis
```python
# KMS security analysis
kms_results = client.query_cloud_kms_security()

# Analyze key rotation policies, access controls, and security configurations
for kms_result in kms_results:
    if kms_result.is_high_risk:
        print(f"⚠️ KMS Risk: {kms_result.kms_resource} - {kms_result.security_risk}")
```

#### Comprehensive Analysis
```python
# Run all enhanced analysis methods
comprehensive_results = client.query_comprehensive_analysis_enhanced()

# Access individual components
storage_analysis = comprehensive_results.storage_analysis
kms_analysis = comprehensive_results.kms_analysis
optimization_results = comprehensive_results.storage_optimization
compliance_summary = comprehensive_results.storage_compliance

print(f"Overall Security Score: {comprehensive_results.overall_security_score}%")
print(f"Critical Issues: {comprehensive_results.critical_issues_count}")
```

### 📊 **Data Models**

#### Storage Resource Model
```python
from gcp_resource_analysis.models import GCPStorageResource

# Example storage resource
resource = GCPStorageResource(
    application="web-app",                    # Application name from labels
    storage_resource="production-bucket",     # Resource name
    storage_type="Cloud Storage Bucket",     # Resource type
    encryption_method="Customer Managed Key (CMEK)",  # Encryption type
    security_findings="Uniform bucket access enabled",  # Security config
    compliance_risk="Low - Secured",         # Risk assessment
    resource_group="production-project",     # Project ID
    location="us-central1",                 # GCP region/zone
    additional_details="STANDARD storage class | Versioning: On",
    resource_id="//storage.googleapis.com/projects/prod/buckets/production-bucket"
)

# Check if resource is high risk
if resource.is_high_risk:
    print(f"High risk resource: {resource.storage_resource}")
```

#### Enhanced Compliance Summary Model
```python
from gcp_resource_analysis.models import GCPEnhancedStorageComplianceSummary

# Example enhanced compliance summary
summary = GCPEnhancedStorageComplianceSummary(
    application="web-application",
    total_storage_resources=25,
    storage_bucket_count=8,
    persistent_disk_count=12,
    cloud_sql_count=3,
    bigquery_dataset_count=1,
    spanner_instance_count=0,
    filestore_count=1,
    memorystore_count=0,
    kms_key_count=5,                    # Enhanced: includes KMS keys
    encrypted_resources=23,
    secure_transport_resources=25,
    network_secured_resources=22,
    resources_with_issues=2,
    compliance_score=92.0,
    compliance_status="Good"
)
```

#### KMS Security Result Model
```python
from gcp_resource_analysis.models import GCPKMSSecurityResult

# Example KMS analysis result
kms_result = GCPKMSSecurityResult(
    application="secure-app",
    kms_resource="encryption-key",
    resource_type="CryptoKey",
    rotation_status="Automatic rotation: P90D",
    access_control="Purpose: ENCRYPT_DECRYPT | Protection: SOFTWARE",
    security_findings="Algorithm: GOOGLE_SYMMETRIC_ENCRYPTION | Auto-rotation: P90D",
    security_risk="Low - Automated key management",
    kms_details="Software protection level with quarterly rotation",
    resource_group="security-project",
    location="global",
    resource_id="//cloudkms.googleapis.com/projects/security/locations/global/keyRings/main/cryptoKeys/encryption-key"
)
```

## 🔍 Analysis Examples

### Security Analysis

```python
# Find publicly accessible storage
access_results = client.query_storage_access_control()
public_resources = [r for r in access_results if r.is_high_risk]

# Find unencrypted resources
storage_results = client.query_enhanced_storage_analysis()
unencrypted = [r for r in storage_results
               if "No encryption" in r.encryption_method]

# High-risk configurations across all resource types
high_risk_storage = [r for r in storage_results if r.is_high_risk]
high_risk_kms = [r for r in client.query_cloud_kms_security() if r.is_high_risk]

print(f"High-risk storage resources: {len(high_risk_storage)}")
print(f"High-risk KMS resources: {len(high_risk_kms)}")
```

### Cost Optimization Analysis

```python
# Find unused resources
optimization_results = client.query_enhanced_storage_optimization()
unused = [r for r in optimization_results
          if "unused" in r.utilization_status.lower()]

# High savings potential
high_savings = [r for r in optimization_results
                if r.has_high_optimization_potential]

# Storage lifecycle opportunities
lifecycle_opps = [r for r in optimization_results
                  if "lifecycle" in r.optimization_recommendation.lower()]

print(f"Unused resources: {len(unused)}")
print(f"High savings opportunities: {len(high_savings)}")
print(f"Lifecycle optimization opportunities: {len(lifecycle_opps)}")
```

### Compliance Reporting

```python
from gcp_resource_analysis.utils import create_compliance_report, export_to_csv

# Generate enhanced compliance summary
summaries = client.get_enhanced_storage_compliance_summary()

# Create HTML compliance report
create_compliance_report(summaries, "enhanced_compliance_report.html")

# Export detailed analysis to CSV
storage_results = client.query_enhanced_storage_analysis()
export_to_csv(storage_results, "detailed_storage_analysis.csv")

# Export KMS analysis
kms_results = client.query_cloud_kms_security()
export_to_csv(kms_results, "kms_security_analysis.csv")
```

## 🛠️ Advanced Usage

### Multi-Project Analysis with Rate Limiting

```python
# Configure rate limiting
client = GCPResourceAnalysisClient(
    project_ids=["prod-1", "prod-2", "staging", "dev"]
)

# Customize rate limiting
client.rate_limiter.max_requests_per_minute = 50

# Run comprehensive analysis across all projects
results = client.query_comprehensive_analysis_enhanced()

print(f"Projects analyzed: {len(results.project_ids)}")
print(f"Total resources: {results.total_resources_analyzed}")
print(f"Critical issues: {results.critical_issues_count}")
print(f"Overall security score: {results.overall_security_score}%")
```

### Custom Analysis Filtering

```python
# Filter by application
app_resources = [r for r in storage_results if r.application == "critical-app"]

# Filter by risk level
critical_issues = [r for r in storage_results
                   if r.compliance_risk.startswith("High")]

# Filter by location/region
us_resources = [r for r in storage_results
                if r.location.startswith("us-")]

# Filter by encryption type
cmek_resources = [r for r in storage_results
                  if "Customer Managed" in r.encryption_method]

# Combine filters
critical_unencrypted = [r for r in storage_results
                        if r.is_high_risk and "No encryption" in r.encryption_method]
```

### Comprehensive Security Assessment

```python
def assess_project_security(project_id):
    """Comprehensive security assessment for a single project"""
    client = GCPResourceAnalysisClient(project_ids=[project_id])

    # Run all analysis methods
    storage_analysis = client.query_enhanced_storage_analysis()
    kms_analysis = client.query_cloud_kms_security()
    access_analysis = client.query_storage_access_control()
    backup_analysis = client.query_enhanced_storage_backup_analysis()

    # Calculate security metrics
    total_resources = len(storage_analysis) + len(kms_analysis)
    high_risk_count = (len([r for r in storage_analysis if r.is_high_risk]) +
                       len([r for r in kms_analysis if r.is_high_risk]))

    encrypted_count = len([r for r in storage_analysis
                           if "Customer Managed" in r.encryption_method or
                              "Google Managed" in r.encryption_method])

    security_score = ((total_resources - high_risk_count) / total_resources * 100) if total_resources > 0 else 100
    encryption_score = (encrypted_count / len(storage_analysis) * 100) if storage_analysis else 100

    return {
        'project_id': project_id,
        'total_resources': total_resources,
        'high_risk_count': high_risk_count,
        'security_score': round(security_score, 1),
        'encryption_score': round(encryption_score, 1),
        'storage_resources': len(storage_analysis),
        'kms_resources': len(kms_analysis),
        'public_access_issues': len([r for r in access_analysis if r.is_high_risk]),
        'backup_issues': len([r for r in backup_analysis if r.is_high_risk])
    }

# Assess multiple projects
projects = ["prod-project", "staging-project", "dev-project"]
for project in projects:
    assessment = assess_project_security(project)
    print(f"📊 {assessment['project_id']}: {assessment['security_score']}% security score")
```

## 📊 Sample Output

### Enhanced Storage Analysis Results
```
🔍 GCP Resource Analysis Results
================================================================================

📦 Storage Resources Found: 127
├── 🪣 Cloud Storage Buckets: 45
├── 💾 Persistent Disks: 32
├── 🗄️ Cloud SQL Instances: 18
├── 📈 BigQuery Datasets: 12
├── 🔑 Cloud KMS Keys: 15
└── 📁 Cloud Filestore: 5

🛡️ Security Analysis:
├── ✅ Encrypted Resources: 118/127 (93%)
├── 🔐 CMEK Encrypted: 42/127 (33%)
├── 🌐 Network Secured: 115/127 (91%)
├── 🔄 Auto-Rotating Keys: 12/15 (80%)
└── ⚠️ High-Risk Issues: 9

💰 Cost Optimization:
├── 💡 High Savings Potential: 12 resources
├── 📊 Unused Resources: 5 disks, 2 buckets
├── 🔄 Lifecycle Opportunities: 18 buckets
└── 💾 Right-sizing Opportunities: 8 SQL instances

📈 Enhanced Compliance Summary:
├── 🟢 Excellent (95-100%): 3 applications
├── 🟡 Good (85-94%): 5 applications
├── 🟠 Needs Improvement (70-84%): 2 applications
└── 🔴 Critical Issues (<70%): 1 application

🔑 KMS Security:
├── 🔄 Auto-Rotation Enabled: 12/15 keys
├── 🛡️ Software Protected: 10/15 keys
├── 🔒 Hardware Protected: 5/15 keys
└── ⚠️ Manual Rotation Only: 3/15 keys

Overall Scores:
├── 📊 Security Score: 87.4%
├── 📈 Compliance Score: 91.2%
└── 💰 Optimization Score: 78.6%
```

## 🧪 Testing

### Run Tests
```bash
# Install development dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run specific test categories
pytest -m unit              # Unit tests only
pytest -m integration       # Integration tests (requires GCP credentials)
pytest -m gcp              # Tests requiring real GCP resources

# Run with coverage
pytest --cov=gcp_resource_analysis --cov-report=html
```

### Test Configuration
```bash
# Set up test environment
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/test-service-account.json
export GCP_TEST_PROJECT_ID=your-test-project
export GCP_PROJECT_IDS=test-project-1,test-project-2

# Run integration tests
pytest -m integration -v
```

### Test Categories

- **Unit Tests**: Test individual methods and functions without external dependencies
- **Integration Tests**: Test with real GCP API calls (requires credentials and enabled APIs)
- **Mock Tests**: Test with mocked GCP responses for various scenarios
- **Enhanced Tests**: Test new enhanced analysis methods and comprehensive features
- **Performance Tests**: Test performance characteristics with large datasets

## 🔧 Configuration

### Environment Variables
```bash
# Required
export GCP_PROJECT_IDS="project1,project2,project3"

# Optional
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
export GCP_ANALYSIS_LOG_LEVEL="INFO"  # DEBUG, INFO, WARNING, ERROR
export GCP_ANALYSIS_MAX_REQUESTS_PER_MINUTE="100"
export GCP_ANALYSIS_DEFAULT_REGION="us-central1"
```

### Configuration File (.env)
```env
GCP_PROJECT_IDS=production-project,staging-project,development-project
GOOGLE_APPLICATION_CREDENTIALS=/path/to/gcp-service-account.json
GCP_ANALYSIS_LOG_LEVEL=INFO
GCP_ANALYSIS_MAX_REQUESTS_PER_MINUTE=100
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Run the test suite (`pytest`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Setup
```bash
# Clone repository
git clone https://github.com/your-org/gcp-resource-analysis.git
cd gcp-resource-analysis

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks (optional)
pre-commit install

# Run tests
pytest
```

### Adding New Analysis Methods

1. **Add analyzer class** in `gcp_storage_analysis.py`:
```python
class GCPNewServiceAnalyzer:
    @staticmethod
    def analyze_new_service(asset_type: str, data: Dict[str, Any]) -> Dict[str, str]:
        # Implementation here
        pass
```

2. **Add data model** in `models/storage_analysis.py`:
```python
class GCPNewServiceResult(BaseModel):
    # Model definition here
    pass
```

3. **Add client method** in `client.py`:
```python
def query_new_service_analysis(self) -> List[GCPNewServiceResult]:
    # Method implementation here
    pass
```

4. **Add tests** in `tests/tests_client.py`:
```python
def test_new_service_analysis(self, gcp_client):
    # Test implementation here
    pass
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Related Tools

- **Cloud Asset Inventory**: The underlying GCP service used for resource discovery
- **Security Command Center**: GCP's security management and data risk platform
- **Cloud Security Scanner**: Automated security scanning for App Engine applications
- **Config Connector**: Kubernetes add-on for managing GCP resources

## 📞 Support

- 📚 [Documentation](https://github.com/your-org/gcp-resource-analysis/docs)
- 🐛 [Issues](https://github.com/your-org/gcp-resource-analysis/issues)
- 💬 [Discussions](https://github.com/your-org/gcp-resource-analysis/discussions)
- 📧 [Email Support](mailto:support@your-org.com)

---

**Built for comprehensive GCP security, compliance, and cost optimization** 🚀
