# GCP Resource Analysis

🔍 **Comprehensive Google Cloud Platform resource analysis for security, compliance, and optimization**

A Python package that provides Azure Resource Graph equivalent functionality for Google Cloud Platform, enabling deep analysis of your GCP resources using Cloud Asset Inventory.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Google Cloud](https://img.shields.io/badge/Google%20Cloud-4285F4?logo=google-cloud&logoColor=white)](https://cloud.google.com/)

## 🎯 Features

### 📊 **Comprehensive Analysis**
- **Storage Analysis**: Cloud Storage, Cloud SQL, BigQuery, Persistent Disks
- **Compute Analysis**: Compute Engine, GKE, Cloud Run, App Engine
- **Network Analysis**: VPC, Firewall Rules, Load Balancers
- **IAM Analysis**: Service Accounts, Roles, Permissions
- **Container Analysis**: GKE clusters, Cloud Run services, Artifact Registry

### 🛡️ **Security & Compliance**
- Encryption method detection (CMEK vs Google-managed)
- Public access configuration analysis
- Network security assessment
- IAM privilege escalation detection
- Compliance scoring with detailed findings

### 💰 **Cost Optimization**
- Unused resource identification
- Right-sizing recommendations  
- Storage class optimization
- Reserved instance opportunities

### 📈 **Reporting & Analytics**
- Application-based compliance summaries
- Risk-based resource prioritization
- CSV/JSON export capabilities
- HTML compliance reports

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
summaries = client.get_storage_compliance_summary()
for summary in summaries:
    print(f"📊 {summary.application}: {summary.compliance_score}% compliance")
```

### Command Line Interface

```bash
# Run storage analysis
gcp-analysis storage --projects your-project-id --export-csv

# Run comprehensive analysis
gcp-analysis comprehensive --projects project1,project2 --output report.html

# Get compliance summary
gcp-analysis compliance --projects your-project-id --format json
```

## 📋 Prerequisites

### 1. Authentication Setup

**Option A: Service Account (Recommended)**
```bash
# Create service account
gcloud iam service-accounts create gcp-resource-analyzer

# Grant permissions
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:gcp-resource-analyzer@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/cloudasset.viewer"

# Create and download key
gcloud iam service-accounts keys create ~/gcp-analyzer-key.json \
    --iam-account=gcp-resource-analyzer@YOUR_PROJECT_ID.iam.gserviceaccount.com
```

**Option B: User Account**
```bash
gcloud auth application-default login
```

### 2. Enable Required APIs

```bash
gcloud services enable cloudasset.googleapis.com
gcloud services enable storage.googleapis.com  
gcloud services enable sqladmin.googleapis.com
gcloud services enable compute.googleapis.com
```

### 3. IAM Permissions

Your service account or user needs these roles:
- `roles/cloudasset.viewer` - View resource inventory
- `roles/storage.objectViewer` - Analyze storage resources
- `roles/cloudsql.viewer` - Analyze Cloud SQL instances
- `roles/compute.viewer` - Analyze compute resources

## 📚 Documentation

### Core Components

#### 🏗️ **GCPResourceAnalysisClient**
Main client class providing all analysis functionality.

```python
client = GCPResourceAnalysisClient(
    project_ids=["project-1", "project-2"],
    credentials_path="/path/to/service-account.json"  # Optional
)
```

#### 📦 **Storage Analysis**
```python
# Security analysis
storage_resources = client.query_storage_analysis()

# Access control analysis  
access_results = client.query_storage_access_control()

# Backup analysis
backup_results = client.query_storage_backup_analysis()

# Cost optimization
optimization_results = client.query_storage_optimization()

# Compliance summary
compliance_summaries = client.get_storage_compliance_summary()
```

#### 💻 **Compute Analysis**
```python
# VM and compute security
compute_resources = client.query_compute_analysis()

# Security configurations
security_results = client.query_compute_security()

# Right-sizing opportunities
optimization_results = client.query_compute_optimization()
```

#### 🌐 **Network Analysis**
```python
# Network security
network_resources = client.query_network_analysis()

# Firewall rule analysis
firewall_results = client.query_firewall_analysis()

# Load balancer security
lb_results = client.query_load_balancer_analysis()
```

### Data Models

#### Storage Resource Model
```python
@dataclass
class GCPStorageResource:
    application: str                 # Application name from labels
    storage_resource: str           # Resource name
    storage_type: str              # Cloud Storage, Cloud SQL, etc.
    encryption_method: str         # CMEK, Google-managed, etc.
    security_findings: str         # Security configuration details
    compliance_risk: str           # Risk level and description
    resource_group: str            # Project ID
    location: str                  # GCP region/zone
    additional_details: str        # Extra configuration info
    resource_id: str              # Full GCP resource identifier
```

#### Compliance Summary Model
```python
@dataclass  
class GCPStorageComplianceSummary:
    application: str                    # Application name
    total_storage_resources: int        # Total resource count
    storage_bucket_count: int          # Cloud Storage buckets
    persistent_disk_count: int         # Persistent disks
    cloud_sql_count: int              # Cloud SQL instances
    bigquery_dataset_count: int       # BigQuery datasets
    encrypted_resources: int           # Encrypted resource count
    secure_transport_resources: int    # HTTPS/TLS enabled
    network_secured_resources: int     # Network restrictions
    resources_with_issues: int         # Resources with problems
    compliance_score: float           # Score 0-100
    compliance_status: str            # Status description
```

## 🔍 Analysis Examples

### Security Analysis
```python
# Find publicly accessible storage
access_results = client.query_storage_access_control()
public_buckets = [r for r in access_results if r.allows_public_access]

# Find unencrypted resources
storage_results = client.query_storage_analysis()
unencrypted = [r for r in storage_results if not r.is_encrypted]

# High-risk configurations
high_risk = [r for r in storage_results if r.is_high_risk]
```

### Cost Optimization
```python
# Find unused resources
optimization_results = client.query_storage_optimization()
unused = [r for r in optimization_results if "unused" in r.utilization_status.lower()]

# High savings potential
high_savings = [r for r in optimization_results if r.has_high_savings_potential]

# Storage class optimization
storage_class_opps = [r for r in optimization_results 
                     if "lifecycle" in r.optimization_recommendation.lower()]
```

### Compliance Reporting
```python
from gcp_resource_analysis.utils import create_compliance_report

# Generate HTML compliance report
summaries = client.get_storage_compliance_summary()
create_compliance_report(summaries, "compliance_report.html")

# Export to CSV
from gcp_resource_analysis.utils import export_to_csv
export_to_csv(storage_results, "storage_analysis.csv")
```

## 🛠️ Advanced Usage

### Multi-Project Analysis
```python
# Analyze across multiple projects
client = GCPResourceAnalysisClient(project_ids=[
    "production-project",
    "staging-project", 
    "development-project"
])

results = client.query_comprehensive_analysis()
```

### Custom Filtering
```python
# Filter by application
app_resources = [r for r in storage_results if r.application == "critical-app"]

# Filter by risk level
critical_issues = [r for r in storage_results 
                  if r.compliance_risk.startswith("High")]

# Filter by location
us_resources = [r for r in storage_results 
               if r.location.startswith("us-")]
```

### Rate Limiting Configuration
```python
# Custom rate limiting
client.rate_limiter.max_requests_per_minute = 50

# Manual rate limit check
if client.rate_limiter.can_make_request():
    results = client.query_storage_analysis()
```

## 📊 Sample Output

### Storage Analysis Results
```
📦 Storage Resources Found: 45
├── 🪣 Cloud Storage Buckets: 23
├── 💾 Persistent Disks: 12  
├── 🗄️ Cloud SQL Instances: 7
└── 📈 BigQuery Datasets: 3

🔍 Security Analysis:
├── ✅ Encrypted Resources: 42/45 (93%)
├── 🔐 CMEK Encrypted: 15/45 (33%)
├── 🌐 Network Secured: 40/45 (89%)
└── ⚠️ High-Risk Issues: 3

💰 Cost Optimization:
├── 💡 High Savings Potential: 5 resources
├── 📊 Unused Resources: 2 disks
└── 🔄 Lifecycle Opportunities: 8 buckets

📈 Compliance Summary:
├── 🟢 Excellent (95-100%): 2 applications
├── 🟡 Good (85-94%): 3 applications  
├── 🟠 Needs Improvement (70-84%): 1 application
└── 🔴 Critical Issues (<70%): 0 applications
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

# Run integration tests
pytest -m integration
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
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Run tests
pytest
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆚 Azure Resource Graph Equivalent

This package provides GCP equivalent functionality to Azure Resource Graph:

| Azure Resource Graph | GCP Resource Analysis |
|---------------------|----------------------|
| Resource Graph Query | Cloud Asset Inventory |
| Azure Storage Account | Cloud Storage Bucket |
| Azure Managed Disk | Persistent Disk |
| Azure SQL Database | Cloud SQL Instance |
| Azure Cosmos DB | BigQuery/Spanner |
| Azure Key Vault | Cloud KMS |
| Azure Resource Groups | GCP Projects |
| KQL Queries | Python-based Analysis |

## 🔗 Related Projects

- [Azure Resource Graph Client](https://github.com/your-org/azure-resource-graph) - The Azure equivalent
- [GCP Security Scanner](https://github.com/your-org/gcp-security-scanner) - Complementary security tooling
- [Multi-Cloud Governance](https://github.com/your-org/multi-cloud-governance) - Cross-cloud compliance

## 📞 Support

- 📚 [Documentation](https://github.com/your-org/gcp-resource-analysis/docs)
- 🐛 [Issues](https://github.com/your-org/gcp-resource-analysis/issues)
- 💬 [Discussions](https://github.com/your-org/gcp-resource-analysis/discussions)
- 📧 [Email Support](mailto:support@your-org.com)

---

**Made with ❤️ for cloud security and governance**
