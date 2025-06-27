#!/usr/bin/env python3
"""
Utility Functions for GCP Resource Analysis

This module provides utility functions for:
- Logging setup and configuration
- Data export (CSV, JSON, HTML)
- Report generation
- Project validation
- Common helper functions

These utilities support the main analysis client and provide
convenient functions for data processing and output formatting.
"""

import csv
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Union


def setup_logging(
        level: Union[str, int] = logging.INFO,
        format_string: Optional[str] = None,
        log_file: Optional[str] = None
) -> logging.Logger:
    """
    Set up logging configuration for GCP Resource Analysis

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_string: Custom log format string
        log_file: Optional file path to write logs to

    Returns:
        Configured logger instance
    """
    if format_string is None:
        format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    # Configure root logger
    logging.basicConfig(
        level=level,
        format=format_string,
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    logger = logging.getLogger('gcp_resource_analysis')

    # Add file handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_formatter = logging.Formatter(format_string)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger


def validate_project_ids(project_ids: List[str]) -> List[str]:
    """
    Validate GCP project IDs format

    Args:
        project_ids: List of project IDs to validate

    Returns:
        List of validated project IDs

    Raises:
        ValueError: If any project ID is invalid
    """
    validated_ids = []

    for project_id in project_ids:
        # Basic validation rules for GCP project IDs
        if not project_id:
            raise ValueError("Project ID cannot be empty")

        if len(project_id) < 6 or len(project_id) > 30:
            raise ValueError(f"Project ID '{project_id}' must be 6-30 characters long")

        if not project_id[0].islower():
            raise ValueError(f"Project ID '{project_id}' must start with a lowercase letter")

        # Check for valid characters (lowercase letters, numbers, hyphens)
        valid_chars = set('abcdefghijklmnopqrstuvwxyz0123456789-')
        if not all(c in valid_chars for c in project_id):
            raise ValueError(f"Project ID '{project_id}' contains invalid characters")

        validated_ids.append(project_id)

    return validated_ids


def export_to_csv(data: List[Any], filename: str, include_timestamp: bool = True) -> str:
    """
    Export analysis results to CSV format

    Args:
        data: List of analysis result objects (with __dict__ method)
        filename: Output filename
        include_timestamp: Whether to include timestamp in filename

    Returns:
        Full path to the created CSV file
    """
    if not data:
        raise ValueError("No data provided for export")

    # Add timestamp to filename if requested
    if include_timestamp:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        name, ext = os.path.splitext(filename)
        filename = f"{name}_{timestamp}{ext}"

    # Convert objects to dictionaries
    rows = []
    for item in data:
        if hasattr(item, '__dict__'):
            rows.append(item.__dict__)
        elif isinstance(item, dict):
            rows.append(item)
        else:
            raise ValueError(f"Cannot convert {type(item)} to CSV row")

    # Write CSV file
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        if rows:
            fieldnames = rows[0].keys()
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    return os.path.abspath(filename)


def export_to_json(data: List[Any], filename: str, include_timestamp: bool = True, indent: int = 2) -> str:
    """
    Export analysis results to JSON format

    Args:
        data: List of analysis result objects
        filename: Output filename
        include_timestamp: Whether to include timestamp in filename
        indent: JSON indentation level

    Returns:
        Full path to the created JSON file
    """
    if not data:
        raise ValueError("No data provided for export")

    # Add timestamp to filename if requested
    if include_timestamp:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        name, ext = os.path.splitext(filename)
        filename = f"{name}_{timestamp}{ext}"

    # Convert objects to dictionaries
    serializable_data = []
    for item in data:
        if hasattr(item, '__dict__'):
            serializable_data.append(item.__dict__)
        elif isinstance(item, dict):
            serializable_data.append(item)
        else:
            # Try to serialize other types
            try:
                serializable_data.append(json.loads(json.dumps(item, default=str)))
            except (TypeError, ValueError):
                raise ValueError(f"Cannot serialize {type(item)} to JSON")

    # Write JSON file
    with open(filename, 'w', encoding='utf-8') as jsonfile:
        json.dump(serializable_data, jsonfile, indent=indent, default=str)

    return os.path.abspath(filename)


def create_compliance_report(
        compliance_summaries: List[Any],
        filename: str,
        include_timestamp: bool = True
) -> str:
    """
    Create an HTML compliance report

    Args:
        compliance_summaries: List of compliance summary objects
        filename: Output filename
        include_timestamp: Whether to include timestamp in filename

    Returns:
        Full path to the created HTML file
    """
    if not compliance_summaries:
        raise ValueError("No compliance data provided for report")

    # Add timestamp to filename if requested
    if include_timestamp:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        name, ext = os.path.splitext(filename)
        filename = f"{name}_{timestamp}{ext}"

    # Generate HTML report
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>GCP Resource Compliance Report</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }}
            h1 {{
                color: #1a73e8;
                border-bottom: 3px solid #1a73e8;
                padding-bottom: 10px;
            }}
            h2 {{
                color: #333;
                margin-top: 30px;
            }}
            .summary-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }}
            .summary-card {{
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 20px;
                background: #fafafa;
            }}
            .app-name {{
                font-size: 1.2em;
                font-weight: bold;
                color: #1a73e8;
                margin-bottom: 10px;
            }}
            .compliance-score {{
                font-size: 2em;
                font-weight: bold;
                margin: 10px 0;
            }}
            .score-excellent {{ color: #34a853; }}
            .score-good {{ color: #fbbc04; }}
            .score-needs-improvement {{ color: #ea4335; }}
            .score-critical {{ color: #d93025; }}
            .metric {{
                display: flex;
                justify-content: space-between;
                margin: 5px 0;
                padding: 5px 0;
                border-bottom: 1px solid #eee;
            }}
            .metric:last-child {{
                border-bottom: none;
            }}
            .timestamp {{
                color: #666;
                font-size: 0.9em;
                text-align: right;
                margin-top: 20px;
            }}
            .status-badge {{
                display: inline-block;
                padding: 4px 8px;
                border-radius: 4px;
                color: white;
                font-size: 0.8em;
                font-weight: bold;
            }}
            .status-excellent {{ background-color: #34a853; }}
            .status-good {{ background-color: #fbbc04; }}
            .status-acceptable {{ background-color: #ff9800; }}
            .status-needs-improvement {{ background-color: #ea4335; }}
            .status-critical {{ background-color: #d93025; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔍 GCP Resource Compliance Report</h1>

            <h2>📊 Application Compliance Summary</h2>
            <div class="summary-grid">
    """

    # Add compliance cards for each application
    for summary in compliance_summaries:
        # Determine score color class
        score = getattr(summary, 'compliance_score', 0)
        if score >= 95:
            score_class = 'score-excellent'
            status_class = 'status-excellent'
        elif score >= 85:
            score_class = 'score-good'
            status_class = 'status-good'
        elif score >= 70:
            score_class = 'score-acceptable'
            status_class = 'status-acceptable'
        elif score >= 50:
            score_class = 'score-needs-improvement'
            status_class = 'status-needs-improvement'
        else:
            score_class = 'score-critical'
            status_class = 'status-critical'

        html_content += f"""
                <div class="summary-card">
                    <div class="app-name">{getattr(summary, 'application', 'Unknown')}</div>
                    <div class="compliance-score {score_class}">{score:.1f}%</div>
                    <span class="status-badge {status_class}">{getattr(summary, 'compliance_status', 'Unknown')}</span>

                    <div class="metric">
                        <span>📦 Total Resources:</span>
                        <span>{getattr(summary, 'total_storage_resources', 0)}</span>
                    </div>
                    <div class="metric">
                        <span>🪣 Cloud Storage:</span>
                        <span>{getattr(summary, 'storage_bucket_count', 0)}</span>
                    </div>
                    <div class="metric">
                        <span>💾 Persistent Disks:</span>
                        <span>{getattr(summary, 'persistent_disk_count', 0)}</span>
                    </div>
                    <div class="metric">
                        <span>🗄️ Cloud SQL:</span>
                        <span>{getattr(summary, 'cloud_sql_count', 0)}</span>
                    </div>
                    <div class="metric">
                        <span>🔐 Encrypted:</span>
                        <span>{getattr(summary, 'encrypted_resources', 0)}</span>
                    </div>
                    <div class="metric">
                        <span>⚠️ Issues:</span>
                        <span>{getattr(summary, 'resources_with_issues', 0)}</span>
                    </div>
                </div>
        """

    html_content += f"""
            </div>

            <div class="timestamp">
                📅 Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </div>
        </div>
    </body>
    </html>
    """

    # Write HTML file
    with open(filename, 'w', encoding='utf-8') as htmlfile:
        htmlfile.write(html_content)

    return os.path.abspath(filename)


def format_resource_summary(resources: List[Any]) -> Dict[str, Any]:
    """
    Create a formatted summary of resource analysis results

    Args:
        resources: List of resource analysis objects

    Returns:
        Dictionary with summary statistics
    """
    if not resources:
        return {
            'total_resources': 0,
            'high_risk_resources': 0,
            'by_type': {},
            'by_application': {},
            'by_risk_level': {}
        }

    summary = {
        'total_resources': len(resources),
        'high_risk_resources': 0,
        'by_type': {},
        'by_application': {},
        'by_risk_level': {}
    }

    for resource in resources:
        # Count high-risk resources
        if hasattr(resource, 'is_high_risk') and resource.is_high_risk:
            summary['high_risk_resources'] += 1

        # Count by type
        resource_type = getattr(resource, 'storage_type', getattr(resource, 'resource_type', 'Unknown'))
        summary['by_type'][resource_type] = summary['by_type'].get(resource_type, 0) + 1

        # Count by application
        application = getattr(resource, 'application', 'Unknown')
        summary['by_application'][application] = summary['by_application'].get(application, 0) + 1

        # Count by risk level
        risk = getattr(resource, 'compliance_risk', getattr(resource, 'security_risk', 'Unknown'))
        risk_level = risk.split(' - ')[0] if ' - ' in risk else risk
        summary['by_risk_level'][risk_level] = summary['by_risk_level'].get(risk_level, 0) + 1

    return summary


def create_project_structure(base_path: str = "gcp_resource_analysis") -> None:
    """
    Create the complete project directory structure

    Args:
        base_path: Base directory path for the project
    """
    directories = [
        base_path,
        f"{base_path}/gcp_resource_analysis",
        f"{base_path}/tests",
        f"{base_path}/examples",
        f"{base_path}/docs",
        f"{base_path}/scripts",
        f"{base_path}/gcp_samples",
        f"{base_path}/.github/workflows"
    ]

    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✅ Created directory: {directory}")

    # Create __init__.py files
    init_files = [
        f"{base_path}/gcp_resource_analysis/__init__.py",
        f"{base_path}/tests/__init__.py",
        f"{base_path}/gcp_samples/__init__.py"
    ]

    for init_file in init_files:
        Path(init_file).touch()
        print(f"✅ Created file: {init_file}")

    print(f"\n🎉 Project structure created successfully in {base_path}/")


def load_config_from_env() -> Dict[str, Any]:
    """
    Load configuration from environment variables

    Returns:
        Dictionary with configuration values
    """
    config = {
        'project_ids': [],
        'credentials_path': None,
        'log_level': 'INFO',
        'max_requests_per_minute': 100
    }

    # Load project IDs
    project_ids_str = os.getenv('GCP_PROJECT_IDS', '')
    if project_ids_str:
        config['project_ids'] = [p.strip() for p in project_ids_str.split(',') if p.strip()]

    # Load credentials path
    config['credentials_path'] = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')

    # Load log level
    config['log_level'] = os.getenv('GCP_ANALYSIS_LOG_LEVEL', 'INFO').upper()

    # Load rate limiting
    max_requests = os.getenv('GCP_ANALYSIS_MAX_REQUESTS_PER_MINUTE')
    if max_requests:
        try:
            config['max_requests_per_minute'] = int(max_requests)
        except ValueError:
            pass

    return config


def print_analysis_summary(results: Dict[str, Any]) -> None:
    """
    Print a formatted summary of analysis results

    Args:
        results: Analysis results dictionary
    """
    print("\n" + "=" * 80)
    print("📊 GCP RESOURCE ANALYSIS SUMMARY")
    print("=" * 80)

    # Storage analysis summary
    if 'storage_security' in results:
        storage_summary = format_resource_summary(results['storage_security'])
        print(f"\n🗄️ Storage Resources:")
        print(f"   📦 Total: {storage_summary['total_resources']}")
        print(f"   ⚠️  High Risk: {storage_summary['high_risk_resources']}")

        if storage_summary['by_type']:
            print("   📋 By Type:")
            for resource_type, count in storage_summary['by_type'].items():
                print(f"      • {resource_type}: {count}")

    # Compliance summary
    if 'compliance_summary' in results:
        print(f"\n📈 Compliance Summary:")
        for summary in results['compliance_summary']:
            app_name = getattr(summary, 'application', 'Unknown')
            score = getattr(summary, 'compliance_score', 0)
            status = getattr(summary, 'compliance_status', 'Unknown')

            # Choose emoji based on score
            if score >= 90:
                emoji = "🟢"
            elif score >= 75:
                emoji = "🟡"
            else:
                emoji = "🔴"

            print(f"   {emoji} {app_name}: {score:.1f}% ({status})")

    # Optimization opportunities
    if 'optimization' in results:
        high_savings = len([r for r in results['optimization']
                            if hasattr(r, 'has_high_savings_potential') and r.has_high_savings_potential])
        print(f"\n💰 Cost Optimization:")
        print(f"   💡 High savings opportunities: {high_savings}")

    print("\n" + "=" * 80)


# Export commonly used functions
__all__ = [
    'setup_logging',
    'validate_project_ids',
    'export_to_csv',
    'export_to_json',
    'create_compliance_report',
    'format_resource_summary',
    'create_project_structure',
    'load_config_from_env',
    'print_analysis_summary'
]
