#!/usr/bin/env python3
"""
GCP Network/VPC Analysis Queries and Analyzers

Provides comprehensive analysis of Google Cloud Platform network and VPC resources
equivalent to Azure's Network Security Group and network analysis capabilities.

This module includes:
- VPC network security configuration analysis
- Firewall rules detailed analysis and risk assessment
- SSL/TLS certificate analysis for load balancers
- Network topology and connectivity analysis
- Network resource optimization recommendations
- Network compliance scoring and reporting

GCP Network Asset Types Covered:
- compute.googleapis.com/Network (VPC Networks)
- compute.googleapis.com/Firewall (Firewall Rules)
- compute.googleapis.com/SslCertificate (SSL Certificates)
- compute.googleapis.com/HttpsHealthCheck (Health Checks)
- compute.googleapis.com/UrlMap (Load Balancer URL Maps)
- compute.googleapis.com/BackendService (Backend Services)
- compute.googleapis.com/TargetHttpsProxy (HTTPS Proxies)
- compute.googleapis.com/GlobalForwardingRule (Global Forwarding Rules)
- compute.googleapis.com/Router (Cloud Router)
- compute.googleapis.com/VpnTunnel (VPN Tunnels)
- compute.googleapis.com/InterconnectAttachment (Interconnect)

Example Usage:
    # Get VPC network asset types for analysis
    asset_types = GCPNetworkAnalysisQueries.get_vpc_network_security_asset_types()

    # Analyze firewall rule security
    rule_analysis = GCPFirewallRuleAnalyzer.analyze_firewall_rule_security(
        asset_type, firewall_data
    )

    # Analyze SSL certificate configuration
    cert_analysis = GCPSSLCertificateAnalyzer.analyze_ssl_certificate_security(
        asset_type, certificate_data
    )
"""

import logging
from datetime import datetime
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class GCPNetworkAnalysisQueries:
    """
    GCP Network Analysis Asset Type Queries

    Defines the GCP asset types for comprehensive network security analysis
    equivalent to Azure's network resource types.
    """

    @staticmethod
    def get_vpc_network_security_asset_types() -> List[str]:
        """
        Get asset types for VPC network security analysis

        Returns:
            List of GCP asset types for VPC network analysis
        """
        return [
            "compute.googleapis.com/Network",
            "compute.googleapis.com/Subnetwork",
            "compute.googleapis.com/Router",
            "compute.googleapis.com/VpnTunnel",
            "compute.googleapis.com/InterconnectAttachment"
        ]

    @staticmethod
    def get_firewall_rules_analysis_asset_types() -> List[str]:
        """
        Get asset types for firewall rules analysis

        Returns:
            List of GCP asset types for firewall rules analysis
        """
        return [
            "compute.googleapis.com/Firewall"
        ]

    @staticmethod
    def get_ssl_certificate_analysis_asset_types() -> List[str]:
        """
        Get asset types for SSL certificate analysis

        Returns:
            List of GCP asset types for SSL/TLS certificate analysis
        """
        return [
            "compute.googleapis.com/SslCertificate",
            "compute.googleapis.com/ManagedSslCertificate",
            "compute.googleapis.com/TargetHttpsProxy",
            "compute.googleapis.com/UrlMap"
        ]

    @staticmethod
    def get_network_topology_asset_types() -> List[str]:
        """
        Get asset types for network topology analysis

        Returns:
            List of GCP asset types for network topology analysis
        """
        return [
            "compute.googleapis.com/Network",
            "compute.googleapis.com/Subnetwork",
            "compute.googleapis.com/Route",
            "compute.googleapis.com/Router",
            "compute.googleapis.com/VpnGateway",
            "compute.googleapis.com/VpnTunnel",
            "compute.googleapis.com/InterconnectAttachment",
            "compute.googleapis.com/GlobalForwardingRule",
            "compute.googleapis.com/ForwardingRule"
        ]

    @staticmethod
    def get_network_optimization_asset_types() -> List[str]:
        """
        Get asset types for network resource optimization analysis

        Returns:
            List of GCP asset types for network optimization analysis
        """
        return [
            "compute.googleapis.com/Address",
            "compute.googleapis.com/GlobalAddress",
            "compute.googleapis.com/BackendService",
            "compute.googleapis.com/HealthCheck",
            "compute.googleapis.com/HttpsHealthCheck",
            "compute.googleapis.com/GlobalForwardingRule",
            "compute.googleapis.com/ForwardingRule"
        ]

    @staticmethod
    def get_comprehensive_network_asset_types() -> List[str]:
        """
        Get all asset types for comprehensive network analysis

        Returns:
            List of all GCP network asset types
        """
        asset_types = set()
        asset_types.update(GCPNetworkAnalysisQueries.get_vpc_network_security_asset_types())
        asset_types.update(GCPNetworkAnalysisQueries.get_firewall_rules_analysis_asset_types())
        asset_types.update(GCPNetworkAnalysisQueries.get_ssl_certificate_analysis_asset_types())
        asset_types.update(GCPNetworkAnalysisQueries.get_network_topology_asset_types())
        asset_types.update(GCPNetworkAnalysisQueries.get_network_optimization_asset_types())
        return list(asset_types)


class GCPNetworkSecurityAnalyzer:
    """
    GCP VPC Network Security Configuration Analyzer

    Analyzes VPC network security configurations including:
    - VPC network configuration and security
    - Subnetwork security and isolation
    - Private Google Access configuration
    - Flow logs configuration
    - Network peering security
    """

    @staticmethod
    def analyze_vpc_network_security_comprehensive(asset_type: str, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Comprehensive VPC network security analysis

        Args:
            asset_type: GCP asset type
            data: Asset data dictionary

        Returns:
            Dictionary containing comprehensive network security analysis
        """
        try:
            if data is None:
                return GCPNetworkSecurityAnalyzer._get_default_analysis_result()

            if 'compute.googleapis.com/Network' in asset_type:
                return GCPNetworkSecurityAnalyzer._analyze_vpc_network(data)
            elif 'compute.googleapis.com/Subnetwork' in asset_type:
                return GCPNetworkSecurityAnalyzer._analyze_subnetwork(data)
            elif 'compute.googleapis.com/Router' in asset_type:
                return GCPNetworkSecurityAnalyzer._analyze_cloud_router(data)
            elif 'compute.googleapis.com/VpnTunnel' in asset_type:
                return GCPNetworkSecurityAnalyzer._analyze_vpn_tunnel(data)
            else:
                return GCPNetworkSecurityAnalyzer._get_default_analysis_result()

        except Exception as e:
            logger.warning(f"Failed to analyze network security for {asset_type}: {e}")
            return GCPNetworkSecurityAnalyzer._get_default_analysis_result()

    @staticmethod
    def _analyze_vpc_network(data: Dict[str, Any]) -> Dict[str, str]:
        """Analyze VPC network configuration"""
        auto_create_subnetworks = data.get('autoCreateSubnetworks', True)
        routing_config = data.get('routingConfig', {})
        peerings = data.get('peerings', [])

        # Network configuration analysis
        if auto_create_subnetworks:
            network_configuration = "Legacy Network - Auto-create subnetworks enabled"
            security_risk = "Medium - Legacy network mode with automatic subnets"
        else:
            network_configuration = "Custom Network - Manual subnet management"
            security_risk = "Low - Custom network with controlled subnets"

        # Security findings
        findings = []
        if auto_create_subnetworks:
            findings.append("Legacy network mode detected")

        routing_mode = routing_config.get('routingMode', 'REGIONAL')
        if routing_mode == 'GLOBAL':
            findings.append("Global routing enabled")

        if peerings:
            findings.append(f"{len(peerings)} network peering connections")

        security_findings = "; ".join(findings) if findings else "Standard network configuration"

        # Compliance status
        if auto_create_subnetworks:
            compliance_status = "Needs Improvement - Consider custom network mode"
        else:
            compliance_status = "Compliant - Custom network configuration"

        # Network details
        network_details = f"Routing Mode: {routing_mode}"
        if peerings:
            network_details += f" | Peerings: {len(peerings)}"
        if auto_create_subnetworks:
            network_details += " | Legacy Mode"

        return {
            'network_configuration': network_configuration,
            'security_findings': security_findings,
            'security_risk': security_risk,
            'compliance_status': compliance_status,
            'network_details': network_details
        }

    @staticmethod
    def _analyze_subnetwork(data: Dict[str, Any]) -> Dict[str, str]:
        """Analyze subnetwork configuration"""
        private_ip_google_access = data.get('privateIpGoogleAccess', False)
        enable_flow_logs = data.get('enableFlowLogs', False)
        purpose = data.get('purpose', 'PRIVATE')
        secondary_ip_ranges = data.get('secondaryIpRanges', [])

        # Configuration analysis
        config_features = []
        if private_ip_google_access:
            config_features.append("Private Google Access")
        if enable_flow_logs:
            config_features.append("Flow Logs Enabled")
        if secondary_ip_ranges:
            config_features.append(f"{len(secondary_ip_ranges)} Secondary Ranges")

        network_configuration = f"Purpose: {purpose}"
        if config_features:
            network_configuration += f" | Features: {', '.join(config_features)}"

        # Security findings
        findings = []
        if not enable_flow_logs:
            findings.append("Flow logs disabled - limited visibility")
        if private_ip_google_access:
            findings.append("Private Google Access enabled")
        if secondary_ip_ranges:
            findings.append("Secondary IP ranges configured")

        security_findings = "; ".join(findings) if findings else "Basic subnetwork configuration"

        # Risk assessment
        risk_factors = 0
        if not enable_flow_logs:
            risk_factors += 1

        if risk_factors == 0:
            security_risk = "Low - Well configured subnetwork"
            compliance_status = "Compliant"
        elif risk_factors == 1:
            security_risk = "Medium - Consider enabling flow logs"
            compliance_status = "Partially Compliant"
        else:
            security_risk = "High - Multiple configuration issues"
            compliance_status = "Non-Compliant"

        network_details = f"IP Range: {data.get('ipCidrRange', 'Unknown')}"
        if private_ip_google_access:
            network_details += " | Private Google Access"

        return {
            'network_configuration': network_configuration,
            'security_findings': security_findings,
            'security_risk': security_risk,
            'compliance_status': compliance_status,
            'network_details': network_details
        }

    @staticmethod
    def _analyze_cloud_router(data: Dict[str, Any]) -> Dict[str, str]:
        """Analyze Cloud Router configuration"""
        bgp = data.get('bgp', {})
        nats = data.get('nats', [])
        interfaces = data.get('interfaces', [])

        # Configuration analysis
        asn = bgp.get('asn', 'Unknown')
        advertise_mode = bgp.get('advertiseMode', 'DEFAULT')

        network_configuration = f"BGP ASN: {asn} | Advertise Mode: {advertise_mode}"

        # Security findings
        findings = []
        if nats:
            findings.append(f"{len(nats)} NAT configurations")
        if interfaces:
            findings.append(f"{len(interfaces)} BGP interfaces")
        if advertise_mode == 'CUSTOM':
            findings.append("Custom route advertisement")

        security_findings = "; ".join(findings) if findings else "Standard router configuration"

        # Risk assessment - routers are generally low risk
        security_risk = "Low - Standard Cloud Router configuration"
        compliance_status = "Compliant"

        network_details = f"NATs: {len(nats)} | Interfaces: {len(interfaces)}"

        return {
            'network_configuration': network_configuration,
            'security_findings': security_findings,
            'security_risk': security_risk,
            'compliance_status': compliance_status,
            'network_details': network_details
        }

    @staticmethod
    def _analyze_vpn_tunnel(data: Dict[str, Any]) -> Dict[str, str]:
        """Analyze VPN tunnel configuration"""
        status = data.get('status', 'UNKNOWN')
        ike_version = data.get('ikeVersion', 1)
        local_traffic_selector = data.get('localTrafficSelector', [])
        remote_traffic_selector = data.get('remoteTrafficSelector', [])

        # Configuration analysis
        network_configuration = f"IKE Version: {ike_version} | Status: {status}"

        # Security findings
        findings = []
        if ike_version == 1:
            findings.append("Using IKEv1 - consider upgrading to IKEv2")
        if status != 'ESTABLISHED':
            findings.append(f"Tunnel status: {status}")
        if local_traffic_selector:
            findings.append(f"Local selectors: {len(local_traffic_selector)}")

        security_findings = "; ".join(findings) if findings else "Standard VPN configuration"

        # Risk assessment
        if ike_version == 1:
            security_risk = "Medium - IKEv1 is less secure than IKEv2"
            compliance_status = "Needs Improvement"
        elif status != 'ESTABLISHED':
            security_risk = "High - VPN tunnel not established"
            compliance_status = "Non-Compliant"
        else:
            security_risk = "Low - Secure VPN configuration"
            compliance_status = "Compliant"

        network_details = f"IKE: v{ike_version} | Status: {status}"
        if local_traffic_selector:
            network_details += f" | Selectors: {len(local_traffic_selector)}"

        return {
            'network_configuration': network_configuration,
            'security_findings': security_findings,
            'security_risk': security_risk,
            'compliance_status': compliance_status,
            'network_details': network_details
        }

    @staticmethod
    def _get_default_analysis_result() -> Dict[str, str]:
        """Get default analysis result for unknown asset types"""
        return {
            'network_configuration': 'Unknown network resource type',
            'security_findings': 'Manual review required',
            'security_risk': 'Manual review needed',
            'compliance_status': 'Manual Review Required',
            'network_details': 'Resource type not analyzed'
        }


class GCPFirewallRuleAnalyzer:
    """
    GCP Firewall Rules Security Analyzer

    Analyzes firewall rules for security risks including:
    - Overly permissive rules (0.0.0.0/0 source)
    - High-risk port combinations
    - Direction and action analysis
    - Priority and rule ordering risks
    """

    # High-risk ports that should be carefully controlled
    HIGH_RISK_PORTS = {
        '22': 'SSH',
        '3389': 'RDP',
        '21': 'FTP',
        '23': 'Telnet',
        '135': 'RPC',
        '139': 'NetBIOS',
        '445': 'SMB',
        '1433': 'SQL Server',
        '3306': 'MySQL',
        '5432': 'PostgreSQL',
        '6379': 'Redis',
        '27017': 'MongoDB'
    }

    @staticmethod
    def analyze_firewall_rule_security(asset_type: str, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Analyze firewall rule security configuration

        Args:
            asset_type: GCP asset type
            data: Firewall rule data

        Returns:
            Dictionary containing firewall rule security analysis
        """
        try:
            if data is None or 'compute.googleapis.com/Firewall' not in asset_type:
                return GCPFirewallRuleAnalyzer._get_default_firewall_analysis()

            direction = data.get('direction', 'INGRESS')
            action = 'ALLOW' if data.get('allowed') else 'DENY'
            priority = data.get('priority', 1000)
            source_ranges = data.get('sourceRanges', [])
            target_tags = data.get('targetTags', [])
            source_tags = data.get('sourceTags', [])
            allowed_rules = data.get('allowed', [])
            denied_rules = data.get('denied', [])

            # Analyze rule configuration
            rule_config = GCPFirewallRuleAnalyzer._analyze_rule_configuration(
                direction, action, priority, source_ranges, target_tags, allowed_rules, denied_rules
            )

            # Analyze security risk
            risk_analysis = GCPFirewallRuleAnalyzer._analyze_security_risk(
                direction, action, source_ranges, allowed_rules, denied_rules
            )

            # Determine compliance status
            compliance_status = GCPFirewallRuleAnalyzer._determine_compliance_status(risk_analysis['risk_level'])

            return {
                'rule_configuration': rule_config['configuration'],
                'security_findings': rule_config['findings'],
                'security_risk': risk_analysis['risk_description'],
                'compliance_status': compliance_status,
                'rule_details': rule_config['details']
            }

        except Exception as e:
            logger.warning(f"Failed to analyze firewall rule: {e}")
            return GCPFirewallRuleAnalyzer._get_default_firewall_analysis()

    @staticmethod
    def _analyze_rule_configuration(direction: str, action: str, priority: int,
                                    source_ranges: List[str], target_tags: List[str],
                                    allowed_rules: List[Dict], denied_rules: List[Dict]) -> Dict[str, str]:
        """Analyze firewall rule configuration"""

        # Basic configuration
        config_parts = [f"{direction} {action}", f"Priority: {priority}"]

        # Source analysis
        if source_ranges:
            if '0.0.0.0/0' in source_ranges:
                config_parts.append("Source: Any (0.0.0.0/0)")
            else:
                config_parts.append(f"Source: {len(source_ranges)} ranges")

        # Target analysis
        if target_tags:
            config_parts.append(f"Targets: {len(target_tags)} tags")
        else:
            config_parts.append("Targets: All instances")

        configuration = " | ".join(config_parts)

        # Findings analysis
        findings = []

        # Check for high-risk configurations
        if '0.0.0.0/0' in source_ranges and action == 'ALLOW':
            findings.append("Allows traffic from any source (0.0.0.0/0)")

        if not target_tags and action == 'ALLOW':
            findings.append("No target tags - applies to all instances")

        if priority < 100:
            findings.append("Very high priority rule")

        # Analyze allowed ports
        if allowed_rules:
            for rule in allowed_rules:
                protocol = rule.get('IPProtocol', 'unknown')
                ports = rule.get('ports', [])

                if not ports:  # All ports
                    findings.append(f"Allows all {protocol} ports")
                else:
                    for port_range in ports:
                        if '-' in str(port_range):  # Port range
                            findings.append(f"Port range: {port_range}")
                        elif str(port_range) in GCPFirewallRuleAnalyzer.HIGH_RISK_PORTS:
                            service = GCPFirewallRuleAnalyzer.HIGH_RISK_PORTS[str(port_range)]
                            findings.append(f"High-risk port: {port_range} ({service})")

        security_findings = "; ".join(findings) if findings else "Standard firewall rule"

        # Details
        details_parts = [f"Direction: {direction}", f"Action: {action}", f"Priority: {priority}"]
        if source_ranges:
            details_parts.append(f"Sources: {len(source_ranges)}")
        if target_tags:
            details_parts.append(f"Targets: {len(target_tags)}")

        details = " | ".join(details_parts)

        return {
            'configuration': configuration,
            'findings': security_findings,
            'details': details
        }

    @staticmethod
    def _analyze_security_risk(direction: str, action: str, source_ranges: List[str],
                               allowed_rules: List[Dict], denied_rules: List[Dict]) -> Dict[str, Any]:
        """Analyze security risk level"""

        risk_factors = 0
        risk_details = []

        # High risk: Allow from anywhere
        if action == 'ALLOW' and '0.0.0.0/0' in source_ranges:
            risk_factors += 3
            risk_details.append("allows traffic from any source")

        # Medium risk: Allow with broad port ranges
        if action == 'ALLOW' and allowed_rules:
            for rule in allowed_rules:
                ports = rule.get('ports', [])
                if not ports:  # All ports
                    risk_factors += 2
                    risk_details.append("allows all ports")
                else:
                    for port_range in ports:
                        if str(port_range) in GCPFirewallRuleAnalyzer.HIGH_RISK_PORTS:
                            risk_factors += 1
                            service = GCPFirewallRuleAnalyzer.HIGH_RISK_PORTS[str(port_range)]
                            risk_details.append(f"exposes {service} port")

        # Determine risk level and description
        if risk_factors >= 4:
            risk_level = 'HIGH'
            risk_description = f"High - {', '.join(risk_details[:2])}"  # Limit description length
        elif risk_factors >= 2:
            risk_level = 'MEDIUM'
            risk_description = f"Medium - {', '.join(risk_details[:2])}"
        elif risk_factors >= 1:
            risk_level = 'LOW'
            risk_description = f"Low - {risk_details[0] if risk_details else 'minor security concern'}"
        else:
            risk_level = 'LOW'
            risk_description = "Low - Standard firewall rule"

        return {
            'risk_level': risk_level,
            'risk_description': risk_description,
            'risk_factors': risk_factors
        }

    @staticmethod
    def _determine_compliance_status(risk_level: str) -> str:
        """Determine compliance status based on risk level"""
        if risk_level == 'HIGH':
            return "Non-Compliant - High risk configuration"
        elif risk_level == 'MEDIUM':
            return "Needs Improvement - Medium risk detected"
        else:
            return "Compliant"

    @staticmethod
    def _get_default_firewall_analysis() -> Dict[str, str]:
        """Get default firewall analysis result"""
        return {
            'rule_configuration': 'Unknown firewall rule type',
            'security_findings': 'Manual review required',
            'security_risk': 'Manual review needed',
            'compliance_status': 'Manual Review Required',
            'rule_details': 'Rule analysis failed'
        }


class GCPSSLCertificateAnalyzer:
    """
    GCP SSL/TLS Certificate Security Analyzer

    Analyzes SSL certificates and related load balancer configurations for:
    - Certificate expiration dates
    - Certificate types (managed vs self-managed)
    - TLS/SSL policy configurations
    - Load balancer security configurations
    """

    @staticmethod
    def analyze_ssl_certificate_security(asset_type: str, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Analyze SSL certificate security configuration

        Args:
            asset_type: GCP asset type
            data: Certificate/proxy data

        Returns:
            Dictionary containing SSL certificate security analysis
        """
        try:
            if data is None:
                return GCPSSLCertificateAnalyzer._get_default_certificate_analysis()

            if 'SslCertificate' in asset_type:
                return GCPSSLCertificateAnalyzer._analyze_ssl_certificate(data)
            elif 'TargetHttpsProxy' in asset_type:
                return GCPSSLCertificateAnalyzer._analyze_https_proxy(data)
            elif 'UrlMap' in asset_type:
                return GCPSSLCertificateAnalyzer._analyze_url_map(data)
            else:
                return GCPSSLCertificateAnalyzer._get_default_certificate_analysis()

        except Exception as e:
            logger.warning(f"Failed to analyze SSL certificate for {asset_type}: {e}")
            return GCPSSLCertificateAnalyzer._get_default_certificate_analysis()

    @staticmethod
    def _analyze_ssl_certificate(data: Dict[str, Any]) -> Dict[str, str]:
        """Analyze SSL certificate configuration"""
        cert_type = data.get('type', 'SELF_MANAGED')
        managed = data.get('managed', {})
        expire_time = data.get('expireTime')
        subject_alternative_names = data.get('subjectAlternativeNames', [])

        # Certificate configuration
        if cert_type == 'MANAGED':
            cert_configuration = "Google-managed SSL certificate"
            security_risk = "Low - Google-managed certificate with auto-renewal"
            compliance_status = "Compliant"
        else:
            cert_configuration = "Self-managed SSL certificate"

            # Check expiration for self-managed certificates
            if expire_time:
                try:
                    expire_date = datetime.fromisoformat(expire_time.replace('Z', '+00:00'))
                    days_until_expiry = (expire_date - datetime.now().replace(tzinfo=expire_date.tzinfo)).days

                    if days_until_expiry < 30:
                        security_risk = "High - Certificate expires within 30 days"
                        compliance_status = "Critical - Certificate renewal required"
                    elif days_until_expiry < 90:
                        security_risk = "Medium - Certificate expires within 90 days"
                        compliance_status = "Needs Attention"
                    else:
                        security_risk = "Low - Certificate valid for >90 days"
                        compliance_status = "Compliant"
                except Exception:
                    security_risk = "Medium - Unable to verify expiration"
                    compliance_status = "Manual Review Required"
            else:
                security_risk = "Medium - No expiration information available"
                compliance_status = "Manual Review Required"

        # Security findings
        findings = []
        if cert_type == 'MANAGED':
            findings.append("Google-managed certificate with automatic renewal")
        if subject_alternative_names:
            findings.append(f"Covers {len(subject_alternative_names)} domains")
        if managed:
            status = managed.get('status', 'Unknown')
            findings.append(f"Management status: {status}")

        security_findings = "; ".join(findings) if findings else "Standard certificate configuration"

        # Certificate details
        cert_details = f"Type: {cert_type}"
        if expire_time:
            cert_details += f" | Expires: {expire_time[:10]}"
        if subject_alternative_names:
            cert_details += f" | Domains: {len(subject_alternative_names)}"

        return {
            'certificate_configuration': cert_configuration,
            'security_findings': security_findings,
            'security_risk': security_risk,
            'compliance_status': compliance_status,
            'certificate_details': cert_details
        }

    @staticmethod
    def _analyze_https_proxy(data: Dict[str, Any]) -> Dict[str, str]:
        """Analyze HTTPS proxy configuration"""
        ssl_certificates = data.get('sslCertificates', [])
        ssl_policy = data.get('sslPolicy')
        url_map = data.get('urlMap', '')

        # Proxy configuration
        cert_count = len(ssl_certificates)
        cert_configuration = f"HTTPS Proxy with {cert_count} SSL certificate(s)"

        # Security findings
        findings = []
        if ssl_policy:
            findings.append("Custom SSL policy configured")
        else:
            findings.append("Using default SSL policy")

        if cert_count == 0:
            findings.append("No SSL certificates configured")
        elif cert_count > 1:
            findings.append("Multiple SSL certificates")

        security_findings = "; ".join(findings) if findings else "Standard HTTPS proxy"

        # Risk assessment
        if cert_count == 0:
            security_risk = "High - No SSL certificates configured"
            compliance_status = "Non-Compliant"
        elif not ssl_policy:
            security_risk = "Medium - Using default SSL policy"
            compliance_status = "Needs Improvement"
        else:
            security_risk = "Low - Properly configured HTTPS proxy"
            compliance_status = "Compliant"

        proxy_details = f"Certificates: {cert_count}"
        if ssl_policy:
            proxy_details += " | Custom SSL Policy"
        if url_map:
            proxy_details += " | URL Map Configured"

        return {
            'certificate_configuration': cert_configuration,
            'security_findings': security_findings,
            'security_risk': security_risk,
            'compliance_status': compliance_status,
            'certificate_details': proxy_details
        }

    @staticmethod
    def _analyze_url_map(data: Dict[str, Any]) -> Dict[str, str]:
        """Analyze URL map configuration"""
        default_service = data.get('defaultService', '')
        host_rules = data.get('hostRules', [])
        path_matchers = data.get('pathMatchers', [])

        # URL map configuration
        cert_configuration = f"Load Balancer URL Map with {len(host_rules)} host rules"

        # Security findings
        findings = []
        if host_rules:
            findings.append(f"{len(host_rules)} host-based routing rules")
        if path_matchers:
            findings.append(f"{len(path_matchers)} path matchers")
        if default_service:
            findings.append("Default backend service configured")

        security_findings = "; ".join(findings) if findings else "Basic URL map configuration"

        # Risk assessment (URL maps are generally low risk)
        security_risk = "Low - Standard load balancer configuration"
        compliance_status = "Compliant"

        url_map_details = f"Host Rules: {len(host_rules)} | Path Matchers: {len(path_matchers)}"

        return {
            'certificate_configuration': cert_configuration,
            'security_findings': security_findings,
            'security_risk': security_risk,
            'compliance_status': compliance_status,
            'certificate_details': url_map_details
        }

    @staticmethod
    def _get_default_certificate_analysis() -> Dict[str, str]:
        """Get default certificate analysis result"""
        return {
            'certificate_configuration': 'Unknown certificate resource type',
            'security_findings': 'Manual review required',
            'security_risk': 'Manual review needed',
            'compliance_status': 'Manual Review Required',
            'certificate_details': 'Certificate analysis failed'
        }


class GCPNetworkTopologyAnalyzer:
    """
    GCP Network Topology and Connectivity Analyzer

    Analyzes network topology and connectivity patterns for:
    - VPC peering configurations
    - VPN connectivity security
    - Interconnect security
    - Load balancer topology
    - Network segmentation analysis
    """

    @staticmethod
    def analyze_network_topology(asset_type: str, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Analyze network topology configuration

        Args:
            asset_type: GCP asset type
            data: Network resource data

        Returns:
            Dictionary containing network topology analysis
        """
        try:
            if data is None:
                return GCPNetworkTopologyAnalyzer._get_default_topology_analysis()

            if 'compute.googleapis.com/Network' in asset_type:
                return GCPNetworkTopologyAnalyzer._analyze_vpc_topology(data)
            elif 'compute.googleapis.com/Route' in asset_type:
                return GCPNetworkTopologyAnalyzer._analyze_route_topology(data)
            elif 'compute.googleapis.com/GlobalForwardingRule' in asset_type:
                return GCPNetworkTopologyAnalyzer._analyze_load_balancer_topology(data)
            elif 'VpnGateway' in asset_type or 'VpnTunnel' in asset_type:
                return GCPNetworkTopologyAnalyzer._analyze_vpn_topology(data)
            else:
                return GCPNetworkTopologyAnalyzer._get_default_topology_analysis()

        except Exception as e:
            logger.warning(f"Failed to analyze network topology for {asset_type}: {e}")
            return GCPNetworkTopologyAnalyzer._get_default_topology_analysis()

    @staticmethod
    def _analyze_vpc_topology(data: Dict[str, Any]) -> Dict[str, str]:
        """Analyze VPC network topology"""
        peerings = data.get('peerings', [])
        routing_config = data.get('routingConfig', {})
        auto_create_subnets = data.get('autoCreateSubnetworks', True)

        # Topology configuration
        routing_mode = routing_config.get('routingMode', 'REGIONAL')
        topology_type = f"VPC Network - {routing_mode} routing"

        if peerings:
            topology_type += f" with {len(peerings)} peering connections"

        # Network configuration analysis
        config_features = []
        if not auto_create_subnets:
            config_features.append("Custom mode network")
        if routing_mode == 'GLOBAL':
            config_features.append("Global routing enabled")
        if peerings:
            config_features.append(f"{len(peerings)} network peerings")

        network_configuration = " | ".join(config_features) if config_features else "Standard VPC network"

        # Security implications
        implications = []
        if routing_mode == 'GLOBAL':
            implications.append("Global routing increases connectivity scope")
        if peerings:
            implications.append("Network peering extends trust boundaries")
        if auto_create_subnets:
            implications.append("Automatic subnet creation reduces control")

        security_implications = "; ".join(implications) if implications else "Standard network isolation"

        # Risk assessment
        risk_factors = 0
        if routing_mode == 'GLOBAL':
            risk_factors += 1
        if len(peerings) > 3:
            risk_factors += 1
        if auto_create_subnets:
            risk_factors += 1

        if risk_factors >= 2:
            configuration_risk = "Medium - Multiple connectivity features increase complexity"
        elif risk_factors == 1:
            configuration_risk = "Low - Standard network configuration"
        else:
            configuration_risk = "Low - Simple network topology"

        return {
            'topology_type': topology_type,
            'network_configuration': network_configuration,
            'configuration_risk': configuration_risk,
            'security_implications': security_implications,
            'topology_details': f"Routing: {routing_mode} | Peerings: {len(peerings)}"
        }

    @staticmethod
    def _analyze_route_topology(data: Dict[str, Any]) -> Dict[str, str]:
        """Analyze custom route configuration"""
        dest_range = data.get('destRange', '')
        next_hop_gateway = data.get('nextHopGateway', '')
        next_hop_instance = data.get('nextHopInstance', '')
        next_hop_ip = data.get('nextHopIp', '')
        priority = data.get('priority', 1000)

        # Topology type
        if next_hop_gateway:
            topology_type = "Custom Route - Internet Gateway"
        elif next_hop_instance:
            topology_type = "Custom Route - Instance Next Hop"
        elif next_hop_ip:
            topology_type = "Custom Route - IP Next Hop"
        else:
            topology_type = "Custom Route - Unknown Next Hop"

        # Configuration analysis
        network_configuration = f"Destination: {dest_range} | Priority: {priority}"

        # Security implications
        implications = []
        if dest_range == '0.0.0.0/0':
            implications.append("Default route - affects all traffic")
        if next_hop_instance:
            implications.append("Routes through specific instance")
        if priority < 100:
            implications.append("High priority route")

        security_implications = "; ".join(implications) if implications else "Standard routing configuration"

        # Risk assessment
        if dest_range == '0.0.0.0/0' and priority < 1000:
            configuration_risk = "Medium - High priority default route"
        elif next_hop_instance:
            configuration_risk = "Medium - Instance-based routing"
        else:
            configuration_risk = "Low - Standard custom route"

        return {
            'topology_type': topology_type,
            'network_configuration': network_configuration,
            'configuration_risk': configuration_risk,
            'security_implications': security_implications,
            'topology_details': f"Dest: {dest_range} | Priority: {priority}"
        }

    @staticmethod
    def _analyze_load_balancer_topology(data: Dict[str, Any]) -> Dict[str, str]:
        """Analyze load balancer topology"""
        load_balancing_scheme = data.get('loadBalancingScheme', 'EXTERNAL')
        port_range = data.get('portRange', '')
        target = data.get('target', '')
        ip_address = data.get('IPAddress', '')

        # Topology type
        topology_type = f"Load Balancer - {load_balancing_scheme}"
        if port_range:
            topology_type += f" on ports {port_range}"

        # Configuration analysis
        config_parts = [f"Scheme: {load_balancing_scheme}"]
        if port_range:
            config_parts.append(f"Ports: {port_range}")
        if ip_address:
            config_parts.append("Static IP")

        network_configuration = " | ".join(config_parts)

        # Security implications
        implications = []
        if load_balancing_scheme == 'EXTERNAL':
            implications.append("External load balancer - Internet facing")
        elif load_balancing_scheme == 'INTERNAL':
            implications.append("Internal load balancer - Private traffic only")

        if port_range and ('80' in port_range or '443' in port_range):
            implications.append("HTTP/HTTPS traffic")

        security_implications = "; ".join(implications) if implications else "Standard load balancer"

        # Risk assessment
        if load_balancing_scheme == 'EXTERNAL':
            configuration_risk = "Medium - External exposure requires security controls"
        else:
            configuration_risk = "Low - Internal load balancer"

        return {
            'topology_type': topology_type,
            'network_configuration': network_configuration,
            'configuration_risk': configuration_risk,
            'security_implications': security_implications,
            'topology_details': f"Scheme: {load_balancing_scheme} | Ports: {port_range}"
        }

    @staticmethod
    def _analyze_vpn_topology(data: Dict[str, Any]) -> Dict[str, str]:
        """Analyze VPN topology"""
        # This would be for VPN Gateways and Tunnels
        if 'status' in data:  # VPN Tunnel
            status = data.get('status', 'UNKNOWN')
            peer_ip = data.get('peerIp', '')
            ike_version = data.get('ikeVersion', 1)

            topology_type = f"VPN Tunnel - IKEv{ike_version}"
            network_configuration = f"Status: {status} | Peer: {peer_ip[:15]}..."

            if status != 'ESTABLISHED':
                configuration_risk = "High - VPN tunnel not established"
                security_implications = "VPN connectivity issues detected"
            elif ike_version == 1:
                configuration_risk = "Medium - IKEv1 less secure than IKEv2"
                security_implications = "Consider upgrading to IKEv2"
            else:
                configuration_risk = "Low - Secure VPN connection"
                security_implications = "Standard VPN security"

        else:  # VPN Gateway
            topology_type = "VPN Gateway"
            network_configuration = "Cloud VPN Gateway"
            configuration_risk = "Low - Standard VPN gateway"
            security_implications = "Provides secure site-to-site connectivity"

        return {
            'topology_type': topology_type,
            'network_configuration': network_configuration,
            'configuration_risk': configuration_risk,
            'security_implications': security_implications,
            'topology_details': network_configuration
        }

    @staticmethod
    def _get_default_topology_analysis() -> Dict[str, str]:
        """Get default topology analysis result"""
        return {
            'topology_type': 'Unknown network topology',
            'network_configuration': 'Manual review required',
            'configuration_risk': 'Manual review needed',
            'security_implications': 'Configuration analysis required',
            'topology_details': 'Topology analysis failed'
        }


class GCPNetworkOptimizationAnalyzer:
    """
    GCP Network Resource Optimization Analyzer

    Analyzes network resources for cost and performance optimization:
    - Unused static IP addresses
    - Underutilized load balancers
    - Inefficient health check configurations
    - Network resource rightsizing opportunities
    """

    @staticmethod
    def analyze_network_resource_optimization(asset_type: str, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Analyze network resource optimization opportunities

        Args:
            asset_type: GCP asset type
            data: Network resource data

        Returns:
            Dictionary containing optimization analysis
        """
        try:
            if data is None:
                return GCPNetworkOptimizationAnalyzer._get_default_optimization_analysis()

            if 'Address' in asset_type:
                return GCPNetworkOptimizationAnalyzer._analyze_static_ip_optimization(data)
            elif 'BackendService' in asset_type:
                return GCPNetworkOptimizationAnalyzer._analyze_backend_service_optimization(data)
            elif 'HealthCheck' in asset_type:
                return GCPNetworkOptimizationAnalyzer._analyze_health_check_optimization(data)
            elif 'ForwardingRule' in asset_type:
                return GCPNetworkOptimizationAnalyzer._analyze_forwarding_rule_optimization(data)
            else:
                return GCPNetworkOptimizationAnalyzer._get_default_optimization_analysis()

        except Exception as e:
            logger.warning(f"Failed to analyze network optimization for {asset_type}: {e}")
            return GCPNetworkOptimizationAnalyzer._get_default_optimization_analysis()

    @staticmethod
    def _analyze_static_ip_optimization(data: Dict[str, Any]) -> Dict[str, str]:
        """Analyze static IP address optimization"""
        status = data.get('status', 'IN_USE')
        address_type = data.get('addressType', 'EXTERNAL')
        users = data.get('users', [])

        # Optimization analysis
        if status == 'RESERVED' and not users:
            optimization_type = "Unused Static IP Address"
            utilization_status = "Unused - No resources attached"
            cost_optimization_potential = "High - Delete unused static IP"
            optimization_recommendation = "Delete unused static IP to avoid hourly charges"
            resource_details = f"Status: {status} | Type: {address_type} | Users: 0"
        elif status == 'IN_USE':
            optimization_type = "Active Static IP Address"
            utilization_status = "In Use - Attached to resources"
            cost_optimization_potential = "Low - IP address in active use"
            optimization_recommendation = "No action needed - IP is actively used"
            resource_details = f"Status: {status} | Type: {address_type} | Users: {len(users)}"
        else:
            optimization_type = "Static IP Address Review"
            utilization_status = f"Status: {status}"
            cost_optimization_potential = "Manual review required"
            optimization_recommendation = "Review IP address usage and requirements"
            resource_details = f"Status: {status} | Type: {address_type}"

        return {
            'optimization_type': optimization_type,
            'utilization_status': utilization_status,
            'cost_optimization_potential': cost_optimization_potential,
            'optimization_recommendation': optimization_recommendation,
            'resource_details': resource_details
        }

    @staticmethod
    def _analyze_backend_service_optimization(data: Dict[str, Any]) -> Dict[str, str]:
        """Analyze backend service optimization"""
        backends = data.get('backends', [])
        load_balancing_scheme = data.get('loadBalancingScheme', 'EXTERNAL')
        protocol = data.get('protocol', 'HTTP')
        health_checks = data.get('healthChecks', [])

        # Optimization analysis
        backend_count = len(backends)
        health_check_count = len(health_checks)

        if backend_count == 0:
            optimization_type = "Backend Service - No Backends"
            utilization_status = "Unused - No backend instances configured"
            cost_optimization_potential = "High - Delete unused backend service"
            optimization_recommendation = "Delete backend service with no configured backends"
        elif backend_count == 1 and load_balancing_scheme == 'EXTERNAL':
            optimization_type = "Backend Service - Single Backend"
            utilization_status = "Low utilization - Single backend for load balancer"
            cost_optimization_potential = "Medium - Consider direct instance access"
            optimization_recommendation = "Evaluate if load balancer is needed for single backend"
        elif health_check_count > 2:
            optimization_type = "Backend Service - Multiple Health Checks"
            utilization_status = "Over-configured - Multiple health checks"
            cost_optimization_potential = "Low - Consolidate health checks"
            optimization_recommendation = "Consider consolidating health check configurations"
        else:
            optimization_type = "Backend Service - Well Configured"
            utilization_status = "Good configuration"
            cost_optimization_potential = "Low - Properly configured"
            optimization_recommendation = "No optimization needed"

        resource_details = f"Backends: {backend_count} | Health Checks: {health_check_count} | Protocol: {protocol}"

        return {
            'optimization_type': optimization_type,
            'utilization_status': utilization_status,
            'cost_optimization_potential': cost_optimization_potential,
            'optimization_recommendation': optimization_recommendation,
            'resource_details': resource_details
        }

    @staticmethod
    def _analyze_health_check_optimization(data: Dict[str, Any]) -> Dict[str, str]:
        """Analyze health check optimization"""
        check_interval_sec = data.get('checkIntervalSec', 10)
        timeout_sec = data.get('timeoutSec', 5)
        healthy_threshold = data.get('healthyThreshold', 2)
        unhealthy_threshold = data.get('unhealthyThreshold', 3)
        health_check_type = data.get('type', 'HTTP')

        # Optimization analysis
        if check_interval_sec < 10:
            optimization_type = "Health Check - High Frequency"
            utilization_status = "Over-configured - Very frequent health checks"
            cost_optimization_potential = "Medium - Increase check interval"
            optimization_recommendation = f"Consider increasing check interval from {check_interval_sec}s to 10s+"
        elif timeout_sec > 10:
            optimization_type = "Health Check - Long Timeout"
            utilization_status = "Sub-optimal - Long timeout period"
            cost_optimization_potential = "Low - Reduce timeout for faster failover"
            optimization_recommendation = f"Consider reducing timeout from {timeout_sec}s to 5-10s"
        elif unhealthy_threshold > 5:
            optimization_type = "Health Check - High Failure Threshold"
            utilization_status = "Sub-optimal - High failure threshold"
            cost_optimization_potential = "Low - Reduce failure threshold"
            optimization_recommendation = f"Consider reducing unhealthy threshold from {unhealthy_threshold} to 3-5"
        else:
            optimization_type = "Health Check - Well Configured"
            utilization_status = "Good configuration"
            cost_optimization_potential = "Low - Properly configured"
            optimization_recommendation = "No optimization needed"

        resource_details = f"Type: {health_check_type} | Interval: {check_interval_sec}s | Timeout: {timeout_sec}s"

        return {
            'optimization_type': optimization_type,
            'utilization_status': utilization_status,
            'cost_optimization_potential': cost_optimization_potential,
            'optimization_recommendation': optimization_recommendation,
            'resource_details': resource_details
        }

    @staticmethod
    def _analyze_forwarding_rule_optimization(data: Dict[str, Any]) -> Dict[str, str]:
        """Analyze forwarding rule optimization"""
        load_balancing_scheme = data.get('loadBalancingScheme', 'EXTERNAL')
        port_range = data.get('portRange', '')
        target = data.get('target', '')
        ip_address = data.get('IPAddress', '')

        # Optimization analysis
        if not target:
            optimization_type = "Forwarding Rule - No Target"
            utilization_status = "Unused - No target configured"
            cost_optimization_potential = "High - Delete unused forwarding rule"
            optimization_recommendation = "Delete forwarding rule with no configured target"
        elif load_balancing_scheme == 'EXTERNAL' and not ip_address:
            optimization_type = "Forwarding Rule - Ephemeral IP"
            utilization_status = "Using ephemeral IP - May change on restart"
            cost_optimization_potential = "Low - Consider static IP for production"
            optimization_recommendation = "Consider static IP for production workloads"
        else:
            optimization_type = "Forwarding Rule - Active"
            utilization_status = "Active and properly configured"
            cost_optimization_potential = "Low - No optimization needed"
            optimization_recommendation = "No action required"

        has_static_ip = "Yes" if ip_address else "No"
        resource_details = f"Scheme: {load_balancing_scheme} | Ports: {port_range} | Static IP: {has_static_ip}"

        return {
            'optimization_type': optimization_type,
            'utilization_status': utilization_status,
            'cost_optimization_potential': cost_optimization_potential,
            'optimization_recommendation': optimization_recommendation,
            'resource_details': resource_details
        }

    @staticmethod
    def _get_default_optimization_analysis() -> Dict[str, str]:
        """Get default optimization analysis result"""
        return {
            'optimization_type': 'Unknown network resource',
            'utilization_status': 'Manual review required',
            'cost_optimization_potential': 'Manual review needed',
            'optimization_recommendation': 'Resource analysis required',
            'resource_details': 'Optimization analysis failed'
        }
