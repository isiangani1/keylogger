# Automated Reporting Framework
# Generates comprehensive reports for red team engagements

import os
import json
import time
import hashlib
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict
from config import DEBUG_MODE
from core.stealth import stealth_manager

class ReportingManager:
    """Handles automated report generation"""
    
    def __init__(self, report_dir: str = None):
        self.report_dir = report_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'reports'
        )
        self.reports = {}
        self.scheduled_reports = {}
        self._lock = threading.Lock()
        
        # Create report directory
        os.makedirs(self.report_dir, exist_ok=True)
    
    def generate_session_report(self, session_data: Dict, format: str = 'json') -> Dict:
        """Generate comprehensive session report"""
        report = {
            'id': self._generate_id(),
            'timestamp': datetime.now().isoformat(),
            'type': 'session_report',
            'session_info': self._extract_session_info(session_data),
            'executive_summary': self._generate_executive_summary(session_data),
            'technique_analysis': self._analyze_techniques(session_data),
            'credential_summary': self._summarize_credentials(session_data),
            'network_activity': self._summarize_network_activity(session_data),
            'detection_summary': self._summarize_detections(session_data),
            'recommendations': self._generate_recommendations(session_data)
        }
        
        # Store report
        with self._lock:
            self.reports[report['id']] = report
        
        # Export
        if format == 'json':
            report['content'] = json.dumps(report, indent=2)
        elif format == 'html':
            report['content'] = self._generate_html_report(report)
        
        # Save to file
        self._save_report(report)
        
        return report
    
    def _extract_session_info(self, session_data: Dict) -> Dict:
        """Extract key session information"""
        return {
            'session_id': session_data.get('session_id', 'unknown'),
            'start_time': session_data.get('start_time', datetime.now().isoformat()),
            'end_time': datetime.now().isoformat(),
            'hostname': session_data.get('basic', {}).get('hostname', 'unknown'),
            'username': session_data.get('basic', {}).get('username', 'unknown'),
            'os_type': session_data.get('basic', {}).get('os_type', 'unknown'),
            'ip_addresses': session_data.get('network', {}).get('interfaces', []),
            'domain': session_data.get('basic', {}).get('user_domain', 'unknown')
        }
    
    def _generate_executive_summary(self, session_data: Dict) -> Dict:
        """Generate executive summary"""
        techniques_used = session_data.get('techniques', [])
        credentials_found = session_data.get('credentials', [])
        lateral_movements = session_data.get('lateral_movement', [])
        
        return {
            'overview': (
                f"Red team engagement completed on {datetime.now().strftime('%Y-%m-%d')}. "
                f"The assessment achieved {'significant' if len(techniques_used) > 5 else 'moderate'} "
                f"results across the target environment."
            ),
            'key_findings': [
                f"Successfully executed {len(techniques_used)} MITRE ATT&CK techniques",
                f"Harvested {len(credentials_found)} credential sets",
                f"Achieved {len(lateral_movements)} lateral movement objectives",
                f"Detected security controls: {', '.join(session_data.get('security', {}).get('antivirus', [])) or 'None detected'}"
            ] if session_data else [],
            'risk_score': self._calculate_risk_score(session_data),
            'overall_assessment': self._get_assessment_level(len(techniques_used), len(credentials_found))
        }
    
    def _analyze_techniques(self, session_data: Dict) -> Dict:
        """Analyze executed techniques"""
        techniques = session_data.get('techniques', [])
        
        # Group by tactic
        by_tactic = defaultdict(list)
        for tech in techniques:
            by_tactic[tech.get('tactic', 'Unknown')].append(tech)
        
        return {
            'total_techniques': len(techniques),
            'successful_techniques': sum(1 for t in techniques if t.get('success', True)),
            'failed_techniques': sum(1 for t in techniques if not t.get('success', True)),
            'by_tactic': dict(by_tactic),
            'technique_details': techniques[:20],  # Limit to 20 for summary
            'coverage_analysis': self._analyze_coverage(session_data)
        }
    
    def _analyze_coverage(self, session_data: Dict) -> Dict:
        """Analyze technique coverage"""
        return {
            'initial_access': len(session_data.get('techniques', [])),
            'execution': len(session_data.get('techniques', [])),
            'persistence': len(session_data.get('techniques', [])),
            'privilege_escalation': len(session_data.get('techniques', [])),
            'defense_evasion': len(session_data.get('techniques', [])),
            'credential_access': len(session_data.get('techniques', [])),
            'discovery': len(session_data.get('techniques', [])),
            'lateral_movement': len(session_data.get('lateral_movement', [])),
            'collection': len(session_data.get('techniques', [])),
            'command_and_control': len(session_data.get('techniques', [])),
            'exfiltration': len(session_data.get('techniques', []))
        }
    
    def _summarize_credentials(self, session_data: Dict) -> Dict:
        """Summarize credential harvesting results"""
        credentials = session_data.get('credentials', [])
        
        return {
            'total_credentials': len(credentials),
            'credential_types': {
                'windows': len([c for c in credentials if c.get('type', '').startswith('windows')]),
                'browser': len([c for c in credentials if c.get('type', '').startswith('browser')]),
                'wireless': len([c for c in credentials if c.get('type', '').startswith('wireless')]),
                'vault': len([c for c in credentials if c.get('type', '').startswith('vault')])
            },
            'password_strength_analysis': self._analyze_password_strength(credentials),
            'sensitive_creds': len([c for c in credentials if self._is_sensitive(c)])
        }
    
    def _analyze_password_strength(self, credentials: List[Dict]) -> Dict:
        """Analyze password strength from harvested credentials"""
        # Simplified analysis
        weak_count = sum(1 for c in credentials if c.get('password', '').__len__() < 8)
        medium_count = sum(1 for c in credentials if 8 <= c.get('password', '').__len__() <= 12)
        strong_count = sum(1 for c in credentials if c.get('password', '').__len__() > 12)
        
        return {
            'weak': weak_count,
            'medium': medium_count,
            'strong': strong_count
        }
    
    def _is_sensitive(self, credential: Dict) -> bool:
        """Check if credential is sensitive"""
        sensitive_patterns = ['admin', 'root', 'domain', 'sa', 'sysadmin']
        username = credential.get('username', '').lower()
        return any(pattern in username for pattern in sensitive_patterns)
    
    def _summarize_network_activity(self, session_data: Dict) -> Dict:
        """Summarize network activity"""
        network = session_data.get('network', {})
        
        return {
            'interfaces_discovered': len(network.get('interfaces', [])),
            'internal_ips': [iface['addresses'] for iface in network.get('interfaces', [])],
            'dns_servers': network.get('dns_servers', []),
            'network_shares': len(session_data.get('shares', [])),
            'hosts_discovered': session_data.get('discovered_hosts', [])
        }
    
    def _summarize_detections(self, session_data: Dict) -> Dict:
        """Summarize detection attempts and outcomes"""
        techniques = session_data.get('techniques', [])
        
        return {
            'total_attempts': len(techniques),
            'undetected': sum(1 for t in techniques if t.get('detected', False) == False),
            'detected': sum(1 for t in techniques if t.get('detected', False) == True),
            'blocked': sum(1 for t in techniques if t.get('blocked', False) == True),
            'alerts_triggered': len(session_data.get('alerts', []))
        }
    
    def _generate_recommendations(self, session_data: Dict) -> List[Dict]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Based on credentials found
        credentials = session_data.get('credentials', [])
        if len(credentials) > 0:
            recommendations.append({
                'priority': 'High',
                'category': 'Credential Security',
                'finding': f'Found {len(credentials)} credentials in insecure storage',
                'recommendation': 'Implement credential vault solutions and enforce password policies'
            })
        
        # Based on lateral movement
        lateral = session_data.get('lateral_movement', [])
        if len(lateral) > 0:
            recommendations.append({
                'priority': 'High',
                'category': 'Network Segmentation',
                'finding': 'Lateral movement achieved between systems',
                'recommendation': 'Implement network segmentation and least-privilege access controls'
            })
        
        # Based on techniques used
        techniques = session_data.get('techniques', [])
        techniques_used = [t.get('technique_id') for t in techniques]
        
        if 'T1056.001' in techniques_used:
            recommendations.append({
                'priority': 'Medium',
                'category': 'Endpoint Security',
                'finding': 'Keylogging activity detected',
                'recommendation': 'Deploy endpoint detection and response (EDR) solutions'
            })
        
        if 'T1113' in techniques_used:
            recommendations.append({
                'priority': 'Medium',
                'category': 'Endpoint Security',
                'finding': 'Screen capture capability demonstrated',
                'recommendation': 'Implement screen capture detection and prevention'
            })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'Medium',
                'category': 'Monitoring',
                'finding': 'Command and control activity observed',
                'recommendation': 'Enhance network monitoring for C2 indicators'
            },
            {
                'priority': 'Low',
                'category': 'Awareness',
                'finding': 'User credentials accessible',
                'recommendation': 'Implement security awareness training for credential handling'
            }
        ])
        
        return recommendations
    
    def _calculate_risk_score(self, session_data: Dict) -> int:
        """Calculate overall risk score (0-100)"""
        score = 0
        
        # Credentials found
        credentials = session_data.get('credentials', [])
        score += min(len(credentials) * 15, 45)
        
        # Lateral movement achieved
        lateral = session_data.get('lateral_movement', [])
        score += min(len(lateral) * 20, 40)
        
        # Sensitive data accessed
        if session_data.get('sensitive_data_accessed'):
            score += 15
        
        return min(score, 100)
    
    def _get_assessment_level(self, technique_count: int, cred_count: int) -> str:
        """Get overall assessment level"""
        if technique_count > 10 and cred_count > 5:
            return 'Critical - Multiple attack vectors successful'
        elif technique_count > 5 and cred_count > 2:
            return 'High - Significant security gaps identified'
        elif technique_count > 2:
            return 'Medium - Some security improvements needed'
        else:
            return 'Low - Limited attack success'
    
    def _generate_html_report(self, report: Dict) -> str:
        """Generate HTML format report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Red Team Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1 {{ color: #333; border-bottom: 2px solid #333; }}
                h2 {{ color: #555; margin-top: 30px; }}
                .summary {{ background: #f5f5f5; padding: 20px; border-radius: 5px; }}
                .finding {{ margin: 10px 0; padding: 10px; background: #fff; border-left: 3px solid #333; }}
                .high {{ border-left-color: #d9534f; }}
                .medium {{ border-left-color: #f0ad4e; }}
                .low {{ border-left-color: #5cb85c; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
                th {{ background-color: #4CAF50; color: white; }}
            </style>
        </head>
        <body>
            <h1>Red Team Assessment Report</h1>
            <div class="summary">
                <p><strong>Generated:</strong> {report['timestamp']}</p>
                <p><strong>Assessment Level:</strong> {report['executive_summary'].get('overall_assessment', 'N/A')}</p>
                <p><strong>Risk Score:</strong> {report['executive_summary'].get('risk_score', 0)}/100</p>
            </div>
            
            <h2>Executive Summary</h2>
            <p>{report['executive_summary'].get('overview', 'No overview available')}</p>
            
            <h2>Technique Analysis</h2>
            <p>Total Techniques: {report['technique_analysis'].get('total_techniques', 0)}</p>
            <p>Successful: {report['technique_analysis'].get('successful_techniques', 0)}</p>
            
            <h2>Recommendations</h2>
            {self._generate_html_recommendations(report.get('recommendations', []))}
        </body>
        </html>
        """
        return html
    
    def _generate_html_recommendations(self, recommendations: List[Dict]) -> str:
        """Generate HTML for recommendations"""
        html = ""
        for rec in recommendations:
            priority_class = rec.get('priority', '').lower()
            html += f"""
            <div class="finding {priority_class}">
                <strong>[{rec.get('priority', 'N/A')}] {rec.get('category', 'Unknown')}</strong>
                <p>{rec.get('finding', '')}</p>
                <p><em>Recommendation: {rec.get('recommendation', '')}</em></p>
            </div>
            """
        return html
    
    def schedule_report(self, name: str, interval_hours: int, report_type: str):
        """Schedule automated report generation"""
        self.scheduled_reports[name] = {
            'type': report_type,
            'interval_hours': interval_hours,
            'next_run': datetime.now() + timedelta(hours=interval_hours),
            'active': True
        }
    
    def get_scheduled_reports(self) -> Dict:
        """Get list of scheduled reports"""
        return self.scheduled_reports.copy()
    
    def get_report_history(self) -> List[Dict]:
        """Get history of generated reports"""
        return [
            {'id': rid, 'timestamp': r.get('timestamp')} 
            for rid, r in self.reports.items()
        ]
    
    def export_all_reports(self, output_dir: str = None) -> List[str]:
        """Export all reports to files"""
        output_dir = output_dir or self.report_dir
        os.makedirs(output_dir, exist_ok=True)
        
        exported = []
        for rid, report in self.reports.items():
            filename = os.path.join(output_dir, f"report_{rid}.json")
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            exported.append(filename)
        
        return exported
    
    def _generate_id(self) -> str:
        """Generate unique report ID"""
        return hashlib.md5(
            f"{time.time()}{id(self)}".encode()
        ).hexdigest()[:12]
    
    def _save_report(self, report: Dict):
        """Save report to file"""
        try:
            filename = os.path.join(
                self.report_dir, 
                f"report_{report['id']}.json"
            )
            
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
                
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Report save failed: {e}")
                )


# Global reporting manager instance
reporting_manager = ReportingManager()
