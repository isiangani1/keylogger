# MITRE ATT&CK Logging System
# Comprehensive MITRE ATT&CK framework logging and mapping

import os
import json
import time
import hashlib
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any
from config import DEBUG_MODE
from core.stealth import stealth_manager

# Extended MITRE ATT&CK Technique Mappings
MITRE_TECHNIQUES_DB = {
    # Initial Access
    'T1190': {'name': 'Exploit Public-Facing Application', 'tactic': 'Initial Access'},
    'T1133': {'name': 'External Remote Services', 'tactic': 'Initial Access'},
    'T1078': {'name': 'Valid Accounts', 'tactic': 'Initial Access'},
    
    # Execution
    'T1059': {'name': 'Command and Scripting Interpreter', 'tactic': 'Execution'},
    'T1059.001': {'name': 'PowerShell', 'tactic': 'Execution'},
    'T1059.003': {'name': 'Windows Command Shell', 'tactic': 'Execution'},
    'T1053': {'name': 'Scheduled Task/Job', 'tactic': 'Execution'},
    'T1053.005': {'name': 'Scheduled Task', 'tactic': 'Execution'},
    'T1047': {'name': 'Windows Management Instrumentation', 'tactic': 'Execution'},
    
    # Persistence
    'T1547': {'name': 'Boot or Logon Autostart Execution', 'tactic': 'Persistence'},
    'T1547.001': {'name': 'Registry Run Keys / Startup Folder', 'tactic': 'Persistence'},
    'T1543': {'name': 'Create or Modify System Process', 'tactic': 'Persistence'},
    'T1543.003': {'name': 'Windows Service', 'tactic': 'Persistence'},
    'T1050': {'name': 'New Service', 'tactic': 'Persistence'},
    'T1197': {'name': 'BITS Jobs', 'tactic': 'Persistence'},
    
    # Privilege Escalation
    'T1068': {'name': 'Exploitation for Privilege Escalation', 'tactic': 'Privilege Escalation'},
    'T1055': {'name': 'Process Injection', 'tactic': 'Privilege Escalation'},
    'T1055.001': {'name': 'Dynamic-link Library Injection', 'tactic': 'Privilege Escalation'},
    'T1548': {'name': 'Abuse Elevation Control Mechanism', 'tactic': 'Privilege Escalation'},
    
    # Defense Evasion
    'T1070': {'name': 'Indicator Removal', 'tactic': 'Defense Evasion'},
    'T1070.004': {'name': 'File Deletion', 'tactic': 'Defense Evasion'},
    'T1027': {'name': 'Obfuscated Files or Information', 'tactic': 'Defense Evasion'},
    'T1027.002': {'name': 'Software Packing', 'tactic': 'Defense Evasion'},
    'T1027.003': {'name': 'Steganography', 'tactic': 'Defense Evasion'},
    'T1078': {'name': 'Valid Accounts', 'tactic': 'Defense Evasion'},
    'T1564': {'name': 'Hide Artifacts', 'tactic': 'Defense Evasion'},
    'T1564.001': {'name': 'Hidden Files and Directories', 'tactic': 'Defense Evasion'},
    'T1564.003': {'name': 'NTFS File Attributes', 'tactic': 'Defense Evasion'},
    'T1218': {'name': 'Signed Binary Proxy Execution', 'tactic': 'Defense Evasion'},
    'T1218.011': {'name': 'Rundll32', 'tactic': 'Defense Evasion'},
    'T1205': {'name': 'Traffic Signaling', 'tactic': 'Defense Evasion'},
    'T1622': {'name': 'Debugger Evasion', 'tactic': 'Defense Evasion'},
    
    # Credential Access
    'T1555': {'name': 'Credentials from Password Stores', 'tactic': 'Credential Access'},
    'T1555.001': {'name': 'Keychain', 'tactic': 'Credential Access'},
    'T1555.002': {'name': 'Securityd Memory', 'tactic': 'Credential Access'},
    'T1555.003': {'name': 'Windows Credential Manager', 'tactic': 'Credential Access'},
    'T1552': {'name': 'Unsecured Credentials', 'tactic': 'Credential Access'},
    'T1552.001': {'name': 'Credentials in Files', 'tactic': 'Credential Access'},
    'T1552.002': {'name': 'Credentials in Registry', 'tactic': 'Credential Access'},
    'T1552.004': {'name': 'Private Keys', 'tactic': 'Credential Access'},
    'T1556': {'name': 'Modify Authentication Process', 'tactic': 'Credential Access'},
    'T1110': {'name': 'Brute Force', 'tactic': 'Credential Access'},
    'T1003': {'name': 'OS Credential Dumping', 'tactic': 'Credential Access'},
    'T1003.001': {'name': 'LSASS Memory', 'tactic': 'Credential Access'},
    'T1003.002': {'name': 'Security Account Manager', 'tactic': 'Credential Access'},
    'T1003.003': {'name': 'NTDS', 'tactic': 'Credential Access'},
    'T1056': {'name': 'Input Capture', 'tactic': 'Credential Access'},
    'T1056.001': {'name': 'Keylogging', 'tactic': 'Credential Access'},
    'T1056.002': {'name': 'GUI Input Capture', 'tactic': 'Credential Access'},
    
    # Discovery
    'T1087': {'name': 'Account Discovery', 'tactic': 'Discovery'},
    'T1087.001': {'name': 'Local Account', 'tactic': 'Discovery'},
    'T1087.002': {'name': 'Domain Account', 'tactic': 'Discovery'},
    'T1087.003': {'name': 'Cloud Account', 'tactic': 'Discovery'},
    'T1018': {'name': 'Remote System Discovery', 'tactic': 'Discovery'},
    'T1016': {'name': 'System Network Configuration Discovery', 'tactic': 'Discovery'},
    'T1016.001': {'name': 'Internet Connection Discovery', 'tactic': 'Discovery'},
    'T1046': {'name': 'Network Service Discovery', 'tactic': 'Discovery'},
    'T1057': {'name': 'Process Discovery', 'tactic': 'Discovery'},
    'T1007': {'name': 'System Service Discovery', 'tactic': 'Discovery'},
    'T1082': {'name': 'System Information Discovery', 'tactic': 'Discovery'},
    'T1083': {'name': 'File and Directory Discovery', 'tactic': 'Discovery'},
    'T1124': {'name': 'System Time Discovery', 'tactic': 'Discovery'},
    'T1622': {'name': 'Debugger Evasion', 'tactic': 'Discovery'},
    
    # Lateral Movement
    'T1021': {'name': 'Remote Services', 'tactic': 'Lateral Movement'},
    'T1021.001': {'name': 'Remote Desktop Protocol', 'tactic': 'Lateral Movement'},
    'T1021.002': {'name': 'SMB/Windows Admin Shares', 'tactic': 'Lateral Movement'},
    'T1021.003': {'name': 'Remote File Protocol', 'tactic': 'Lateral Movement'},
    'T1021.004': {'name': 'SSH', 'tactic': 'Lateral Movement'},
    'T1021.005': {'name': 'VNC', 'tactic': 'Lateral Movement'},
    'T1021.006': {'name': 'Windows Remote Management', 'tactic': 'Lateral Movement'},
    'T1091': {'name': 'Replication Through Removable Media', 'tactic': 'Lateral Movement'},
    'T1210': {'name': 'Exploitation of Remote Services', 'tactic': 'Lateral Movement'},
    
    # Collection
    'T1123': {'name': 'Audio Capture', 'tactic': 'Collection'},
    'T1119': {'name': 'Automated Collection', 'tactic': 'Collection'},
    'T1113': {'name': 'Screen Capture', 'tactic': 'Collection'},
    'T1113.001': {'name': 'Desktop Window Manager', 'tactic': 'Collection'},
    'T1005': {'name': 'Data from Local System', 'tactic': 'Collection'},
    'T1039': {'name': 'Data from Network Shared Drive', 'tactic': 'Collection'},
    'T1025': {'name': 'Data from Removable Media', 'tactic': 'Collection'},
    'T1114': {'name': 'Email Collection', 'tactic': 'Collection'},
    'T1114.001': {'name': 'Local Email Collection', 'tactic': 'Collection'},
    'T1056': {'name': 'Input Capture', 'tactic': 'Collection'},
    
    # Command and Control
    'T1071': {'name': 'Application Layer Protocol', 'tactic': 'Command and Control'},
    'T1071.001': {'name': 'Web Protocols', 'tactic': 'Command and Control'},
    'T1071.002': {'name': 'DNS', 'tactic': 'Command and Control'},
    'T1071.003': {'name': 'Mail Protocols', 'tactic': 'Command and Control'},
    'T1095': {'name': 'Non-Application Layer Protocol', 'tactic': 'Command and Control'},
    'T1001': {'name': 'Data Obfuscation', 'tactic': 'Command and Control'},
    'T1001.001': {'name': 'Junk Data', 'tactic': 'Command and Control'},
    'T1001.002': {'name': 'Steganography', 'tactic': 'Command and Control'},
    'T1132': {'name': 'Data Encoding', 'tactic': 'Command and Control'},
    'T1132.001': {'name': 'Standard Encoding', 'tactic': 'Command and Control'},
    'T1008': {'name': 'Fallback Channels', 'tactic': 'Command and Control'},
    'T1105': {'name': 'Ingress Tool Transfer', 'tactic': 'Command and Control'},
    'T1104': {'name': 'Multi-Stage Channels', 'tactic': 'Command and Control'},
    
    # Exfiltration
    'T1041': {'name': 'Exfiltration Over C2 Channel', 'tactic': 'Exfiltration'},
    'T1011': {'name': 'Exfiltration Over Other Network Medium', 'tactic': 'Exfiltration'},
    'T1011.001': {'name': 'Exfiltration Over Bluetooth', 'tactic': 'Exfiltration'},
    'T1052': {'name': 'Exfiltration Over Physical Medium', 'tactic': 'Exfiltration'},
    'T1052.001': {'name': 'Exfiltration over USB', 'tactic': 'Exfiltration'},
    'T1020': {'name': 'Automated Exfiltration', 'tactic': 'Exfiltration'},
    'T1020.001': {'name': 'Traffic Duplication', 'tactic': 'Exfiltration'},
    'T1030': {'name': 'Data Transfer Size Limits', 'tactic': 'Exfiltration'},
    'T1567': {'name': 'Exfiltration Over Web Service', 'tactic': 'Exfiltration'},
    'T1567.001': {'name': 'Exfiltration to Cloud Storage', 'tactic': 'Exfiltration'},
    
    # Impact
    'T1486': {'name': 'Data Encrypted for Impact', 'tactic': 'Impact'},
    'T1489': {'name': 'Service Stop', 'tactic': 'Impact'},
    'T1529': {'name': 'System Shutdown/Reboot', 'tactic': 'Impact'},
    'T1561': {'name': 'Disk Wipe', 'tactic': 'Impact'},
    'T1561.001': {'name': 'Disk Content Wipe', 'tactic': 'Impact'},
    'T1561.002': {'name': 'Disk Structure Wipe', 'tactic': 'Impact'},
}

# APT Group Mappings
APT_GROUPS = {
    'APT1': {'name': 'Comment Crew', 'techniques': ['T1082', 'T1056.001', 'T1041', 'T1547.001']},
    'APT28': {'name': 'Fancy Bear', 'techniques': ['T1003.001', 'T1021.002', 'T1550.002', 'T1113']},
    'APT29': {'name': 'Cozy Bear', 'techniques': ['T1059.001', 'T1027', 'T1071.001', 'T1055']},
    'APT41': {'name': 'Barium', 'techniques': ['T1021.001', 'T1082', 'T1055', 'T1003']},
    'LAPSUS$': {'name': 'Lapsus$', 'techniques': ['T1078', 'T1113', 'T1003', 'T1021.002']},
    'WIZARD SPIDER': {'name': 'Wizard Spider', 'techniques': ['T1486', 'T1056.001', 'T1021.002']},
}


class MITRELogger:
    """Comprehensive MITRE ATT&CK logging system"""
    
    def __init__(self, log_dir: str = None):
        self.log_dir = log_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'logs'
        )
        self.technique_log = []
        self.session_log = []
        self.coverage_stats = {
            'techniques_used': set(),
            'tactics_used': set(),
            'groups_mimicked': set()
        }
        self._lock = threading.Lock()
        
        # Create log directory
        os.makedirs(self.log_dir, exist_ok=True)
    
    def log_technique(self, technique_id: str, success: bool = True, 
                     details: Dict = None, session_id: str = None) -> Dict:
        """Log a MITRE ATT&CK technique execution"""
        with self._lock:
            # Validate technique
            technique_info = MITRE_TECHNIQUES_DB.get(technique_id, {
                'name': 'Unknown Technique',
                'tactic': 'Unknown'
            })
            
            log_entry = {
                'id': self._generate_id(),
                'timestamp': datetime.now().isoformat(),
                'technique_id': technique_id,
                'technique_name': technique_info['name'],
                'tactic': technique_info['tactic'],
                'success': success,
                'details': details or {},
                'session_id': session_id or self._generate_id()
            }
            
            # Update coverage stats
            self.coverage_stats['techniques_used'].add(technique_id)
            self.coverage_stats['tactics_used'].add(technique_info['tactic'])
            
            # Add to logs
            self.technique_log.append(log_entry)
            self.session_log.append(log_entry)
            
            # Write to file
            self._write_technique_log(log_entry)
            
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Logged technique {technique_id} ({technique_info['name']}): {'Success' if success else 'Failed'}")
                )
            
            return log_entry
    
    def log_technique_batch(self, techniques: List[Dict]) -> List[Dict]:
        """Log multiple techniques at once"""
        results = []
        for tech in techniques:
            result = self.log_technique(
                technique_id=tech.get('technique_id', 'Unknown'),
                success=tech.get('success', True),
                details=tech.get('details', {}),
                session_id=tech.get('session_id')
            )
            results.append(result)
        return results
    
    def log_campaign_phase(self, phase_name: str, techniques: List[str], 
                           details: Dict = None) -> Dict:
        """Log a campaign phase"""
        phase_log = {
            'id': self._generate_id(),
            'timestamp': datetime.now().isoformat(),
            'phase': phase_name,
            'techniques': techniques,
            'details': details or {},
            'technique_results': []
        }
        
        for technique_id in techniques:
            result = self.log_technique(technique_id)
            phase_log['technique_results'].append(result)
        
        return phase_log
    
    def mimic_apt_group(self, group_id: str) -> Dict:
        """Configure campaign to mimic a specific APT group"""
        if group_id not in APT_GROUPS:
            return {'error': f'APT group {group_id} not found'}
        
        group_info = APT_GROUPS[group_id]
        
        # Log mimicked group
        with self._lock:
            self.coverage_stats['groups_mimicked'].add(group_id)
        
        return {
            'group_id': group_id,
            'group_name': group_info['name'],
            'techniques': group_info['techniques'],
            'coverage': self.get_technique_coverage(group_info['techniques'])
        }
    
    def get_technique_coverage(self, technique_ids: List[str]) -> Dict:
        """Get coverage information for specific techniques"""
        coverage = {
            'total': len(technique_ids),
            'covered': 0,
            'techniques': []
        }
        
        for tech_id in technique_ids:
            tech_status = {
                'technique_id': tech_id,
                'covered': tech_id in self.coverage_stats['techniques_used'],
                'info': MITRE_TECHNIQUES_DB.get(tech_id, {'name': 'Unknown'})
            }
            if tech_status['covered']:
                coverage['covered'] += 1
            coverage['techniques'].append(tech_status)
        
        coverage['percentage'] = round(
            (coverage['covered'] / coverage['total'] * 100) 
            if coverage['total'] > 0 else 0, 2
        )
        
        return coverage
    
    def get_coverage_report(self) -> Dict:
        """Generate comprehensive coverage report"""
        all_techniques = set(MITRE_TECHNIQUES_DB.keys())
        
        return {
            'timestamp': datetime.now().isoformat(),
            'techniques_used': list(self.coverage_stats['techniques_used']),
            'tactics_used': list(self.coverage_stats['tactics_used']),
            'groups_mimicked': list(self.coverage_stats['groups_mimicked']),
            'total_techniques': len(all_techniques),
            'covered_techniques': len(self.coverage_stats['techniques_used']),
            'coverage_percentage': round(
                len(self.coverage_stats['techniques_used']) / len(all_techniques) * 100, 2
            ),
            'tactics_coverage': {
                'total': len(set(t['tactic'] for t in MITRE_TECHNIQUES_DB.values())),
                'used': len(self.coverage_stats['tactics_used']),
                'percentage': 0  # Calculate based on actual tactics
            }
        }
    
    def get_attack_matrix(self, focus_tactics: List[str] = None) -> Dict:
        """Generate ATT&CK matrix view"""
        matrix = {}
        
        for technique_id, info in MITRE_TECHNIQUES_DB.items():
            tactic = info['tactic']
            
            # Filter by tactics if specified
            if focus_tactics and tactic not in focus_tactics:
                continue
            
            if tactic not in matrix:
                matrix[tactic] = []
            
            matrix[tactic].append({
                'id': technique_id,
                'name': info['name'],
                'used': technique_id in self.coverage_stats['techniques_used']
            })
        
        return matrix
    
    def get_session_report(self, session_id: str = None) -> Dict:
        """Get report for a specific session"""
        if session_id:
            session_logs = [log for log in self.session_log 
                          if log.get('session_id') == session_id]
        else:
            session_logs = self.session_log.copy()
        
        if not session_logs:
            return {'error': 'No logs found for session'}
        
        # Group by tactic
        by_tactic = {}
        for log in session_logs:
            tactic = log['tactic']
            if tactic not in by_tactic:
                by_tactic[tactic] = []
            by_tactic[tactic].append(log)
        
        return {
            'session_id': session_logs[0].get('session_id', 'unknown'),
            'start_time': session_logs[0]['timestamp'],
            'end_time': session_logs[-1]['timestamp'],
            'total_techniques': len(session_logs),
            'successful_techniques': sum(1 for log in session_logs if log['success']),
            'failed_techniques': sum(1 for log in session_logs if not log['success']),
            'by_tactic': by_tactic
        }
    
    def export_logs(self, output_format: str = 'json') -> str:
        """Export logs in specified format"""
        if output_format == 'json':
            return json.dumps(self.session_log, indent=2)
        elif output_format == 'csv':
            lines = ['timestamp,technique_id,technique_name,tactic,success']
            for log in self.session_log:
                lines.append(
                    f"{log['timestamp']},{log['technique_id']},"
                    f"{log['technique_name']},{log['tactic']},"
                    f"{log['success']}"
                )
            return '\n'.join(lines)
        else:
            return json.dumps(self.session_log, indent=2)
    
    def clear_logs(self):
        """Clear all logs"""
        with self._lock:
            self.technique_log.clear()
            self.session_log.clear()
            self.coverage_stats = {
                'techniques_used': set(),
                'tactics_used': set(),
                'groups_mimicked': set()
            }
    
    def _generate_id(self) -> str:
        """Generate unique ID"""
        return hashlib.md5(
            f"{time.time()}{id(self)}".encode()
        ).hexdigest()[:12]
    
    def _write_technique_log(self, log_entry: Dict):
        """Write log entry to file"""
        try:
            filename = os.path.join(
                self.log_dir, 
                f"mitre_log_{datetime.now().strftime('%Y%m%d')}.jsonl"
            )
            
            with open(filename, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Failed to write MITRE log: {e}")
                )


# Global MITRE logger instance
mitre_logger = MITRELogger()
