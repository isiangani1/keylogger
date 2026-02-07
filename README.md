# APT Emulation Framework

A comprehensive Advanced Persistent Threat (APT) emulation system designed for penetration testing and red team engagements. This framework simulates realistic APT behaviors and techniques mapped to the MITRE ATT&CK framework.

## LEGAL DISCLAIMER

**FOR AUTHORIZED TESTING ONLY**

This tool is designed exclusively for authorized penetration testing, red team exercises, and security research. Users must:

- Have explicit written authorization before deployment
- Comply with all applicable laws and regulations
- Use only in controlled, authorized environments
- Follow responsible disclosure practices

Unauthorized use is strictly prohibited and may violate local, state, and federal laws.

## 🎯 Features

### Core Capabilities
- **Stealth Operations**: Process masquerading, anti-VM detection, silent execution
- **Advanced Persistence**: Registry keys, scheduled tasks, startup folders, services
- **Enhanced C2**: HTTPS communication, DNS tunneling, encryption, jitter
- **Comprehensive Reconnaissance**: System, network, security software discovery
- **MITRE ATT&CK Integration**: Technique logging and mapping
- **Modular Architecture**: Plugin-based system for extensibility

### Implemented MITRE ATT&CK Techniques

| Technique ID | Technique Name | Implementation |
|--------------|----------------|----------------|
| T1082 | System Information Discovery | Comprehensive system enumeration |
| T1056.001 | Input Capture: Keylogging | Enhanced keylogger with stealth |
| T1041 | Exfiltration Over C2 Channel | Encrypted data transmission |
| T1547.001 | Registry Run Keys | Multiple persistence methods |
| T1053.005 | Scheduled Task/Job | Task-based persistence |
| T1071.001 | Web Protocols | HTTPS C2 communication |
| T1027 | Obfuscated Files or Information | Data encryption and encoding |
| T1087.001 | Local Account Discovery | User enumeration |
| T1087.002 | Domain Account Discovery | AD enumeration |
| T1057 | Process Discovery | Running process enumeration |
| T1135 | Network Share Discovery | SMB share enumeration |

## Project Structure

```
apt_emulator/
├── core/                    # Core framework modules
│   ├── __init__.py         # Package initialization
│   ├── stealth.py          # Anti-detection mechanisms
│   ├── communication.py    # C2 protocols
│   ├── persistence.py      # Persistence techniques
│   └── reconnaissance.py   # System/network discovery
├── plans/                  # Implementation documentation
│   ├── apt_emulation_improvement_plan.md
│   ├── mitre_attack_mapping.md
│   └── implementation_roadmap.md
├── config.py              # Centralized configuration
├── main.py                # Full APT emulator
├── payload.py             # Lightweight payload
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd apt_emulator
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure the system**
   ```bash
   # Edit config.py to set your C2 server and preferences
   nano config.py
   ```

## Usage

### Basic Execution

**Full APT Emulator:**
```bash
python main.py
```

**Lightweight Payload:**
```bash
python payload.py
```

### Configuration Options

Edit [`config.py`](config.py) to customize:

```python
# Operational Security
SILENT_MODE = True          # Disable debug output
DEBUG_MODE = False          # Enable debugging
PROCESS_NAME_MASQUERADE = "svchost.exe"  # Process name

# C2 Configuration
C2_SERVER = 'https://your-c2-server.com/api'
TRANSMISSION_INTERVAL = 900  # 15 minutes

# Stealth Settings
JITTER_MIN = 1              # Minimum delay
JITTER_MAX = 5              # Maximum delay
```

## Core Modules

### Stealth Manager (`core/stealth.py`)
- Process name masquerading
- Console window hiding
- Anti-VM/sandbox detection
- Behavioral jitter and timing
- Silent error handling

### Communication (`core/communication.py`)
- HTTPS C2 with SSL bypass
- Data encryption (XOR + Base64)
- Retry logic with exponential backoff
- DNS tunneling support
- File exfiltration capabilities

### Persistence (`core/persistence.py`)
- Registry Run Keys (HKCU/HKLM)
- Scheduled Tasks
- Startup Folder
- Windows Services
- Multiple installation methods

### Reconnaissance (`core/reconnaissance.py`)
- System information gathering
- Network configuration discovery
- Security software detection
- Domain enumeration
- User and process discovery
- Hardware and software inventory

## APT Simulation Profiles

The framework supports simulation of different APT groups:

### APT29 (Cozy Bear)
- Focus: Stealth, PowerShell, Living-off-the-Land
- Techniques: T1059.001, T1027, T1071.001, T1055

### APT28 (Fancy Bear)
- Focus: Credential harvesting, Lateral movement
- Techniques: T1003.001, T1021.002, T1550.002, T1113

### APT1 (Comment Crew)
- Focus: Data collection, Exfiltration
- Techniques: T1005, T1083, T1041, T1547.001

## MITRE ATT&CK Integration

The framework automatically logs executed techniques:

```python
# Technique logging example
self._log_technique('T1082', True, {
    'method': 'comprehensive_discovery',
    'info_categories': 8
})
```

## Security Features

### Anti-Detection
- Process masquerading as legitimate Windows processes
- Anti-VM and sandbox detection
- Behavioral timing randomization
- Silent operation modes

### Encryption
- XOR encryption for C2 communications
- Base64 encoding for data obfuscation
- SSL/TLS for transport security

### Operational Security
- Configurable debug modes
- Silent error handling
- Jitter and timing controls
- Multiple persistence vectors

## 🧪 Testing

**Syntax Validation:**
```bash
python -m py_compile *.py core/*.py
```

**Dependency Check:**
```bash
pip check
```

**Module Import Test:**
```bash
python -c "from core import *; print('All modules imported successfully')"
```

## Roadmap

### Phase 1 (Planned)
- Credential harvesting capabilities
- Lateral movement functionality
- Advanced evasion techniques
- Modular plugin system

### Phase 2 (Future)
- MITRE ATT&CK logging system
- Automated reporting framework
- Campaign orchestration
- AI-powered evasion

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement improvements following MITRE ATT&CK mapping
4. Add comprehensive testing
5. Submit a pull request

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Red Team Field Manual V3](https://github.com/tanc7/hacking-books/blob/master/RTFM%20-%20Red%20Team%20Field%20Manual%20v3.pdf)
- [APT Groups and Operations](https://attack.mitre.org/groups/)
on nsert, propagate t next device for ax impact,ndrid,usb,hhd,ssd
## Ethical Use

This framework is intended to help organizations:
- Test their security controls
- Validate detection capabilities
- Improve incident response procedures
- Enhance security awareness

Always ensure proper authorization and follow responsible disclosure practices.

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**
*** This is for educational purposes only***