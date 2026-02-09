# APT Emulation Framework v2.0

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

### Phase 1 Features (Implemented)
- **Credential Harvesting**: Browser credentials, Windows credentials, wireless profiles, LSA secrets
- **Screen Capture**: Single screenshots, continuous screen streaming, active window capture
- **Lateral Movement**: Network discovery, SMB/WMI/PsExec movement, remote execution
- **Advanced Evasion**: Sandbox detection, behavioral simulation, anti-analysis techniques
- **Plugin System**: Modular architecture with hook-based event system

### Phase 2 Features (Implemented)
- **MITRE ATT&CK Logging**: Comprehensive technique logging, coverage tracking, attack matrix
- **Automated Reporting**: Executive summaries, technique analysis, recommendations
- **Campaign Orchestration**: Multi-phase campaigns, APT group templates, automated execution

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
| T1055 | Process Injection | Various injection techniques |
| T1555 | Credentials from Password Stores | Browser, Windows, Vault harvesting |
| T1113 | Screen Capture | Screenshot and screen streaming |
| T1018 | Remote System Discovery | Network host discovery |
| T1021.002 | SMB/Windows Admin Shares | Lateral movement via SMB |
| T1047 | Windows Management Instrumentation | WMI-based execution |
| T1003.001 | LSASS Memory | Memory credential dumping |
| T1564 | Hide Artifacts | Advanced evasion techniques |

## Project Structure

```
keylogger/                      # Main project directory
├── core/                       # Core framework modules
│   ├── __init__.py            # Package initialization
│   ├── stealth.py             # Anti-detection mechanisms
│   ├── communication.py       # C2 protocols
│   ├── persistence.py         # Persistence techniques
│   ├── reconnaissance.py      # System/network discovery
│   ├── credentials.py         # Credential harvesting
│   ├── screenshot.py          # Screen capture
│   ├── lateral_movement.py     # Lateral movement
│   ├── evasion.py             # Advanced evasion
│   ├── plugins.py             # Plugin system
│   ├── mitre.py              # MITRE ATT&CK logging
│   ├── reporting.py           # Reporting framework
│   └── campaign.py            # Campaign orchestration
├── plans/                      # Implementation documentation
├── config.py                  # Centralized configuration
├── main.py                   # Full APT emulator
├── payload.py                # Lightweight payload
├── requirements.txt          # Python dependencies
└── README.md                # This file
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

# Feature Toggles
CREDENTIAL_HARVEST_ENABLED = True
SCREEN_CAPTURE_ENABLED = True
LATERAL_MOVEMENT_ENABLED = True
EVASION_ENABLED = True
PLUGIN_SYSTEM_ENABLED = True
MITRE_LOGGING_ENABLED = True

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

### Credential Harvester (`core/credentials.py`)
- Browser credentials (Chrome, Firefox, Edge)
- Windows Credential Manager
- Wireless network profiles
- Windows Vault access
- LSA secrets (admin required)

### Screen Capture (`core/screenshot.py`)
- Single screenshot capture
- Continuous screen streaming
- Active window capture
- JPEG compression with quality control

### Lateral Movement (`core/lateral_movement.py`)
- Network discovery and ping sweeps
- SMB share discovery
- SMB-based movement
- WMI-based execution
- Scheduled task creation
- PsExec-style execution

### Evasion Manager (`core/evasion.py`)
- Advanced sandbox detection
- VM artifact detection
- Analysis tool detection
- User activity simulation
- Behavioral timing randomization

### Plugin System (`core/plugins.py`)
- Plugin base class
- Plugin manager for loading/execution
- Hook-based event system
- Built-in plugins (Keylogger, Credential, Screenshot, Lateral)
- Plugin configuration and lifecycle management

### MITRE ATT&CK Logger (`core/mitre.py`)
- Comprehensive technique logging
- ATT&CK matrix generation
- APT group profiles (APT1, APT28, APT29, APT41)
- Technique coverage tracking
- Session reporting

### Reporting Manager (`core/reporting.py`)
- Automated report generation
- Executive summaries
- Technique analysis
- Credential summaries
- Network activity summaries
- Security recommendations
- JSON and HTML output formats

### Campaign Orchestrator (`core/campaign.py`)
- Multi-phase campaign execution
- Phase dependencies and ordering
- Campaign templates:
  - Initial Access Campaign
  - Credential Theft Campaign
  - Lateral Movement Campaign
  - Full Assessment Campaign
- Execution logging and status tracking

## APT Simulation Profiles

The framework supports simulation of different APT groups:

### APT29 (Cozy Bear)
- Focus: Stealth, PowerShell, Living-off-the-Light
- Techniques: T1059.001, T1027, T1071.001, T1055

### APT28 (Fancy Bear)
- Focus: Credential harvesting, Lateral movement
- Techniques: T1003.001, T1021.002, T1550.002, T1113

### APT41 (Barium)
- Focus: Multi-purpose operations
- Techniques: T1021.001, T1082, T1055, T1003

## MITRE ATT&CK Integration

The framework automatically logs executed techniques:

```python
# Technique logging example
mitre_logger.log_technique('T1082', True, {
    'method': 'comprehensive_discovery',
    'info_categories': 8
})

# Get coverage report
coverage = mitre_logger.get_coverage_report()

# Generate ATT&CK matrix
matrix = mitre_logger.get_attack_matrix()
```

## Campaign Templates

Create and execute multi-phase campaigns:

```python
from core.campaign import CampaignOrchestrator, CampaignTemplates

# Create orchestrator
orchestrator = CampaignOrchestrator()

# Load full assessment template
CampaignTemplates.create_full_assessment_campaign(orchestrator)

# Execute campaign
results = orchestrator.execute_campaign()
```

## Plugin Development

Create custom plugins by extending PluginBase:

```python
from core.plugins import PluginBase

class CustomPlugin(PluginBase):
    name = "CustomPlugin"
    version = "1.0.0"
    description = "My custom plugin"
    
    def initialize(self, config=None):
        self.enabled = True
        self.loaded = True
        return True
    
    def custom_method(self):
        # Plugin logic
        pass
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

## Testing

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

### Phase 1 (Completed) ✅
- ✅ Credential harvesting capabilities
- ✅ Screen stream and screenshot capabilities
- ✅ Lateral movement functionality
- ✅ Advanced evasion techniques
- ✅ Modular plugin system

### Phase 2 (Completed) ✅
- ✅ MITRE ATT&CK logging system
- ✅ Automated reporting framework
- ✅ Campaign orchestration

### Phase 3 (Future)
- AI-powered evasion
- Cloud-specific techniques
- macOS/Linux support
- Web shell deployment
- Data exfiltration optimization

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement improvements following MITRE ATT&CK mapping
4. Add comprehensive testing
5. Submit a pull request

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Red Team Field Manual V3](https://github.com/tanc7/hacking-books)
- [APT Groups and Operations](https://attack.mitre.org/groups/)

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
