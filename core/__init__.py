# Core APT Emulation Framework
# This package contains the core functionality for APT simulation

from .stealth import stealth_manager
from .communication import c2_client, dns_c2_client
from .persistence import persistence_manager
from .reconnaissance import recon_manager
from .credentials import credential_harvester
from .screenshot import screen_capture
from .lateral_movement import lateral_movement
from .evasion import evasion_manager
from .plugins import plugin_manager, PluginBase, PluginManager
from .mitre import mitre_logger, MITRELogger, MITRE_TECHNIQUES_DB, APT_GROUPS
from .reporting import reporting_manager, ReportingManager
from .campaign import (
    campaign_orchestrator, 
    CampaignOrchestrator, 
    CampaignPhase,
    CampaignTemplates,
    PhaseStatus
)
from .autorun import windows_autorun_manager, usb_auto_execution_manager
from .macos_autorun import macos_launch_agent_manager, macos_usb_auto_execution
from .linux_autorun import (
    linux_udev_manager, 
    linux_launcher_manager, 
    linux_autostart_manager,
    linux_usb_auto_execution
)
from .usb_packager import usb_packager, payload_builder
from .encrypted_c2 import encrypted_c2_client, covert_channel_manager
from .fileless_execution import fileless_execution_manager
from .process_hollowing import process_hollowing_manager
from .lolbas import lolbas_manager

__all__ = [
    'stealth_manager',
    'c2_client',
    'dns_c2_client',
    'persistence_manager',
    'recon_manager',
    'credential_harvester',
    'screen_capture',
    'lateral_movement',
    'evasion_manager',
    'plugin_manager',
    'PluginBase',
    'PluginManager',
    'mitre_logger',
    'MITRELogger',
    'MITRE_TECHNIQUES_DB',
    'APT_GROUPS',
    'reporting_manager',
    'ReportingManager',
    'campaign_orchestrator',
    'CampaignOrchestrator',
    'CampaignPhase',
    'CampaignTemplates',
    'PhaseStatus',
    'windows_autorun_manager',
    'usb_auto_execution_manager',
    'macos_launch_agent_manager',
    'macos_usb_auto_execution',
    'linux_udev_manager',
    'linux_launcher_manager',
    'linux_autostart_manager',
    'linux_usb_auto_execution',
    'usb_packager',
    'payload_builder',
    'encrypted_c2_client',
    'covert_channel_manager',
    'fileless_execution_manager',
    'process_hollowing_manager',
    'lolbas_manager'
]

__version__ = "2.1.0"
__author__ = "APT Emulation Framework"
