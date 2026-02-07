# Core APT Emulation Framework
# This package contains the core functionality for APT simulation

from .stealth import stealth_manager
from .communication import c2_client, dns_c2_client
from .persistence import persistence_manager
from .reconnaissance import recon_manager

__all__ = [
    'stealth_manager',
    'c2_client', 
    'dns_c2_client',
    'persistence_manager',
    'recon_manager'
]

__version__ = "1.0.0"
__author__ = "APT Emulation Framework"