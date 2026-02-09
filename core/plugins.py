# Modular Plugin System
# Enables extensible plugin architecture for APT emulation

import os
import sys
import json
import importlib
import inspect
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any
from config import DEBUG_MODE, MITRE_TECHNIQUES
from core.stealth import stealth_manager

class PluginBase:
    """Base class for all plugins"""
    
    name = "BasePlugin"
    version = "1.0.0"
    description = "Base plugin template"
    author = "APT Emulation Framework"
    
    def __init__(self):
        self.enabled = False
        self.loaded = False
        self.config = {}
        self.hooks = {}
        
    def initialize(self, config: Dict = None) -> bool:
        """Initialize the plugin"""
        self.config = config or {}
        self.enabled = True
        self.loaded = True
        return True
    
    def execute(self, method_name: str, *args, **kwargs) -> Any:
        """Execute a plugin method"""
        if not self.loaded:
            return None
        
        method = getattr(self, method_name, None)
        if method and callable(method):
            try:
                return method(*args, **kwargs)
            except Exception as e:
                if DEBUG_MODE:
                    stealth_manager.safe_execute(
                        lambda: print(f"Plugin {self.name} method {method_name} failed: {e}")
                    )
        return None
    
    def shutdown(self):
        """Shutdown the plugin"""
        self.enabled = False
        self.loaded = False
    
    def register_hook(self, hook_name: str, callback):
        """Register a hook callback"""
        if hook_name not in self.hooks:
            self.hooks[hook_name] = []
        self.hooks[hook_name].append(callback)
    
    def trigger_hook(self, hook_name: str, *args, **kwargs):
        """Trigger all registered hooks"""
        results = []
        if hook_name in self.hooks:
            for callback in self.hooks[hook_name]:
                try:
                    result = callback(*args, **kwargs)
                    results.append(result)
                except Exception as e:
                    if DEBUG_MODE:
                        stealth_manager.safe_execute(
                            lambda: print(f"Hook callback failed: {e}")
                        )
        return results


class PluginManager:
    """Manages plugin loading, execution, and lifecycle"""
    
    def __init__(self, plugin_dir: str = None):
        self.plugin_dir = plugin_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'plugins'
        )
        self.plugins: Dict[str, PluginBase] = {}
        self.plugin_instances: Dict[str, Any] = {}
        self.hooks: Dict[str, List[callable]] = {}
        self.event_bus = {}
        
    def load_plugin(self, plugin_file: str) -> Optional[PluginBase]:
        """Load a single plugin from file"""
        try:
            # Convert filename to module name
            module_name = os.path.splitext(plugin_file)[0]
            
            # Create plugin directory if needed
            sys.path.insert(0, self.plugin_dir)
            
            # Import module
            module = importlib.import_module(module_name)
            
            # Find plugin class
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, PluginBase) and 
                    obj != PluginBase):
                    
                    plugin_instance = obj()
                    
                    # Initialize plugin
                    if plugin_instance.initialize():
                        self.plugins[name] = plugin_instance
                        self.plugin_instances[name] = plugin_instance
                        
                        if DEBUG_MODE:
                            stealth_manager.safe_execute(
                                lambda: print(f"Plugin {name} v{plugin_instance.version} loaded")
                            )
                        
                        return plugin_instance
            
            return None
            
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Plugin loading failed: {e}")
                )
            return None
        finally:
            sys.path.pop(0)
    
    def load_all_plugins(self) -> Dict[str, PluginBase]:
        """Load all plugins from the plugin directory"""
        loaded_plugins = {}
        
        try:
            # Create plugin directory if it doesn't exist
            os.makedirs(self.plugin_dir, exist_ok=True)
            
            # Load built-in plugins first
            builtins_dir = os.path.join(self.plugin_dir, 'builtins')
            if os.path.exists(builtins_dir):
                for filename in os.listdir(builtins_dir):
                    if filename.endswith('.py') and not filename.startswith('_'):
                        plugin = self.load_plugin(os.path.join('builtins', filename))
                        if plugin:
                            loaded_plugins[plugin.name] = plugin
            
            # Load user plugins
            for filename in os.listdir(self.plugin_dir):
                if filename.endswith('.py') and not filename.startswith('_'):
                    plugin = self.load_plugin(filename)
                    if plugin:
                        loaded_plugins[plugin.name] = plugin
                        
        except Exception as e:
            if DEBUG_MODE:
                stealth_manager.safe_execute(
                    lambda: print(f"Plugin loading failed: {e}")
                )
        
        return loaded_plugins
    
    def get_plugin(self, name: str) -> Optional[PluginBase]:
        """Get a plugin by name"""
        return self.plugin_instances.get(name)
    
    def get_all_plugins(self) -> Dict[str, PluginBase]:
        """Get all loaded plugins"""
        return self.plugin_instances.copy()
    
    def execute_plugin(self, name: str, method: str, *args, **kwargs) -> Any:
        """Execute a method on a specific plugin"""
        plugin = self.get_plugin(name)
        if plugin:
            return plugin.execute(method, *args, **kwargs)
        return None
    
    def execute_all_plugins(self, method: str, *args, **kwargs) -> Dict[str, Any]:
        """Execute a method on all plugins"""
        results = {}
        for name, plugin in self.plugin_instances.items():
            result = plugin.execute(method, *args, **kwargs)
            if result is not None:
                results[name] = result
        return results
    
    def register_global_hook(self, hook_name: str, callback: callable):
        """Register a global hook across all plugins"""
        if hook_name not in self.hooks:
            self.hooks[hook_name] = []
        self.hooks[hook_name].append(callback)
    
    def trigger_global_hook(self, hook_name: str, *args, **kwargs) -> List[Any]:
        """Trigger a global hook"""
        results = []
        
        if hook_name in self.hooks:
            for callback in self.hooks[hook_name]:
                try:
                    result = callback(*args, **kwargs)
                    results.append(result)
                except Exception as e:
                    if DEBUG_MODE:
                        stealth_manager.safe_execute(
                            lambda: print(f"Global hook failed: {e}")
                        )
        
        # Also trigger plugin-specific hooks
        for plugin in self.plugin_instances.values():
            results.extend(plugin.trigger_hook(hook_name, *args, **kwargs))
        
        return results
    
    def publish_event(self, event_name: str, event_data: Dict = None):
        """Publish an event to all plugins"""
        self.event_bus[event_name] = {
            'data': event_data,
            'timestamp': datetime.now().isoformat()
        }
        
        # Trigger hooks
        self.trigger_global_hook(f"on_{event_name}", event_data)
    
    def subscribe_to_event(self, plugin_name: str, event_name: str):
        """Subscribe a plugin to an event"""
        plugin = self.get_plugin(plugin_name)
        if plugin:
            plugin.register_hook(f"on_{event_name}", lambda data: self._event_received(plugin_name, event_name, data))
    
    def _event_received(self, plugin_name: str, event_name: str, data: Dict):
        """Handle received event"""
        if DEBUG_MODE:
            stealth_manager.safe_execute(
                lambda: print(f"Plugin {plugin_name} received event {event_name}")
            )
    
    def enable_plugin(self, name: str) -> bool:
        """Enable a plugin"""
        plugin = self.get_plugin(name)
        if plugin:
            plugin.enabled = True
            return True
        return False
    
    def disable_plugin(self, name: str) -> bool:
        """Disable a plugin"""
        plugin = self.get_plugin(name)
        if plugin:
            plugin.enabled = False
            return True
        return False
    
    def configure_plugin(self, name: str, config: Dict) -> bool:
        """Configure a plugin"""
        plugin = self.get_plugin(name)
        if plugin:
            plugin.config.update(config)
            return True
        return False
    
    def shutdown_all_plugins(self):
        """Shutdown all plugins"""
        for name, plugin in self.plugin_instances.items():
            try:
                plugin.shutdown()
                if DEBUG_MODE:
                    stealth_manager.safe_execute(
                        lambda: print(f"Plugin {name} shutdown")
                    )
            except Exception as e:
                if DEBUG_MODE:
                    stealth_manager.safe_execute(
                        lambda: print(f"Plugin {name} shutdown failed: {e}")
                    )
        
        self.plugin_instances.clear()
        self.plugins.clear()
        self.hooks.clear()
        self.event_bus.clear()
    
    def get_plugin_status(self) -> Dict[str, Dict]:
        """Get status of all plugins"""
        status = {}
        for name, plugin in self.plugin_instances.items():
            status[name] = {
                'enabled': plugin.enabled,
                'loaded': plugin.loaded,
                'version': plugin.version,
                'description': plugin.description,
                'config': plugin.config
            }
        return status


# Built-in plugin examples

class KeyloggerPlugin(PluginBase):
    """Built-in keylogger plugin"""
    
    name = "KeyloggerPlugin"
    version = "1.0.0"
    description = "Enhanced keylogging with pattern detection"
    
    def initialize(self, config: Dict = None) -> bool:
        self.config = config or {}
        self.enabled = True
        self.loaded = True
        
        # Register hooks
        self.register_hook('on_startup', self._on_startup)
        self.register_hook('on_shutdown', self._on_shutdown)
        
        return True
    
    def _on_startup(self, data):
        if DEBUG_MODE:
            stealth_manager.safe_execute(
                lambda: print("KeyloggerPlugin: Startup hook triggered")
            )
    
    def _on_shutdown(self, data):
        if DEBUG_MODE:
            stealth_manager.safe_execute(
                lambda: print("KeyloggerPlugin: Shutdown hook triggered")
            )
    
    def start_keylogger(self):
        """Start the keylogger"""
        if not self.enabled:
            return False
        
        # Keylogger implementation
        return True
    
    def stop_keylogger(self):
        """Stop the keylogger"""
        return True
    
    def get_keylog_data(self):
        """Get collected keylog data"""
        return []


class CredentialPlugin(PluginBase):
    """Built-in credential harvesting plugin"""
    
    name = "CredentialPlugin"
    version = "1.0.0"
    description = "Credential harvesting from browsers and system"
    
    def initialize(self, config: Dict = None) -> bool:
        self.config = config or {}
        self.enabled = True
        self.loaded = True
        
        return True
    
    def harvest_credentials(self):
        """Harvest credentials"""
        return {'credentials': []}
    
    def get_credential_count(self):
        """Get count of harvested credentials"""
        return 0


class ScreenshotPlugin(PluginBase):
    """Built-in screenshot plugin"""
    
    name = "ScreenshotPlugin"
    version = "1.0.0"
    description = "Screen capture and monitoring"
    
    def initialize(self, config: Dict = None) -> bool:
        self.config = config or {}
        self.enabled = True
        self.loaded = True
        
        return True
    
    def take_screenshot(self):
        """Take a screenshot"""
        return None
    
    def start_monitoring(self, interval=5.0):
        """Start screen monitoring"""
        return True
    
    def stop_monitoring(self):
        """Stop screen monitoring"""
        return True


class LateralPlugin(PluginBase):
    """Built-in lateral movement plugin"""
    
    name = "LateralPlugin"
    version = "1.0.0"
    description = "Lateral movement capabilities"
    
    def initialize(self, config: Dict = None) -> bool:
        self.config = config or {}
        self.enabled = True
        self.loaded = True
        
        return True
    
    def discover_targets(self):
        """Discover network targets"""
        return {'hosts': [], 'shares': []}
    
    def move_to_target(self, target, method='smb'):
        """Move to target system"""
        return {'success': False}
    
    def execute_remote(self, target, command):
        """Execute command remotely"""
        return {'success': False, 'output': None}


# Global plugin manager instance
plugin_manager = PluginManager()
