# Enhancement Implementation Checklist - Auto-Execution on USB Insertion

## Overview
This document provides a detailed implementation checklist for adding auto-execution capabilities to the keylogger payload when a USB device is inserted into a target system.

---

## Phase 1: Windows Auto-Execution

### 1.1 Create Autorun.inf Generator Module
- [ ] Create `core/autorun.py` module
- [ ] Implement `AutorunGenerator` class
- [ ] Add method to generate valid Autorun.inf file
- [ ] Include action parameter for bypass
- [ ] Add shell execution command configuration
- [ ] Implement icon path configuration
- [ ] Add label configuration for USB disguise
- [ ] Implement digital signature placeholder

### 1.2 Windows Implementation Details
```python
# Required methods:
- generate_autorun_inf(payload_path, icon_path, label)
- create_usb_autorun_package(usb_drive_path)
- validate_autorun_structure()
- test_autorun_execution()
```

---

## Phase 2: macOS Auto-Execution

### 2.1 Create Launch Agent Generator Module
- [ ] Create `core/macos_autorun.py` module
- [ ] Implement `MacOSLaunchAgent` class
- [ ] Add method to generate plist XML
- [ ] Configure RunAtLoad parameter
- [ ] Add KeepAlive configuration
- [ ] Implement Label configuration
- [ ] Add ProgramArguments configuration
- [ ] Configure hidden attribute setting

### 2.2 macOS Implementation Details
```python
# Required methods:
- generate_launch_agent_plist(payload_path, label)
- install_launch_agent(plist_path)
- remove_launch_agent(label)
- create_hideable_package()
```

---

## Phase 3: Linux Auto-Execution

### 3.1 Create Udev Rule Generator Module
- [ ] Create `core/linux_autorun.py` module
- [ ] Implement `LinuxUdevRule` class
- [ ] Add method to generate udev rules
- [ ] Configure SUBSYSTEM matching
- [ ] Add ACTION=="add" condition
- [ ] Implement KERNEL pattern matching
- [ ] Add RUN+= command configuration
- [ ] Create launcher script generator
- [ ] Implement rule installation mechanism

### 3.2 Linux Implementation Details
```python
# Required methods:
- generate_udev_rule(launcher_script_path)
- create_launcher_script(payload_path)
- install_udev_rule(rule_path)
- reload_udev_rules()
- create_autostart_desktop_file()
```

---

## Phase 4: USB Payload Packaging

### 4.1 Create USB Packaging Script
- [ ] Create `core/usb_packager.py` module
- [ ] Implement `USBPackager` class
- [ ] Add method to create self-extracting archive
- [ ] Configure extraction directory
- [ ] Add silent execution flag
- [ ] Implement file hiding mechanism
- [ ] Add icon embedding capability
- [ ] Create cross-platform package generation
- [ ] Add checksum generation for verification

### 4.2 USB Packaging Implementation Details
```python
# Required methods:
- package_payload_for_usb(output_path)
- create_self_extracting_archive(payload_path, output_path)
- add_decoy_files(package_path)
- configure_autorun_for_usb(usb_path)
- verify_package_integrity(package_path)
```

---

## Phase 5: Integration with Persistence Module

### 5.1 Update core/persistence.py
- [ ] Import new auto-execution modules
- [ ] Add `AutoExecutionManager` class
- [ ] Integrate USB auto-execution with existing persistence
- [ ] Add platform detection logic
- [ ] Implement fallback mechanisms
- [ ] Add configuration options to config.py
- [ ] Update `install_all_persistence()` method
- [ ] Add logging for auto-execution events

### 5.2 Integration Points
```python
# New methods in PersistenceManager:
- install_usb_auto_execution(usb_path)
- generate_platform_specific_autorun(usb_path)
- create_multi_platform_usb_package(usb_path)
- validate_usb_auto_execution(usb_path)
```

---

## Phase 6: Executable Generation

### 6.1 Configure PyInstaller
- [ ] Create `payload.spec` configuration file
- [ ] Add hidden imports for required modules
- [ ] Configure onefile mode
- [ ] Add windowed option for stealth
- [ ] Include data files (config, etc.)
- [ ] Add version info resource
- [ ] Configure UPX compression
- [ ] Create build script `build_payload.sh`

### 6.2 PyInstaller Configuration Details
```python
# In payload.spec:
- a = Analysis(['payload.py'], ...)
- pyz = PYZ(a.pure)
- exe = EXE(pyz, ...)
- coll = COLLECT(..., name='payload')
```

---

## Phase 7: Testing and Validation

### 7.1 Windows Testing Checklist
- [ ] Test Autorun.inf generation
- [ ] Validate file structure
- [ ] Test on Windows 10/11 with UAC
- [ ] Verify registry persistence
- [ ] Check startup folder execution
- [ ] Test with disabled autorun
- [ ] Validate evasion capabilities

### 7.2 macOS Testing Checklist
- [ ] Test plist generation
- [ ] Validate XML structure
- [ ] Test launchctl load/unload
- [ ] Verify hidden attribute
- [ ] Check user login persistence
- [ ] Test with SIP enabled
- [ ] Validate notarization bypass

### 7.3 Linux Testing Checklist
- [ ] Test udev rule generation
- [ ] Validate rule syntax
- [ ] Test with udevadm
- [ ] Verify rule reload
- [ ] Check systemd autostart
- [ ] Test Desktop file creation
- [ ] Validate permission handling

### 7.4 Cross-Platform Testing
- [ ] Test USB packaging on all platforms
- [ ] Validate self-extracting archive
- [ ] Check file hiding mechanisms
- [ ] Verify icon embedding
- [ ] Test checksum validation
- [ ] Validate logging output
- [ ] Test error handling

---

## Security Considerations

### 8.1 Evasion Techniques
- [ ] Add code signing simulation
- [ ] Implement file timestamp forgery
- [ ] Add legitimate-looking file names
- [ ] Configure proper file attributes
- [ ] Implement network behavior hiding
- [ ] Add sandbox detection
- [ ] Configure process hollowing prevention

### 8.2 Stealth Configuration
```python
# Update config.py:
- AUTO_EXECUTION_ENABLED = True
- USB_STEALTH_MODE = True
- DECOY_FILE_ENABLED = True
- AUTO_HIDE_FILES = True
```

---

## Implementation Order

1. **Week 1**: Windows Autorun.inf implementation
2. **Week 2**: macOS launch agent implementation  
3. **Week 3**: Linux udev rule implementation
4. **Week 4**: USB packaging and integration
5. **Week 5**: Executable generation configuration
6. **Week 6**: Testing and validation

---

## Dependencies Required

```txt
# New Python packages:
- pyinstaller (already in requirements)
- uuid (standard library)
- plistlib (standard library)
- shutil (standard library)
```

---

## File Structure After Implementation

```
core/
├── autorun.py           # NEW - Windows autorun
├── macos_autorun.py     # NEW - macOS launch agent
├── linux_autorun.py     # NEW - Linux udev rules
├── usb_packager.py      # NEW - USB packaging
├── persistence.py        # UPDATED - integration
└── ...
payload.spec             # NEW - PyInstaller config
build_payload.sh         # NEW - Build script
```

---

## Success Criteria

- [ ] All three platforms have auto-execution
- [ ] USB payload auto-executes on insertion
- [ ] Persistence mechanisms are stealthy
- [ ] Executable generates successfully
- [ ] All tests pass
- [ ] Documentation is complete
