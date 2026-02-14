#!/bin/bash
#
# FTP PenTest Framework - Installation & Setup Script
# This script sets up the environment and verifies dependencies
#

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     FTP PenTest Framework - Installation Script              ║
║     Version 3.0                                               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}[!] Not running as root. Some installations may fail.${NC}"
    echo -e "${YELLOW}[!] Consider running: sudo $0${NC}"
    echo ""
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install package
install_package() {
    local package=$1
    echo -e "${BLUE}[*] Installing $package...${NC}"
    
    if command_exists apt-get; then
        apt-get install -y "$package"
    elif command_exists yum; then
        yum install -y "$package"
    elif command_exists dnf; then
        dnf install -y "$package"
    elif command_exists pacman; then
        pacman -S --noconfirm "$package"
    else
        echo -e "${RED}[!] Package manager not found. Please install $package manually.${NC}"
        return 1
    fi
}

echo -e "${GREEN}[1/5] Checking Python installation...${NC}"
if command_exists python3; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}    ✓ Python 3 found: $PYTHON_VERSION${NC}"
else
    echo -e "${RED}    ✗ Python 3 not found${NC}"
    read -p "    Install Python 3? (y/n): " install_python
    if [ "$install_python" = "y" ]; then
        install_package python3
    else
        echo -e "${RED}    Python 3 is required. Exiting.${NC}"
        exit 1
    fi
fi

echo ""
echo -e "${GREEN}[2/5] Checking required system tools...${NC}"

REQUIRED_TOOLS=("nc" "nmap" "ftp")
MISSING_TOOLS=()

for tool in "${REQUIRED_TOOLS[@]}"; do
    if command_exists "$tool"; then
        echo -e "${GREEN}    ✓ $tool found${NC}"
    else
        echo -e "${YELLOW}    ✗ $tool not found${NC}"
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}[!] Missing tools: ${MISSING_TOOLS[*]}${NC}"
    read -p "    Install missing tools? (y/n): " install_tools
    
    if [ "$install_tools" = "y" ]; then
        for tool in "${MISSING_TOOLS[@]}"; do
            case $tool in
                nc)
                    install_package netcat
                    ;;
                nmap)
                    install_package nmap
                    ;;
                ftp)
                    install_package ftp
                    ;;
            esac
        done
    else
        echo -e "${YELLOW}[!] Some features may not work without these tools.${NC}"
    fi
fi

echo ""
echo -e "${GREEN}[3/5] Setting file permissions...${NC}"

FILES=("ftp_pentest_framework.py" "quick_start.sh" "payload_generator.py")

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        chmod +x "$file"
        echo -e "${GREEN}    ✓ Made $file executable${NC}"
    else
        echo -e "${YELLOW}    ! $file not found in current directory${NC}"
    fi
done

echo ""
echo -e "${GREEN}[4/5] Checking optional dependencies...${NC}"

OPTIONAL_TOOLS=("sshpass" "tmux" "xterm" "gnome-terminal")

for tool in "${OPTIONAL_TOOLS[@]}"; do
    if command_exists "$tool"; then
        echo -e "${GREEN}    ✓ $tool found (optional)${NC}"
    else
        echo -e "${BLUE}    ℹ $tool not found (optional, enhances functionality)${NC}"
    fi
done

echo ""
echo -e "${GREEN}[5/5] Verifying installation...${NC}"

# Test Python script syntax
if python3 -m py_compile ftp_pentest_framework.py 2>/dev/null; then
    echo -e "${GREEN}    ✓ Main framework script validated${NC}"
else
    echo -e "${YELLOW}    ! Could not validate main script (file may not exist in current directory)${NC}"
fi

if python3 -m py_compile payload_generator.py 2>/dev/null; then
    echo -e "${GREEN}    ✓ Payload generator script validated${NC}"
else
    echo -e "${YELLOW}    ! Could not validate payload generator (file may not exist in current directory)${NC}"
fi

# Create test directory structure
echo ""
echo -e "${BLUE}[*] Creating working directories...${NC}"
mkdir -p logs reports payloads 2>/dev/null
echo -e "${GREEN}    ✓ Created: logs/, reports/, payloads/${NC}"

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Installation Complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"

echo ""
echo -e "${BLUE}Quick Start Guide:${NC}"
echo ""
echo -e "1. Quick Start (Interactive Menu):"
echo -e "   ${YELLOW}./quick_start.sh${NC}"
echo ""
echo -e "2. Basic Usage:"
echo -e "   ${YELLOW}python3 ftp_pentest_framework.py -t <target_ip>${NC}"
echo ""
echo -e "3. Generate Payloads:"
echo -e "   ${YELLOW}python3 payload_generator.py -i <your_ip> -p 4444${NC}"
echo ""
echo -e "4. Full Documentation:"
echo -e "   ${YELLOW}cat README.md${NC}"
echo -e "   ${YELLOW}cat KULLANIM_KILAVUZU.md${NC}"
echo ""

echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${RED}⚠️  YASAL UYARI ⚠️${NC}"
echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Bu araç SADECE yasal penetrasyon testleri için kullanılmalıdır!${NC}"
echo -e "${YELLOW}Yetkisiz kullanım SUÇ'tur ve ciddi cezalara yol açabilir!${NC}"
echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${GREEN}Kurulum başarıyla tamamlandı. İyi testler! 🔐${NC}"
