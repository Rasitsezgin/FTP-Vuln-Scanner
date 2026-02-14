#!/usr/bin/env python3
"""
Anonymous FTP Test Script
"""
import os
import sys
import random
import string
from ftplib import FTP 

def get_random_name():
   letters = string.ascii_letters
   return ''.join(random.choice(letters) for i in range(8))

def create_test_file(filename):
   try:
       with open(filename, "w") as f:
           f.write("Test file content")
       return filename
   except:
       return None

# Hedef IP
host = "10.0.2.24"
username = "anonymous"
password = ""

print("=== Anonymous FTP Test ===")
print(f"Target: {host}")

try:
   ftp = FTP(host)
   ftp.login(username, password)
   
   print(f"[+] Anonymous login successful!")
   print(f"[+] Current directory: {ftp.pwd()}")
   print(f"[+] Server banner: {ftp.getwelcome()}")
   
   # Dizin listesi
   print("\n[+] Directory listing:")
   ftp.retrlines('LIST')
   
   # Yazılabilir dizin testi
   print("\n[+] Testing writable directories...")
   test_file = create_test_file(get_random_name() + ".txt")
   
   if test_file:
       try:
           with open(test_file, 'rb') as f:
               ftp.storbinary(f'STOR {test_file}', f)
           print(f"[+] SUCCESS: File upload works in {ftp.pwd()}")
           
           # Dosyayı sil
           try:
               ftp.delete(test_file)
               print(f"[+] SUCCESS: File deletion works")
           except:
               print(f"[-] FAILED: Cannot delete file")
               
       except Exception as e:
           print(f"[-] FAILED: Cannot upload file - {e}")
   
   # Dizin oluşturma testi
   test_dir = get_random_name()
   try:
       ftp.mkd(test_dir)
       print(f"[+] SUCCESS: Directory creation works")
       
       # Dizini sil
       try:
           ftp.rmd(test_dir)
           print(f"[+] SUCCESS: Directory deletion works")
       except:
           print(f"[-] FAILED: Cannot delete directory")
           
   except Exception as e:
       print(f"[-] FAILED: Cannot create directory - {e}")
   
   ftp.quit()
   
   # Yerel test dosyasını temizle
   if test_file and os.path.exists(test_file):
       os.remove(test_file)
       
except Exception as e:
   print(f"[-] Connection failed: {e}")

print("\n[+] Test completed")
