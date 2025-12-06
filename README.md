```markdown
# 🛡️ DRGXEL CyberPack v2.0 - RELEASE EDITION

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Termux%20%7C%20macOS-orange)
![Status](https://img.shields.io/badge/status-RELEASE%20EDITION-success)
![Size](https://img.shields.io/badge/size-single%20file-brightgreen)
![Build](https://img.shields.io/badge/build-20241202-blue)

**Professional Penetration Testing & OSINT Framework**  
*Single-File Python Security MegaTool - Zero Dependencies*

[🚀 Features](#-features) • [💾 Installation](#-installation) • [📖 Usage](#-usage) • [🎯 Modules](#-modules) • [📊 Reports](#-reports) • [⚖️ License](#%EF%B8%8F-license)

</div>

---

## 🌟 Overview

**DRGXEL CyberPack v2.0** adalah framework security testing profesional yang dikemas dalam **satu file Python tunggal** tanpa dependensi eksternal. Tool ini dirancang untuk penetration tester, security researcher, dan IT professional yang membutuhkan toolkit lengkap dan portable.

### ⚡ Mengapa DRGXEL CyberPack?

- 🚀 **Single-File Architecture** - Hanya 1 file Python, tanpa instalasi kompleks
- 🔧 **Zero Dependencies** - 100% menggunakan Python built-in modules
- 📱 **Cross-Platform** - Linux, Termux (Android), macOS, Windows WSL
- 🎨 **Professional UI** - Color-coded CLI dengan progress bars & animations
- 📊 **PDF Reports** - Generate professional security reports dengan grafik
- 🔒 **23 Security Modules** - Complete toolkit untuk penetration testing
- 📈 **Statistics Tracking** - Monitor aktivitas dan progress testing Anda
- ⚡ **LeetScanner Engine** - Automated vulnerability scanner setara tools komersial

---

## 🔥 Key Features

### 🎯 **Complete Security Testing Suite**

| Category | Modules | Description |
|----------|---------|-------------|
| 📡 **Reconnaissance** | 4 modules | Network scanning, subdomain enum, certificate inspection |
| 🎯 **Advanced Testing** | 6 modules | SQLi, XSS, WAF detection, cookie audit, bruteforce |
| 🔍 **OSINT Tools** | 3 modules | Username search (50+ platforms), email breach, PDF forensics |
| 🖥️ **System Security** | 6 modules | DDoS detection, malware scan, process monitoring |
| 🛠️ **Utilities** | 3 modules | Metadata extraction, payload generator, activity logs |
| 🤖 **LeetScanner** | 7 modes | Automated web vulnerability scanner |

### 🤖 **LeetScanner - Automated Vulnerability Scanner**

Framework scanning otomatis dengan 7 mode operasi:

| Mode | Tests | Description |
|------|-------|-------------|
| **FULL SCAN** | 15+ tests | Comprehensive vulnerability assessment |
| **HIGH RISK** | 10 tests | Critical vulnerabilities only (SQLi, RCE, Auth bypass) |
| **FOKUS XSS** | 25+ payloads | Comprehensive XSS testing (5 categories) |
| **FOKUS SQLi** | 25+ payloads | SQL Injection (5 techniques, multi-DB) |
| **SANS TOP 25** | 20 CWEs | SANS/CWE Top 25 Most Dangerous Weaknesses |
| **OWASP TOP 10** | 10 risks | OWASP Top 10 2021 compliance scan |
| **CUSTOM SCAN** | 12 types | Select specific vulnerability types |

---

## 📊 Feature Matrix

### 📡 Reconnaissance Modules

#### 1. **Recon Scanner**
- ✅ **Ping Test** - Network connectivity testing
- ✅ **Port Scanner** - Scan 15 common ports dengan service detection
- ✅ **Subdomain Enumeration** - 25+ common subdomain wordlist
- ✅ **DNS Resolution** - Hostname to IP mapping

#### 2. **Advanced Recon** ⭐ NEW
- ✅ **ASN Lookup** - AS Number, ISP, Network Range, RIR region
- ✅ **Reverse IP Lookup** - Find all domains on shared IP
- ✅ **Reverse DNS** - IP to hostname resolution dengan verification
- ✅ **Certificate Inspector** - SSL/TLS analysis
  - CN, SAN (Subject Alternative Names)
  - Validity period & expiration warning
  - Issuer information
  - TLS version & cipher strength
  - Security assessment & recommendations

#### 3. **Web Vulnerability Scanner**
- ✅ **Mini-Nikto** - Scan 25+ dangerous paths
- ✅ **HTTP Status Detection** - 200, 301, 302, 403 analysis
- ✅ **Interesting Files** - .git, .env, backup.sql, phpinfo.php

#### 4. **Directory Bruteforce**
- ✅ **Internal Wordlist** - 50+ common directories
- ✅ **No External Files** - Built-in wordlist
- ✅ **Smart Detection** - Status code analysis

### 🎯 Advanced Testing Modules

#### 5. **SQLi Vulnerability Checker**
- ✅ **14+ Injection Payloads** - Error, Union, Boolean, Time-based
- ✅ **18+ Error Signatures** - MySQL, PostgreSQL, MSSQL, Oracle, SQLite
- ✅ **Response Analysis** - Length comparison & pattern detection
- ✅ **Database Fingerprinting** - Auto-detect database type

#### 6. **XSS Scanner Mini**
- ✅ **16+ XSS Payloads** - Script, img, svg, iframe, event handlers
- ✅ **Reflected XSS Detection** - Real-time payload analysis
- ✅ **Encoded Payload Support** - HTML entity detection
- ✅ **Context-based Testing** - URL params, form inputs

#### 7. **Active WAF Detector** ⭐ NEW
- ✅ **8 WAF Detection**:
  - Cloudflare, Sucuri, Imperva (Incapsula)
  - Akamai, ModSecurity, BitNinja
  - AWS WAF, Wordfence
- ✅ **5 Detection Methods**:
  - HTTP Header signatures
  - Content pattern matching
  - Status code anomalies
  - Challenge page detection
  - Latency fingerprinting
- ✅ **Protection Mode Assessment** - High/Medium/Low risk rating
- ✅ **Bypass Suggestions** - WAF-specific evasion techniques

#### 8. **Cookie & Session Audit** ⭐ NEW
- ✅ **Security Flags Analysis**:
  - Secure flag (HTTPS enforcement)
  - HttpOnly flag (XSS protection)
  - SameSite flag (CSRF protection)
- ✅ **Session ID Analysis**:
  - Entropy calculation
  - Predictability testing
  - Sequential pattern detection
  - Timestamp detection
- ✅ **JWT Token Analysis**:
  - Header & payload decoding
  - Algorithm weakness detection ('none', weak HMAC)
  - Expiration claim validation
  - Signature strength analysis
- ✅ **Session Fixation Testing** - ID regeneration check
- ✅ **Cookie Hijacking Risk** - Comprehensive risk scoring (0-100)

#### 9. **Bruteforce Panel Login**
- ✅ **3 Attack Modes**:
  - Username bruteforce (11 common usernames)
  - Password bruteforce (11 common passwords)
  - Combo attack (8 user:pass combinations)
- ✅ **Rate-Limited** - 1 request/second (ethical testing)
- ✅ **Success Detection** - Heuristic-based detection

#### 10. **API Fuzzer**
- ✅ **30+ Fuzzing Payloads**:
  - SQLi patterns
  - XSS vectors
  - Path traversal (../../../)
  - Command injection (; | ` $)
  - SSTI templates ({{7*7}}, ${7*7})
  - NoSQL injection ({"$gt":""})
- ✅ **Error Response Detection** - Automatic anomaly detection
- ✅ **Parameter Testing** - GET/POST parameter fuzzing

### 🔍 OSINT & Intelligence Modules

#### 11. **Username OSINT Checker**
- ✅ **50+ Platform Support**:
  - **Social Media**: Twitter, Instagram, TikTok, Facebook, LinkedIn, Reddit
  - **Developer**: GitHub, GitLab, Bitbucket, StackOverflow, HackerRank
  - **Creative**: Behance, Dribbble, DeviantArt, 500px, VSCO
  - **Freelance**: Fiverr, Upwork, Patreon
  - **Gaming**: Steam, Twitch, Discord
  - **Music**: Spotify, SoundCloud, Last.fm
  - **Content**: Medium, WordPress, Blogger, Wattpad
  - Dan 25+ platform lainnya
- ✅ **Success Rate Statistics** - Percentage found analysis
- ✅ **Export Results** - Save to file for reporting

#### 12. **Email Breach Checker**
- ✅ **Offline Mode** - No API key required
- ✅ **Hash Generation** - MD5, SHA1, SHA256
- ✅ **Domain Analysis** - Breach history database
- ✅ **Pattern Analysis** - Weak username detection
- ✅ **Security Recommendations** - Actionable advice
- ✅ **Integration Links** - HaveIBeenPwned, DeHashed, LeakCheck

#### 13. **PDF OSINT Toolkit**
- ✅ **Metadata Extraction**:
  - Title, Author, Creator, Producer
  - Creation date, Modification date
  - PDF version
- ✅ **JavaScript Detection** - Malicious script analysis
- ✅ **Content Extraction**:
  - Embedded URLs
  - Email addresses
  - Hidden data patterns
- ✅ **Malicious Pattern Detection** (10+ patterns):
  - AutoOpen, Launch, URI
  - SubmitForm, ImportData
  - GoToE, GoToR, EmbeddedFile
  - RichMedia, Flash
- ✅ **Risk Scoring System** - 0-100 security assessment
- ✅ **Encryption Analysis** - Encryption status & version
- ✅ **Structure Analysis** - Objects, streams, pages count
- ✅ **Font Detection** - Embedded fonts enumeration
- ✅ **Complete Report** - Export detailed findings

### 🖥️ System & Network Security

#### 14. **Device Information**
- ✅ **System Info** - OS, version, architecture, hostname
- ✅ **CPU Details** - Model, cores, processor info
- ✅ **Memory Analysis** - Total, free, available RAM
- ✅ **Storage Info** - Disk usage, available space
- ✅ **Kernel Info** - Version & details
- ✅ **Network Config** - IP address, interfaces

#### 15. **Anti-DDoS Checker**
- ✅ **Connection Statistics**:
  - ESTABLISHED connections count
  - TIME_WAIT analysis
  - SYN_RECV detection (SYN flood)
- ✅ **Anomaly Detection**:
  - High connection count alerts
  - Unusual pattern detection
  - Multiple connections per IP
- ✅ **Connection Rate Analysis** - ss command integration
- ✅ **Security Alerts** - Real-time threat warnings

#### 16. **Malware Scanner**
- ✅ **File Type Support** - .sh, .py, .php, .pl
- ✅ **10+ Malicious Patterns**:
  - Forkbomb (:(){ :|:& };)
  - Destructive commands (rm -rf /)
  - Remote execution (curl|sh, wget|sh)
  - Encoding tricks (eval base64)
  - Reverse shells (nc -e, python pty.spawn)
  - Permission changes (chmod 777)
  - Cron manipulation
  - Password grabbing
- ✅ **Recursive Scanning** - Directory tree traversal
- ✅ **Pattern Detection** - Regex-based analysis

#### 17. **Process Watchdog**
- ✅ **High CPU Detection** - Resource-intensive processes
- ✅ **Suspicious Names** - Malware, backdoor, miner detection
- ✅ **Network Activity** - Process network connections
- ✅ **Top 10 Display** - CPU consumers ranking
- ✅ **Memory Usage** - RAM consumption analysis

#### 18. **Network Monitor**
- ✅ **Listening Ports** - All open ports display
- ✅ **Active Connections**:
  - ESTABLISHED connections
  - SYN_SENT, SYN_RECV states
  - Foreign addresses tracking
- ✅ **Interface Statistics**:
  - RX/TX bytes per interface
  - MB transferred calculation
- ✅ **DNS Configuration** - Nameserver display
- ✅ **Connection Count** - Total active connections

#### 19. **Network Stress Test** (Safe Mode)
- ✅ **3 Benchmark Modes**:
  - **Ping Benchmark** - Latency, packet loss, min/max/avg
  - **HTTP Benchmark** - Response time, success rate
  - **Connection Benchmark** - Socket connection speed
- ✅ **Rate-Limited** - Ethical testing (1-2 req/sec)
- ✅ **Statistics Output** - Detailed performance metrics

### 🛠️ Utility Modules

#### 20. **File Metadata Extractor**
- ✅ **Basic Info** - Size, dates (modified, accessed, created)
- ✅ **EXIF Support** - Image metadata (if exiftool available)
- ✅ **Format Detection** - JPEG, PNG, GIF identification
- ✅ **Hidden Data Analysis**:
  - URL extraction
  - Email extraction
  - Embedded file signatures (ZIP, PDF, JPEG)
- ✅ **Entropy Analysis** - Encryption/compression detection
- ✅ **File Signature** - Magic number verification

#### 21. **Payload Generator**
- ✅ **100+ Security Payloads** in 8 categories:
  - **LFI** (12 payloads) - ../../../etc/passwd, encodings
  - **RFI** (9 payloads) - Remote includes, data URIs
  - **SSTI** (14 payloads) - Jinja2, Freemarker, Thymeleaf
  - **XSS** (15 payloads) - Script, img, svg, events
  - **SQLi** (17 payloads) - Union, Boolean, Time-based
  - **Directory Traversal** (15 payloads) - Path manipulation
  - **Command Injection** (17 payloads) - Shell commands
  - **XXE** (5 payloads) - XML external entity
- ✅ **Export Function** - Save all payloads to file
- ✅ **Category Selection** - Generate specific types

#### 22. **DRGXEL SysLog**
- ✅ **Activity Logging** - All actions tracked
- ✅ **Timestamped Entries** - Precise time tracking
- ✅ **Last 50 Entries** - Recent activity view
- ✅ **Total Counter** - Lifetime statistics
- ✅ **Clear Function** - Log management
- ✅ **File Location** - ~/drgxel_logs.txt

### 🤖 LeetScanner - Automated Vulnerability Scanner

#### 23. **LeetScanner Suite** ⭐ FLAGSHIP FEATURE

##### **Mode 1: FULL SCAN**
- ✅ **15+ Comprehensive Tests**:
  - SSL/TLS & HSTS validation
  - XSS vulnerability detection
  - SQL Injection testing
  - Directory listing check
  - Sensitive file exposure
  - Security headers audit
  - CSRF protection
  - LFI/RFI detection
  - XXE vulnerability
  - SSRF testing
  - Path traversal
  - Command injection
  - Open redirect
  - Cookie security
  - Server information disclosure
- ✅ **Threat Intel Summary** - Color-coded severity (Critical/High/Medium/Low/Info)
- ✅ **PDF Report Generation** - Professional security reports
- ✅ **Vulnerability Details** - CVSS scores, CVE references, remediation

##### **Mode 2: HIGH RISK**
- ✅ **10 Critical Tests**:
  - **Advanced SQL Injection** - Union, Boolean, Time-based
  - **Remote Code Execution** - Web shell detection
  - **Authentication Bypass** - Admin panel access check
  - **Sensitive Data Exposure** - .env, config files
  - **SSRF** - Internal network access
  - **XXE** - XML external entity
  - **Deserialization** - Unsafe object handling
  - **Path Traversal (Critical)** - File system access
  - **Arbitrary File Upload** - Upload vulnerabilities
  - **Command Injection** - OS command execution
- ✅ **Focus on CRITICAL/HIGH** - Skip low-priority issues
- ✅ **Immediate Action Alerts** - Clear risk communication

##### **Mode 3: FOKUS XSS**
- ✅ **25+ XSS Payloads** in 5 categories:
  - **Basic** (5) - `<script>alert(1)</script>`, `<img>`, `<svg>`
  - **Event Handlers** (5) - onfocus, onstart, ontoggle
  - **Attribute Breaking** (5) - `">`, `'>`, DOM context
  - **Filter Bypass** (5) - Encoding, obfuscation
  - **DOM-based** (5) - Hash, data URIs, base href
- ✅ **Reflected XSS Detection** - Payload tracking
- ✅ **Category Analysis** - Success rate per technique
- ✅ **Comprehensive Coverage** - All XSS vectors

##### **Mode 4: FOKUS SQLi**
- ✅ **25+ SQLi Payloads** in 5 techniques:
  - **Error-based** (5) - `'`, `"`, OR 1=1
  - **Union-based** (5) - UNION SELECT NULL
  - **Boolean-based** (5) - AND 1=1, AND 1=2
  - **Time-based** (5) - SLEEP(), WAITFOR DELAY
  - **Stacked Queries** (5) - Multi-statement execution
- ✅ **Multi-Database Support**:
  - MySQL, PostgreSQL, MSSQL
  - Oracle, SQLite, Generic
- ✅ **30+ Error Signatures** - Database-specific detection
- ✅ **Technique Analysis** - Vulnerable methods identification

##### **Mode 5: SANS TOP 25**
- ✅ **20 CWE Checks** (SANS Top 25 2023):
  - CWE-787: Out-of-bounds Write
  - CWE-79: Cross-site Scripting
  - CWE-89: SQL Injection
  - CWE-20: Improper Input Validation
  - CWE-125: Out-of-bounds Read
  - CWE-78: OS Command Injection
  - CWE-416: Use After Free
  - CWE-22: Path Traversal
  - CWE-352: CSRF
  - CWE-434: Unrestricted File Upload
  - CWE-862: Missing Authorization
  - CWE-476: NULL Pointer Dereference
  - CWE-287: Improper Authentication
  - CWE-190: Integer Overflow
  - CWE-502: Deserialization
  - CWE-77: Command Injection
  - CWE-119: Buffer Errors
  - CWE-798: Hard-coded Credentials
  - CWE-918: SSRF
  - CWE-306: Missing Authentication
- ✅ **CWE-based Classification** - Industry-standard reporting
- ✅ **Compliance Scan** - SANS/CWE compliance verification

##### **Mode 6: OWASP TOP 10**
- ✅ **OWASP Top 10 2021 Compliance**:
  - **A01**: Broken Access Control
  - **A02**: Cryptographic Failures (HTTPS, HSTS)
  - **A03**: Injection (SQL, NoSQL, OS)
  - **A04**: Insecure Design
  - **A05**: Security Misconfiguration
  - **A06**: Vulnerable Components (jQuery, libs)
  - **A07**: Authentication Failures
  - **A08**: Software & Data Integrity
  - **A09**: Logging & Monitoring Failures
  - **A10**: SSRF
- ✅ **OWASP-Compliant Reports** - Industry-standard format
- ✅ **Risk-based Ranking** - Prioritized findings

##### **Mode 7: CUSTOM SCAN**
- ✅ **12 Selectable Vulnerability Types**:
  1. SQL Injection
  2. Cross-Site Scripting (XSS)
  3. Path Traversal
  4. Command Injection
  5. File Upload
  6. SSRF
  7. XXE
  8. CSRF
  9. Authentication Bypass
  10. Information Disclosure
  11. Security Headers
  12. Sensitive Files
- ✅ **Flexible Selection** - Choose specific tests or all
- ✅ **Custom Profiles** - Tailored security assessments

---

## 💾 Installation

### Method 1: Git Clone (Recommended)

```bash
# Clone repository
git clone https://github.com/DragoniaCompany1/Drgxel-Cybersecurity-Tools
cd Drgxel-Cybersecurity-Tools

# Set executable permission
chmod +x security.py

# Run
python3 security.py
```

### Method 2: Direct Download

```bash
# Download file
wget https://github.com/DragoniaCompany1/Drgxel-Cybersecurity-Tools

# Set permission
chmod +x security.py

# Run
python3 security.py
```

### Method 3: Termux (Android)

```bash
# Update & upgrade
pkg update && pkg upgrade -y

# Install Python
pkg install python -y

# Clone or download
git clone https://github.com/DragoniaCompany1/Drgxel-Cybersecurity-Tools
cd Drgxel-Cybersecurity-Tools

# Run
python security.py
```

### Optional Dependencies

```bash
# For PDF reports (optional)
pip install fpdf

# For graphs in reports (optional)
pip install matplotlib

# For EXIF data extraction (optional - Linux/Termux)
pkg install exiftool  # Termux
apt install libimage-exiftool-perl  # Debian/Ubuntu
```

**Note:** Tool berjalan sempurna **tanpa dependencies** di atas. Dependencies hanya untuk fitur tambahan (PDF reports dengan grafik).

---

## 🚀 Quick Start

### Basic Usage

```bash
# Jalankan tool
python3 drgxel_cyberpack.py

# Tool akan menampilkan:
# - Welcome screen dengan statistics
# - System information
# - Pro tips
# - Main menu
```

### Example Workflows

#### 🎯 Workflow 1: Complete Web Application Assessment

```
1. [Menu 23] LeetScanner → [1] FULL SCAN
   Input: https://target.com
   → Comprehensive vulnerability scan

2. [Menu 7] Active WAF Detector
   Input: https://target.com
   → Identify WAF protection

3. [Menu 8] Cookie & Session Audit
   Input: https://target.com
   → Session security analysis

4. Generate PDF report
   → Professional documentation
```

#### 🔍 Workflow 2: OSINT Investigation

```
1. [Menu 11] Username OSINT Checker
   Input: target_username
   → Search 50+ platforms

2. [Menu 12] Email Breach Checker
   Input: target@email.com
   → Check breach databases

3. [Menu 13] PDF OSINT Toolkit
   Input: /path/to/document.pdf
   → Forensic analysis

4. Export all findings
   → Compile intelligence report
```

#### 🛡️ Workflow 3: Network Security Audit

```
1. [Menu 1] Recon Scanner → [2] Port Scanner
   Input: target.com
   → Identify open services

2. [Menu 15] Anti-DDoS Checker
   → Connection analysis

3. [Menu 17] Process Watchdog
   → Monitor suspicious activity

4. [Menu 18] Network Monitor
   → Active connection tracking
```

#### 🎓 Workflow 4: Compliance Testing

```
1. [Menu 23] LeetScanner → [5] SANS TOP 25
   Input: https://target.com
   → CWE compliance scan

2. [Menu 23] LeetScanner → [6] OWASP TOP 10
   Input: https://target.com
   → OWASP compliance scan

3. Generate reports
   → Compliance documentation
```

---

## 📖 Usage Guide

### Main Menu Navigation

```
╔═══════════════════ MAIN MENU ═══════════════════════╗

  [RECONNAISSANCE]
  [1]  Recon Scanner
  [2]  Advanced Recon (ASN, Reverse IP, DNS, Certificate)
  [3]  Web Vulnerability Scanner
  [4]  Directory Bruteforce

  [ADVANCED TESTING]
  [5]  SQLi Vulnerability Checker
  [6]  XSS Scanner Mini
  [7]  Active WAF Detector
  [8]  Cookie & Session Audit
  [9]  Bruteforce Panel Login
  [10] API Fuzzer

  [OSINT & DARK WEB TOOLS]
  [11] Username OSINT Checker
  [12] Email Breach Checker
  [13] PDF OSINT Toolkit

  [SYSTEM & NETWORK]
  [14] Device Information
  [15] Anti-DDoS Checker
  [16] Malware Scanner
  [17] Process Watchdog
  [18] Network Monitor
  [19] Network Stress Test

  [UTILITIES]
  [20] File Metadata Extractor
  [21] Payload Generator
  [22] DRGXEL SysLog

  [LEETSCANNER]
  [23] LeetScanner - Automated Web Scanner

  [0]  Exit

═════════════════════════════════════════════════════
```

---

## 📊 Report Generation

### PDF Reports

DRGXEL CyberPack dapat menghasilkan **professional PDF reports** dengan fitur:

✅ **Executive Summary**
- Overall risk assessment (Critical/High/Medium/Low)
- Vulnerability statistics
- Risk level description

✅ **Vulnerability Distribution Graph**
- Pie chart dengan breakdown severity
- Color-coded visualization
- Percentage distribution

✅ **Detailed Findings**
- CVSS scores & CVE references
- Vulnerability descriptions
- Impact analysis
- Remediation steps

✅ **Security Recommendations**
- Best practices
- Industry-standard guidelines
- Actionable advice

### Report Locations

```
~/drgxel_reports/
├── leetscanner_target.com_20241202_143022.pdf
├── leetscanner_target.com_20241202_143022.txt
├── vuln_graph.png
└── osint_username_20241202.txt
```

---

## ⚙️ System Requirements

### Minimum Requirements
- **OS:** Linux, macOS, Android (Termux), Windows WSL
- **Python:** 3.6+
- **RAM:** 256 MB
- **Storage:** 10 MB
- **Network:** Internet connection (untuk beberapa fitur)

### Recommended
- **OS:** Kali Linux, Parrot OS, Ubuntu 20.04+, Termux
- **Python:** 3.8+
- **RAM:** 512 MB+
- **Storage:** 50 MB+ (untuk reports)
- **Network:** Stable internet connection

### Tested Platforms
- ✅ Kali Linux 2023.x
- ✅ Ubuntu 20.04/22.04
- ✅ Termux (Android 10+)
- ✅ macOS 12+ (Monterey)
- ✅ Windows 11 WSL2
- ✅ Parrot Security OS

---

## 🎯 Use Cases

### For Penetration Testers
- 🎯 Complete web application security assessment
- 🔍 Automated vulnerability scanning
- 📊 Professional report generation
- 🛡️ Compliance testing (OWASP, SANS)

### For Security Researchers
- 🔬 OSINT investigations
- 🕵️ Digital forensics
- 📄 PDF malware analysis
- 🌐 Network reconnaissance

### For IT Professionals
- 🖥️ System security auditing
- 📡 Network monitoring
- 🛡️ Anti-DDoS protection
- 🦠 Malware detection

### For Bug Bounty Hunters
- 🎯 Automated scanning
- 🔍 Vulnerability discovery
- 📝 Professional reporting
- ⚡ Fast reconnaissance

### For Students & Learners
- 📚 Security concept learning
- 🎓 Hands-on practice
- 🔬 Safe testing environment
- 📖 Real-world techniques

---

## 🛡️ Security & Ethics

### ⚠️ LEGAL DISCLAIMER

```
╔═══════════════════════════════════════════════════════╗
║                  ⚠️  IMPORTANT NOTICE                ║
╠═══════════════════════════════════════════════════════╣
║                                                       ║
║  This tool is for EDUCATIONAL & AUTHORIZED use ONLY   ║
║                                                       ║
║  ✅ LEGAL USE CASES:                                 ║
║     • Authorized penetration testing                 ║
║     • Security research with permission              ║
║     • Bug bounty programs                            ║
║     • Personal system auditing                       ║
║     • Educational purposes (labs, CTFs)              ║
║                                                       ║
║  ❌ ILLEGAL ACTIVITIES:                              ║
║     • Unauthorized system access                     ║
║     • Hacking without permission                     ║
║     • Data theft or manipulation                     ║
║     • Malicious attacks                              ║
║     • Any violation of laws                          ║
║                                                       ║
║  The author is NOT responsible for misuse.           ║
║  Users are solely responsible for their actions.     ║
║                                                       ║
║  By using this tool, you agree to use it ethically   ║
║  and legally. Unauthorized use may result in severe  ║
║  legal consequences including criminal prosecution.  ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
```

### Ethical Guidelines

1. **Always get authorization** before testing any system
2. **Respect rate limits** - tool includes built-in delays
3. **Follow responsible disclosure** for vulnerabilities found
4. **Document everything** - maintain audit trails
5. **Stay within scope** - only test authorized targets
6. **Protect sensitive data** - handle findings responsibly

---

## 🤝 Contributing

Kontribusi sangat diterima! Berikut cara berKontribusi sangat diterima! Berikut cara berkontribusi:

### How to Contribute

1. **Fork** repository ini
2. **Create feature branch**
   ```bash
   git checkout -b feature/AmazingFeature
   ```
3. **Commit changes**
   ```bash
   git commit -m 'Add some AmazingFeature'
   ```
4. **Push to branch**
   ```bash
   git push origin feature/AmazingFeature
   ```
5. **Open Pull Request**

### Contribution Guidelines

#### Code Style
- Follow existing code structure
- Use `### [DRGXEL] MODULE START/END` markers
- Include docstrings for all functions
- Add comments for complex logic
- Use descriptive variable names

#### Module Structure
```python
### [DRGXEL] MODULE START: Your Module Name
def your_module_function():
    """Module description"""
    clear_screen()
    print_banner()
    log_activity("Your module executed")
    
    # Your implementation here
    
    update_stats('Your Module Name', target, vuln_found=False)
    input(f"\n{Colors.OKGREEN}[Press Enter to continue...]{Colors.ENDC}")
### [DRGXEL] MODULE END: Your Module Name
```

#### Testing Requirements
- Test on multiple platforms (Linux, Termux, macOS)
- Ensure no external dependencies added
- Verify error handling works
- Check progress bars and animations
- Test with valid and invalid inputs

#### Documentation
- Update README.md with new features
- Add usage examples
- Include module description
- Document any limitations

### Areas for Contribution

🎯 **High Priority**
- [ ] Additional LeetScanner modes
- [ ] More OSINT platforms
- [ ] Enhanced WAF detection
- [ ] Mobile app testing features
- [ ] API endpoint discovery

🔧 **Medium Priority**
- [ ] GUI version (Tkinter/Qt)
- [ ] Cloud service testing (AWS, Azure, GCP)
- [ ] Container security scanning
- [ ] Wireless security modules
- [ ] Blockchain security testing

📚 **Documentation**
- [ ] Video tutorials
- [ ] Module-specific guides
- [ ] Translation to other languages
- [ ] Best practice examples
- [ ] CTF writeups using DRGXEL

---

## 🐛 Bug Reports & Feature Requests

### Reporting Bugs

Jika menemukan bug, buat issue dengan informasi:

```markdown
**Bug Description:**
Clear description of the bug

**Steps to Reproduce:**
1. Go to '...'
2. Click on '...'
3. Enter '...'
4. See error

**Expected Behavior:**
What should happen

**Actual Behavior:**
What actually happens

**Environment:**
- OS: [e.g., Kali Linux 2023.3]
- Python Version: [e.g., 3.10.5]
- DRGXEL Version: [e.g., 2.0]

**Screenshots/Logs:**
If applicable
```

### Feature Requests

```markdown
**Feature Description:**
Clear description of the feature

**Use Case:**
Why is this feature needed?

**Proposed Implementation:**
How should it work?

**Additional Context:**
Any other relevant information
```

---

## 📚 Documentation

### Official Documentation
- 📖 [User Guide](docs/USER_GUIDE.md)
- 🔧 [Module Reference](docs/MODULES.md)
- 🎯 [Tutorial](docs/TUTORIAL.md)
- 🛡️ [Security Best Practices](docs/SECURITY.md)

### Video Tutorials
- 🎥 [Getting Started](https://youtube.com/drgxel)
- 🎥 [LeetScanner Deep Dive](https://youtube.com/drgxel)
- 🎥 [OSINT Techniques](https://youtube.com/drgxel)

### Blog Posts
- 📝 [Introduction to DRGXEL CyberPack](https://blog.drgxel.com)
- 📝 [Advanced Scanning Techniques](https://blog.drgxel.com)
- 📝 [OSINT with DRGXEL](https://blog.drgxel.com)

---

## 💡 Tips & Tricks

### Performance Optimization

```bash
# Untuk scanning yang lebih cepat, gunakan custom scan
# dengan hanya vulnerability types yang relevan
[Menu 23] → [7] CUSTOM SCAN → Select specific types

# Gunakan HIGH RISK mode untuk quick assessment
[Menu 23] → [2] HIGH RISK
```

### Stealth Scanning

```bash
# LeetScanner sudah include rate limiting
# Untuk stealth lebih tinggi:
1. Gunakan VPN/Proxy
2. Rotate User-Agent (built-in)
3. Test di off-peak hours
4. Use WAF detector first untuk strategi bypass
```

### Report Management

```bash
# Organize reports by project
~/drgxel_reports/
├── project_alpha/
│   ├── scan_20241201.pdf
│   └── rescan_20241215.pdf
├── project_beta/
│   └── initial_scan.pdf
└── personal_audits/
    └── homelab_scan.pdf

# Compress old reports
tar -czf reports_archive_2024.tar.gz ~/drgxel_reports/*_2024*.pdf
```

### Automation Scripts

```bash
# Bash script untuk automated daily scan
#!/bin/bash
TARGETS="target1.com target2.com target3.com"

for target in $TARGETS; do
    echo "Scanning $target..."
    python3 drgxel_cyberpack.py <<EOF
23
1
$target
y
3
EOF
    sleep 300  # 5 min delay between scans
done
```

---

## 🔧 Troubleshooting

### Common Issues

#### 1. **Import Error / Module Not Found**
```bash
# Issue: ModuleNotFoundError
# Solution: Tool uses only built-in modules, check Python version
python3 --version  # Must be 3.6+
```

#### 2. **Permission Denied**
```bash
# Issue: Permission denied when running
# Solution: 
chmod +x drgxel_cyberpack.py
# Or run with python explicitly:
python3 drgxel_cyberpack.py
```

#### 3. **PDF Generation Failed**
```bash
# Issue: PDF reports not generating
# Solution: Install FPDF (optional)
pip install fpdf

# Or use text reports instead (always works)
[Generate Reports] → [2] Generate Text Report
```

#### 4. **Network Timeout Errors**
```bash
# Issue: Timeout during scanning
# Solution: 
# - Check internet connection
# - Target may be blocking requests
# - Use VPN if region-blocked
# - Increase timeout in code (advanced)
```

#### 5. **Termux Storage Issues**
```bash
# Issue: Cannot create reports directory
# Solution: Grant storage permission
termux-setup-storage

# Check available space
df -h
```

### Debug Mode

```bash
# Run with Python verbose mode
python3 -v drgxel_cyberpack.py

# Check logs
cat ~/drgxel_logs.txt

# View statistics
# [Menu 22] DRGXEL SysLog
```

---

## 📈 Roadmap

### Version 2.1 (Q1 2025)
- [ ] GraphQL API testing
- [ ] Enhanced cloud security modules (AWS, Azure, GCP)
- [ ] Docker container scanning
- [ ] Kubernetes security audit
- [ ] Enhanced mobile app testing
- [ ] Real-time collaboration features

### Version 2.5 (Q2 2025)
- [ ] Web-based GUI interface
- [ ] REST API for integration
- [ ] Plugin system architecture
- [ ] Custom wordlist import
- [ ] Machine learning-based detection
- [ ] Advanced evasion techniques

### Version 3.0 (Q3 2025)
- [ ] Full GUI application (Qt/Electron)
- [ ] Distributed scanning
- [ ] Database integration (PostgreSQL)
- [ ] Team collaboration features
- [ ] CI/CD pipeline integration
- [ ] Enterprise features

---

## 🏆 Hall of Fame

### Contributors
Special thanks to all contributors who made DRGXEL CyberPack possible!

<!-- Contributors will be automatically added -->

### Bug Hunters
Thanks to security researchers who reported vulnerabilities:

<!-- Bug reporters will be listed here -->

---

## 📞 Support & Community

### Get Help

- 🐛 **Bug Reports:** [GitHub Issues](https://github.com/dragoniacompany1/Drgxel-Cybersecurity-Tools/issues)
- 💡 **Feature Requests:** [GitHub Discussions](https://github.com/dragoniacompany1/Drgxel-Cybersecurity-Tools/discussions)
- 📧 **Email:** lutpilarsi614@gmail.com
- 💬 **Telegram:** [@DRGXELCyberPack](https://t.me/drgxelByteZone)
- 🐦 **WhatsApp:** [DEXEL SCRIPTER](https://whatsapp.com/channel/0029Vb6i6XmFi8xVkZ7QkO40)

### Community

- 🌐 **Website:** [https://github.com/dragoniacompany1]
- 🎓 **ch WhatsAp:** [DRGXEL Community](https://whatsapp.com/channel/0029Vb6i6XmFi8xVkZ7QkO40)
- 📺 **YouTube:** [DRGXEL Channel](https://youtube.com/drgxByteZone)

---

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=dragoniacompany1/Drgxel-Cybersecurity-Tools&type=Date)](https://star-history.com/#dragoniacompany1/Drgxel-Cybersecurity-Tools&Date)

---

## 📜 License

```
MIT License

Copyright (c) 2024 DRGXEL Security Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🙏 Acknowledgments

### Inspired By
- **Metasploit Framework** - Module architecture
- **Nmap** - Network scanning techniques
- **Burp Suite** - Web application testing
- **OWASP ZAP** - Security automation
- **LeetScanner Bot** - Telegram bot interface

### Technologies
- **Python 3** - Core language
- **FPDF** - PDF report generation (optional)
- **Matplotlib** - Graph visualization (optional)

### Security Standards
- **OWASP Top 10 2021** - Web application security risks
- **SANS Top 25** - Most dangerous software weaknesses
- **CWE/SANS** - Common weakness enumeration
- **CVSS 3.1** - Vulnerability scoring system

### Community
Special thanks to the information security community for continuous feedback and support.

---

## 📊 Statistics

<div align="center">

![GitHub stars](https://img.shields.io/github/stars/dragoniacompany1/Drgxel-Cybersecurity-Tools?style=social)
![GitHub forks](https://img.shields.io/github/forks/dragoniacompany1/Drgxel-Cybersecurity-Tools?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/dragoniacompany1/Drgxel-Cybersecurity-Tools?style=social)

![GitHub issues](https://img.shields.io/github/issues/dragoniacompany1/Drgxel-Cybersecurity-Tools)
![GitHub pull requests](https://img.shields.io/github/issues-pr/dragoniacompany1/Drgxel-Cybersecurity-Tools)
![GitHub last commit](https://img.shields.io/github/last-commit/dragoniacompany1/Drgxel-Cybersecurity-Tools)

![GitHub code size](https://img.shields.io/github/languages/code-size/dragoniacompany1/Drgxel-Cybersecurity-Tools)
![Lines of code](https://img.shields.io/tokei/lines/github/dragoniacompany1/Drgxel-Cybersecurity-Tools)

</div>

---

## 🎯 Quick Reference

### Command Cheatsheet

```bash
# Installation
git clone https://github.com/DragoniaCompany1/Drgxel-Cybersecurity-Tools
cd drgxel-cyberpack
chmod +x security.py

# Run
python3 drgxel_cyberpack.py

# Quick scan
# Menu [23] → [1] → https://target.com → Generate report

# OSINT
# Menu [11] → username → View results

# System audit
# Menu [14] → [15] → [16] → Complete check

# View logs
# Menu [22] → View last 50 entries

# Export everything
# All reports saved to: ~/drgxel_reports/
# All logs saved to: ~/drgxel_logs.txt
```

---

<div align="center">

## 💖 Support the Project

If you find DRGXEL CyberPack useful, please consider:

⭐ **Star this repository**  
🐛 **Report bugs**  
💡 **Suggest features**  
📢 **Share with others**  
☕ **Buy me a coffee** - [Gopay](085760860061)

---

**Made with ❤️ by DRGXEL Security Team**

*Stay Safe, Stay Secure!* 🛡️

[⬆ Back to Top](#-drgxel-cyberpack-v20---release-edition)

---

### 📅 Last Updated: December 2025
### 🏷️ Version: 2.0 - Release Edition
### 🔖 Build: 20241202

</div>
