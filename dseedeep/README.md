# ⚡ dseedeep

```
██████╗ ███████╗███████╗███████╗██████╗ ███████╗███████╗██████╗
██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗
██║  ██║███████╗█████╗  █████╗  ██║  ██║█████╗  █████╗  ██████╔╝
██║  ██║╚════██║██╔══╝  ██╔══╝  ██║  ██║██╔══╝  ██╔══╝  ██╔═══╝
██████╔╝███████║███████╗███████╗██████╔╝███████╗███████╗██║
╚═════╝ ╚══════╝╚══════╝╚══════╝╚═════╝ ╚══════╝╚══════╝╚═╝
```

**Advanced Security Reconnaissance Framework** — Modular, API-rich, faster than Sn1per.

> ⚠️ **For authorized penetration testing and security research ONLY.**
> Unauthorized scanning is illegal. Always obtain written permission.

---

## 🔥 What Makes dseedeep Different

| Feature | Sn1per | dseedeep |
|---|---|---|
| API Integrations | 3-4 | **14** |
| No Metasploit required | ✗ | ✅ |
| No Nessus required | ✗ | ✅ |
| No OpenVAS required | ✗ | ✅ |
| Standalone Python | ✗ | ✅ |
| Interactive HTML reports | Limited | ✅ Full |
| WAF Detection | Basic | ✅ 16 WAFs |
| Tech Fingerprinting | Limited | ✅ 25+ signatures |
| Google Dorks | No | ✅ 24 categories |
| FOFA / ZoomEye support | No | ✅ |
| GreyNoise integration | No | ✅ |
| Real-time rich terminal | No | ✅ |

---

## 🧩 Modules

### 🔭 RECON — Passive Reconnaissance
- **DNS Enumeration** — A, AAAA, MX, NS, TXT, SOA, CNAME, CAA, SRV, DMARC, SPF + AXFR zone transfer attempt
- **WHOIS Lookup** — Registrar, dates, nameservers, org, registrant
- **Subdomain Discovery** — Brute-force (500+ wordlist) + crt.sh + HackerTarget + Wayback passive
- **Certificate Transparency** — crt.sh full log mining
- **Wayback Machine** — URL and parameter endpoint discovery

### ⚡ ACTIVE — Active Scanning
- **Port Scanner** — nmap wrapper (SYN, service version, OS detection) + raw socket fallback
- **Banner Grabbing** — HTTP, SSH, FTP, SMTP service banner extraction
- **Stealth Mode** — Slower timing, randomized ordering

### 🕵️ OSINT — Open Source Intelligence
- **Email Harvesting** — Hunter.io API + web scraping + crt.sh extraction
- **Google Dorks** — 24 pre-built dork categories (admin panels, config files, DB files, creds...)
- **Wayback Machine** — URL discovery, parameter endpoints

### 🌐 WEB — Web Application Analysis
- **HTTP Header Analysis** — Scores 9 security headers with severity ratings
- **Technology Fingerprinting** — Detects 25+ technologies (CMS, frameworks, servers, CDN, languages)
- **WAF Detection** — Fingerprints 16 WAFs + behavioral detection via probes
- **Web Crawler** — Discovers pages, JS files, API endpoints, forms

### 🔴 VULN — Vulnerability Surface
- **SSL/TLS Analyzer** — Certificate validity, expiry, weak protocols/ciphers, chain + testssl.sh integration
- **Security Header Vulns** — Maps missing headers to severity ratings
- **Nikto** — Web server vulnerability scanner (wrapper)
- **Nuclei** — Template-based scanner (cve, exposure, misconfiguration tags)

### ⚡ API INTELLIGENCE — 14 Sources

| # | API | What it finds |
|---|---|---|
| 1 | **Shodan** | Exposed services, banners, CVEs, org/ASN |
| 2 | **VirusTotal** | Malware detections, reputation, passive DNS |
| 3 | **Censys** | Certificate/host data, TLS fingerprints |
| 4 | **SecurityTrails** | DNS history, subdomain enumeration, WHOIS history |
| 5 | **Hunter.io** | Email addresses, patterns, MX records |
| 6 | **URLScan.io** | Page screenshot, DOM, loaded resources, IPs |
| 7 | **AbuseIPDB** | Abuse reports, confidence score, ISP |
| 8 | **FOFA** | Chinese cyberspace search, services, titles |
| 9 | **ZoomEye** | Global host/service mapping |
| 10 | **GreyNoise** | Internet noise classification, scanner ID |
| 11 | **BinaryEdge** | Attack surface, exposed service intelligence |
| 12 | **LeakIX** | Exposed services, data leak detection |
| 13 | **IPInfo** | Geolocation, ASN, abuse contact |
| 14 | **HaveIBeenPwned** | Email/domain breach history |

---

## 🚀 Installation

```bash
# Clone
git clone https://github.com/swordenkisk/dseedeep.git
cd dseedeep

# Install Python dependencies
pip3 install -r requirements.txt

# Copy and configure API keys
cp config.yaml.example config.yaml
nano config.yaml

# Make executable
chmod +x dseedeep.py

# Optional: system-wide
sudo ln -s $(pwd)/dseedeep.py /usr/local/bin/dseedeep

# Optional external tools (enhance scan depth)
# Nuclei:
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# Nikto:
sudo apt-get install nikto
# nmap:
sudo apt-get install nmap
# testssl.sh:
git clone https://github.com/drwetter/testssl.sh.git
```

---

## 🎯 Usage Examples

```bash
# Full passive recon
python3 dseedeep.py -t example.com -m recon

# Active port scan (all ports, stealth)
python3 dseedeep.py -t 192.168.1.1 -m active --ports all --stealth

# OSINT: emails, dorks, wayback
python3 dseedeep.py -t example.com -m osint --emails --google-dorks --wayback

# Web application analysis
python3 dseedeep.py -t example.com -m web --screenshot --crawl --crawl-depth 3

# Vulnerability surface (Nuclei + SSL + headers)
python3 dseedeep.py -t example.com -m vuln --nuclei --ssl --nikto

# Full API intelligence sweep
python3 dseedeep.py -t example.com -m api --all-apis

# Full kitchen sink
python3 dseedeep.py -t example.com -m full --all-apis --emails --crawl --nuclei --ssl

# Custom output, proxy, and threads
python3 dseedeep.py -t example.com -m full \
  --output /tmp/myreport \
  --proxy http://127.0.0.1:8080 \
  --threads 30 \
  --format html

# Verbose mode
python3 dseedeep.py -t example.com -m recon -v
```

---

## 📁 Output

Reports are automatically saved to `reports/<target>/<timestamp>/`:

```
reports/
└── example.com/
    └── 20240215_143022/
        ├── dseedeep_example.com.json    ← Full structured data
        ├── dseedeep_example.com.txt     ← Human-readable text
        └── dseedeep_example.com.html    ← Interactive HTML dashboard
```

The **HTML report** features:
- Dark cyberpunk theme
- Severity-colored vulnerability table
- DNS, WHOIS, subdomains, ports sections
- API intelligence cards per source
- WAF + technology detection display
- Clickable Google dork links

---

## ⚙️ Configuration

```yaml
# config.yaml
api_keys:
  shodan:          "your-key"
  virustotal:      "your-key"
  censys_id:       "your-id"
  censys_secret:   "your-secret"
  securitytrails:  "your-key"
  hunter:          "your-key"
  urlscan:         "your-key"
  abuseipdb:       "your-key"
  fofa_email:      "you@mail.com"
  fofa_key:        "your-key"
  zoomeye:         "your-key"
  greynoise:       "your-key"
  binaryedge:      "your-key"
  leakix:          "your-key"
  ipinfo:          "your-key"
  haveibeenpwned:  "your-key"

settings:
  threads:    20
  timeout:    10
  rate_limit: 0.0
```

Or use environment variables:
```bash
export DSEEDEEP_SHODAN="your-key"
export DSEEDEEP_VIRUSTOTAL="your-key"
export DSEEDEEP_CENSYS_ID="your-id"
export DSEEDEEP_CENSYS_SECRET="your-secret"
# etc.
```

---

## 🗂️ Project Structure

```
dseedeep/
├── dseedeep.py              ← Main entry point / CLI
├── config.yaml.example      ← API keys template
├── requirements.txt
│
├── core/
│   ├── engine.py            ← Scan orchestrator
│   ├── config.py            ← Configuration manager
│   ├── logger.py            ← Rich terminal output
│   └── reporter.py          ← TXT/JSON/HTML report generator
│
├── modules/
│   ├── recon/
│   │   ├── dns.py           ← DNS record enumeration
│   │   ├── whois_mod.py     ← WHOIS lookup
│   │   ├── subdomain.py     ← Subdomain discovery
│   │   ├── certs.py         ← Certificate transparency
│   │   ├── portscan.py      ← Port scanner (nmap + socket)
│   │   ├── banner.py        ← Banner grabbing
│   │   └── wayback.py       ← Wayback Machine URLs
│   ├── osint/
│   │   ├── emails.py        ← Email harvesting
│   │   ├── google_dork.py   ← Google dork generator
│   │   └── certs.py         ← Alias
│   ├── web/
│   │   ├── headers.py       ← HTTP header analyzer
│   │   ├── tech.py          ← Technology fingerprinting
│   │   ├── waf.py           ← WAF detection
│   │   └── crawler.py       ← Web crawler
│   └── vuln/
│       ├── ssl_check.py     ← SSL/TLS deep analysis
│       ├── header_vuln.py   ← Security header vulns
│       ├── nikto_wrap.py    ← Nikto wrapper
│       └── nuclei_wrap.py   ← Nuclei wrapper
│
└── apis/
    ├── api_manager.py       ← API orchestrator
    ├── shodan_api.py
    ├── virustotal_api.py
    ├── censys_api.py
    ├── securitytrails_api.py
    ├── hunter_api.py
    ├── urlscan_api.py
    ├── abuseipdb_api.py
    ├── fofa_api.py
    ├── zoomeye_api.py
    ├── greynoise_api.py
    ├── binaryedge_api.py
    ├── leakix_api.py
    ├── ipinfo_api.py
    └── hibp_api.py
```

---

## 🔒 Legal & Ethics

- **Only scan targets you own or have explicit written authorization to test.**
- This tool is for professional penetration testers and security researchers.
- The authors accept no liability for misuse.
- Respect rate limits on all third-party APIs.
- Shodan, VirusTotal, Censys and others have terms of service — comply with them.

---

## 📄 License

MIT License — See [LICENSE](LICENSE)

---

*dseedeep — See deeper.*
