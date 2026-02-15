#!/usr/bin/env python3
"""
██████╗ ███████╗███████╗███████╗██████╗ ███████╗███████╗██████╗
██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗
██║  ██║███████╗█████╗  █████╗  ██║  ██║█████╗  █████╗  ██████╔╝
██║  ██║╚════██║██╔══╝  ██╔══╝  ██║  ██║██╔══╝  ██╔══╝  ██╔═══╝
██████╔╝███████║███████╗███████╗██████╔╝███████╗███████╗██║
╚═════╝ ╚══════╝╚══════╝╚══════╝╚═════╝ ╚══════╝╚══════╝╚═╝

dseedeep v1.0 — Advanced Security Reconnaissance Framework
Author  : Security Research
License : MIT (for authorized testing ONLY)
"""

import sys
import argparse
import signal
from pathlib import Path

# Ensure local imports work
sys.path.insert(0, str(Path(__file__).parent))

from core.engine import ScanEngine
from core.config import Config
from core.logger import banner, console
from rich.panel import Panel
from rich.text import Text


def parse_args():
    parser = argparse.ArgumentParser(
        prog="dseedeep",
        description="Advanced Security Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SCAN MODES:
  recon       Full passive reconnaissance (DNS, WHOIS, subdomains, certs)
  active      Active scanning (ports, banners, web tech)
  osint       OSINT gathering (emails, pastes, code leaks)
  web         Web application analysis (headers, WAF, crawl, screenshot)
  vuln        Vulnerability surface mapping (Nikto, Nuclei, SSL)
  api         API intelligence (Shodan, VT, Censys, FOFA, ZoomEye…)
  full        All modules combined

EXAMPLES:
  dseedeep -t example.com -m recon
  dseedeep -t 192.168.1.1 -m active --ports 1-65535
  dseedeep -t example.com -m full --api-keys config.yaml
  dseedeep -t example.com -m web --screenshot --crawl-depth 3
  dseedeep -t example.com -m osint --emails --pastebin
  dseedeep -t 10.0.0.0/24 -m active --stealth
        """
    )

    # Target
    target_group = parser.add_argument_group("Target")
    target_group.add_argument("-t", "--target",    required=True, help="Target (domain/IP/CIDR/URL)")
    target_group.add_argument("--target-file",     help="File with multiple targets (one per line)")

    # Mode
    mode_group = parser.add_argument_group("Scan Mode")
    mode_group.add_argument("-m", "--mode",
        choices=["recon", "active", "osint", "web", "vuln", "api", "full"],
        default="recon", help="Scan mode (default: recon)")

    # Recon options
    recon_group = parser.add_argument_group("Reconnaissance Options")
    recon_group.add_argument("--no-dns",           action="store_true", help="Skip DNS enumeration")
    recon_group.add_argument("--no-whois",         action="store_true", help="Skip WHOIS lookup")
    recon_group.add_argument("--no-subdomains",    action="store_true", help="Skip subdomain brute-force")
    recon_group.add_argument("--no-certs",         action="store_true", help="Skip certificate transparency")
    recon_group.add_argument("--wordlist",         default=None, help="Custom subdomain wordlist")
    recon_group.add_argument("--depth",            type=int, default=2, help="Subdomain brute-force depth (default: 2)")

    # Active options
    active_group = parser.add_argument_group("Active Scan Options")
    active_group.add_argument("--ports",           default="1-1024", help="Port range (default: 1-1024, use 'all' for 1-65535)")
    active_group.add_argument("--stealth",         action="store_true", help="Stealth mode (slower, quieter)")
    active_group.add_argument("--banner",          action="store_true", help="Enable banner grabbing")
    active_group.add_argument("--udp",             action="store_true", help="Include UDP scan")
    active_group.add_argument("--os-detect",       action="store_true", help="OS detection")
    active_group.add_argument("--service-version", action="store_true", help="Service version detection")

    # OSINT options
    osint_group = parser.add_argument_group("OSINT Options")
    osint_group.add_argument("--emails",           action="store_true", help="Harvest email addresses")
    osint_group.add_argument("--pastebin",         action="store_true", help="Search Pastebin/Pastecn leaks")
    osint_group.add_argument("--github",           action="store_true", help="Search GitHub for exposed secrets")
    osint_group.add_argument("--google-dorks",     action="store_true", help="Run Google dork queries")
    osint_group.add_argument("--linkedin",         action="store_true", help="LinkedIn employee enumeration")
    osint_group.add_argument("--wayback",          action="store_true", help="Wayback Machine URL discovery")

    # Web options
    web_group = parser.add_argument_group("Web Analysis Options")
    web_group.add_argument("--screenshot",         action="store_true", help="Take screenshots (requires cutycapt/gowitness)")
    web_group.add_argument("--crawl",              action="store_true", help="Crawl web application")
    web_group.add_argument("--crawl-depth",        type=int, default=2, help="Crawler depth (default: 2)")
    web_group.add_argument("--waf",                action="store_true", help="WAF detection")
    web_group.add_argument("--tech",               action="store_true", help="Technology fingerprinting")
    web_group.add_argument("--js-files",           action="store_true", help="Extract and analyze JS files")
    web_group.add_argument("--api-endpoints",      action="store_true", help="Discover API endpoints")
    web_group.add_argument("--cors",               action="store_true", help="CORS misconfiguration check")

    # Vuln options
    vuln_group = parser.add_argument_group("Vulnerability Scan Options")
    vuln_group.add_argument("--nikto",             action="store_true", help="Run Nikto web scanner")
    vuln_group.add_argument("--nuclei",            action="store_true", help="Run Nuclei template scanner")
    vuln_group.add_argument("--nuclei-tags",       default="cve,exposure,misconfiguration", help="Nuclei template tags")
    vuln_group.add_argument("--ssl",               action="store_true", help="Deep SSL/TLS analysis")
    vuln_group.add_argument("--headers-vuln",      action="store_true", help="Security header analysis")
    vuln_group.add_argument("--sqli",              action="store_true", help="Basic SQLi surface test")
    vuln_group.add_argument("--xss",               action="store_true", help="Basic XSS surface test")

    # API options
    api_group = parser.add_argument_group("API Intelligence Options")
    api_group.add_argument("--shodan",             action="store_true", help="Shodan intelligence lookup")
    api_group.add_argument("--virustotal",         action="store_true", help="VirusTotal intelligence lookup")
    api_group.add_argument("--censys",             action="store_true", help="Censys certificate/host search")
    api_group.add_argument("--securitytrails",     action="store_true", help="SecurityTrails DNS history")
    api_group.add_argument("--hunter",             action="store_true", help="Hunter.io email discovery")
    api_group.add_argument("--urlscan",            action="store_true", help="URLScan.io page analysis")
    api_group.add_argument("--abuseipdb",          action="store_true", help="AbuseIPDB reputation check")
    api_group.add_argument("--fofa",               action="store_true", help="FOFA cyberspace search")
    api_group.add_argument("--zoomeye",            action="store_true", help="ZoomEye host search")
    api_group.add_argument("--greynoise",          action="store_true", help="GreyNoise noise IP check")
    api_group.add_argument("--binaryedge",         action="store_true", help="BinaryEdge host intelligence")
    api_group.add_argument("--leakix",             action="store_true", help="LeakIX exposed service search")
    api_group.add_argument("--ipinfo",             action="store_true", help="ipinfo.io geolocation/ASN")
    api_group.add_argument("--haveibeenpwned",     action="store_true", help="HaveIBeenPwned email breach check")
    api_group.add_argument("--all-apis",           action="store_true", help="Enable all configured APIs")

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("-o", "--output",    default=None, help="Output directory (default: reports/<target>)")
    output_group.add_argument("--format",
        choices=["txt", "json", "html", "all"],
        default="all", help="Report format (default: all)")
    output_group.add_argument("--no-color",        action="store_true", help="Disable colored output")
    output_group.add_argument("-v", "--verbose",   action="store_true", help="Verbose output")
    output_group.add_argument("-q", "--quiet",     action="store_true", help="Quiet mode (minimal output)")

    # Config
    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument("--api-keys",        default="config.yaml", help="API keys config file (default: config.yaml)")
    config_group.add_argument("--threads",         type=int, default=20, help="Thread count (default: 20)")
    config_group.add_argument("--timeout",         type=int, default=10, help="Request timeout seconds (default: 10)")
    config_group.add_argument("--rate-limit",      type=float, default=0.0, help="Delay between requests in seconds")
    config_group.add_argument("--proxy",           default=None, help="Proxy URL (e.g. http://127.0.0.1:8080)")
    config_group.add_argument("--user-agent",      default=None, help="Custom User-Agent string")

    return parser.parse_args()


def signal_handler(sig, frame):
    console.print("\n\n[bold red]⚠  Scan interrupted by user. Saving partial results...[/bold red]")
    sys.exit(0)


def main():
    signal.signal(signal.SIGINT, signal_handler)
    args = parse_args()

    if not args.quiet:
        banner()

    # Load config
    cfg = Config(args.api_keys)
    cfg.apply_args(args)

    if not args.quiet:
        console.print(Panel.fit(
            f"[bold cyan]Target:[/bold cyan] {args.target}\n"
            f"[bold cyan]Mode  :[/bold cyan] {args.mode.upper()}\n"
            f"[bold cyan]Threads:[/bold cyan] {args.threads}  |  "
            f"[bold cyan]Timeout:[/bold cyan] {args.timeout}s  |  "
            f"[bold cyan]Stealth:[/bold cyan] {'ON' if args.stealth else 'OFF'}",
            title="[bold yellow]⚙  dseedeep Configuration",
            border_style="yellow"
        ))

    # Run engine
    engine = ScanEngine(target=args.target, config=cfg, args=args)
    engine.run()


if __name__ == "__main__":
    main()
