"""
dseedeep — Core Scan Engine
Orchestrates all scan modules based on selected mode and arguments.
"""

import time
import json
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel

from core.logger import console, ScanLogger
from core.config import Config
from core.reporter import Reporter


class ScanEngine:
    """
    Central orchestrator for dseedeep.
    Determines which modules to run based on mode + flags,
    executes them, collects findings, and generates reports.
    """

    def __init__(self, target: str, config: Config, args):
        self.target  = target
        self.config  = config
        self.args    = args
        self.log     = ScanLogger("ENGINE", verbose=args.verbose)
        self.results = {
            "meta": {
                "target":    target,
                "mode":      args.mode,
                "started":   datetime.utcnow().isoformat() + "Z",
                "finished":  None,
                "version":   "1.0",
            },
            "dns":          {},
            "whois":        {},
            "subdomains":   [],
            "certs":        [],
            "ports":        [],
            "banners":      {},
            "osint":        {},
            "web":          {},
            "vuln":         [],
            "apis":         {},
        }

        # Setup output dir
        safe = target.replace("/", "_").replace(":", "_")
        out_base = Path(config.get("output_dir", "reports"))
        self.out_dir = out_base / safe / datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.log.info(f"Output directory: [cyan]{self.out_dir}[/cyan]")

    # ─────────────────────────────────────────────────────────────────
    def run(self):
        start = time.time()
        mode = self.args.mode

        self.log.section(f"Starting {mode.upper()} scan against {self.target}")

        task_map = {
            "recon":  self._run_recon,
            "active": self._run_active,
            "osint":  self._run_osint,
            "web":    self._run_web,
            "vuln":   self._run_vuln,
            "api":    self._run_apis,
            "full":   self._run_full,
        }

        runner = task_map.get(mode, self._run_recon)
        runner()

        elapsed = time.time() - start
        self.results["meta"]["finished"] = datetime.utcnow().isoformat() + "Z"
        self.results["meta"]["elapsed_s"] = round(elapsed, 2)

        self._print_summary(elapsed)

        # Generate reports
        reporter = Reporter(self.results, self.out_dir, self.args.format)
        reporter.generate()

    # ─────────────────────────────────────────────────────────────────
    def _run_recon(self):
        from modules.recon.dns       import DNSEnum
        from modules.recon.whois_mod import WhoisLookup
        from modules.recon.subdomain import SubdomainEnum
        from modules.recon.certs     import CertTransparency
        from modules.recon.wayback   import WaybackEnum

        steps = []
        if not self.args.no_dns:
            steps.append(("DNS Enumeration",       lambda: DNSEnum(self.target, self.config).run()))
        if not self.args.no_whois:
            steps.append(("WHOIS Lookup",          lambda: WhoisLookup(self.target, self.config).run()))
        if not self.args.no_subdomains:
            steps.append(("Subdomain Discovery",   lambda: SubdomainEnum(self.target, self.config, self.args).run()))
        if not self.args.no_certs:
            steps.append(("Certificate Transparency", lambda: CertTransparency(self.target, self.config).run()))
        if self.args.wayback:
            steps.append(("Wayback Machine",       lambda: WaybackEnum(self.target, self.config).run()))

        self._execute_steps(steps, {
            "DNS Enumeration":         "dns",
            "WHOIS Lookup":            "whois",
            "Subdomain Discovery":     "subdomains",
            "Certificate Transparency":"certs",
            "Wayback Machine":         "osint",
        })

    def _run_active(self):
        from modules.recon.portscan import PortScanner
        from modules.recon.banner   import BannerGrab
        from modules.recon.dns      import DNSEnum

        steps = [("DNS Enumeration", lambda: DNSEnum(self.target, self.config).run())]
        steps.append(("Port Scan", lambda: PortScanner(self.target, self.config, self.args).run()))
        if self.args.banner:
            steps.append(("Banner Grabbing", lambda: BannerGrab(self.target, self.results.get("ports", []), self.config).run()))

        self._execute_steps(steps, {
            "DNS Enumeration": "dns",
            "Port Scan":       "ports",
            "Banner Grabbing": "banners",
        })

    def _run_osint(self):
        from modules.osint.emails      import EmailHarvester
        from modules.osint.certs       import CertTransparency
        from modules.osint.google_dork import GoogleDorks

        steps = [("Certificate Transparency", lambda: CertTransparency(self.target, self.config).run())]
        if self.args.emails:
            steps.append(("Email Harvesting",  lambda: EmailHarvester(self.target, self.config).run()))
        if self.args.google_dorks:
            steps.append(("Google Dorks",      lambda: GoogleDorks(self.target, self.config).run()))
        if self.args.wayback:
            from modules.recon.wayback import WaybackEnum
            steps.append(("Wayback Machine",   lambda: WaybackEnum(self.target, self.config).run()))

        self._execute_steps(steps, {
            "Certificate Transparency": "certs",
            "Email Harvesting":         "osint",
            "Google Dorks":             "osint",
            "Wayback Machine":          "osint",
        })

    def _run_web(self):
        from modules.web.headers    import HeaderAnalyzer
        from modules.web.tech       import TechDetect
        from modules.web.waf        import WAFDetect
        from modules.web.crawler    import WebCrawler

        target_url = self.target if self.target.startswith("http") else f"https://{self.target}"
        steps = [
            ("HTTP Headers",        lambda: HeaderAnalyzer(target_url, self.config).run()),
            ("Technology Detect",   lambda: TechDetect(target_url, self.config).run()),
            ("WAF Detection",       lambda: WAFDetect(target_url, self.config).run()),
        ]
        if self.args.crawl:
            steps.append(("Web Crawler",    lambda: WebCrawler(target_url, self.config, self.args).run()))

        self._execute_steps(steps, {
            "HTTP Headers":       "web",
            "Technology Detect":  "web",
            "WAF Detection":      "web",
            "Web Crawler":        "web",
        })

    def _run_vuln(self):
        from modules.vuln.ssl_check    import SSLChecker
        from modules.vuln.header_vuln  import HeaderVulnChecker
        from modules.vuln.nikto_wrap   import NiktoScanner
        from modules.vuln.nuclei_wrap  import NucleiScanner

        target_url = self.target if self.target.startswith("http") else f"https://{self.target}"
        steps = [
            ("SSL/TLS Analysis",        lambda: SSLChecker(self.target, self.config).run()),
            ("Security Headers",        lambda: HeaderVulnChecker(target_url, self.config).run()),
        ]
        if self.args.nikto:
            steps.append(("Nikto Scanner",      lambda: NiktoScanner(target_url, self.config).run()))
        if self.args.nuclei:
            steps.append(("Nuclei Scanner",     lambda: NucleiScanner(self.target, self.config, self.args).run()))

        self._execute_steps(steps, {
            "SSL/TLS Analysis":   "vuln",
            "Security Headers":   "vuln",
            "Nikto Scanner":      "vuln",
            "Nuclei Scanner":     "vuln",
        })

    def _run_apis(self):
        """Run all enabled API lookups."""
        from apis.api_manager import APIManager
        mgr = APIManager(self.target, self.config, self.args)
        api_results = mgr.run_all()
        self.results["apis"].update(api_results)

    def _run_full(self):
        """Run every module — the full kitchen sink."""
        self._run_recon()
        self._run_active()
        self._run_osint()
        self._run_web()
        self._run_vuln()
        self._run_apis()

    # ─────────────────────────────────────────────────────────────────
    def _execute_steps(self, steps, key_map):
        """Execute a list of (name, callable) steps with progress display."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            for name, fn in steps:
                task = progress.add_task(f"{name}...", total=None)
                try:
                    result = fn()
                    dest = key_map.get(name)
                    if dest and result:
                        if isinstance(self.results[dest], list):
                            if isinstance(result, list):
                                self.results[dest].extend(result)
                            else:
                                self.results[dest].append(result)
                        elif isinstance(self.results[dest], dict):
                            if isinstance(result, dict):
                                self.results[dest].update(result)
                    progress.update(task, description=f"[green]✓[/green] {name}", completed=1, total=1)
                except Exception as e:
                    progress.update(task, description=f"[red]✗[/red] {name}: {e}", completed=1, total=1)

    # ─────────────────────────────────────────────────────────────────
    def _print_summary(self, elapsed: float):
        """Print a final summary table."""
        console.print()
        console.rule("[bold green]Scan Complete[/bold green]")

        table = Table(title="Results Summary", border_style="cyan", show_header=True)
        table.add_column("Category",  style="bold cyan",  width=25)
        table.add_column("Findings",  style="bold white", justify="right", width=12)
        table.add_column("Details",   style="dim white")

        dns_r    = self.results.get("dns", {})
        sub_r    = self.results.get("subdomains", [])
        cert_r   = self.results.get("certs", [])
        port_r   = self.results.get("ports", [])
        vuln_r   = self.results.get("vuln", [])
        api_r    = self.results.get("apis", {})
        osint_r  = self.results.get("osint", {})

        table.add_row("DNS Records",       str(len(dns_r)),    ", ".join(list(dns_r.keys())[:5]))
        table.add_row("Subdomains",        str(len(sub_r)),    f"{sub_r[:3]}"[:60] if sub_r else "—")
        table.add_row("Certificates",      str(len(cert_r)),   f"crt.sh results")
        table.add_row("Open Ports",        str(len(port_r)),   ", ".join(str(p.get("port","")) for p in port_r[:8]))
        table.add_row("Vulns / Findings",  str(len(vuln_r)),   "See report for details")
        table.add_row("API Sources",       str(len(api_r)),    ", ".join(api_r.keys())[:60])
        table.add_row("OSINT Findings",    str(sum(len(v) if isinstance(v, list) else 1 for v in osint_r.values())), "—")

        console.print(table)
        console.print(f"\n[bold green]⏱  Elapsed:[/bold green] {elapsed:.1f}s  |  "
                      f"[bold cyan]📁 Report:[/bold cyan] {self.out_dir}")
