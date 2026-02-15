"""
dseedeep — API Intelligence Manager
Coordinates all 13 external API integrations with rate limiting and error handling.
"""
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.logger import ScanLogger, console
from rich.table import Table


class APIManager:
    """
    Runs all enabled API lookups concurrently and merges results.

    Supported APIs:
      1.  Shodan         — exposed services, banners, vulns
      2.  VirusTotal     — reputation, detections, passive DNS
      3.  Censys         — certificates, protocols, TLS
      4.  SecurityTrails — DNS history, subdomains, WHOIS history
      5.  Hunter.io      — email discovery, company intel
      6.  URLScan.io     — screenshot, DOM analysis, page intel
      7.  AbuseIPDB      — abuse reports, reputation score
      8.  FOFA           — Chinese cyberspace search engine
      9.  ZoomEye        — global cyberspace mapping
      10. GreyNoise      — internet noise classification
      11. BinaryEdge     — attack surface, exposed services
      12. LeakIX         — exposed services and data leaks
      13. ipinfo.io      — geolocation, ASN, organization
      14. HaveIBeenPwned — email breach detection
    """

    def __init__(self, target: str, config, args=None):
        self.target = target
        self.config = config
        self.args   = args
        self.log    = ScanLogger("APIs", config.get("verbose", False))

    def run_all(self) -> dict:
        """Run all configured/enabled API lookups."""
        self.log.section("API Intelligence Gathering")
        jobs = self._build_jobs()

        if not jobs:
            self.log.warn("No APIs enabled. Set --all-apis or add keys to config.yaml")
            return {}

        self.log.info(f"Running {len(jobs)} API lookups concurrently…")
        results = {}

        with ThreadPoolExecutor(max_workers=min(len(jobs), 8)) as ex:
            future_map = {ex.submit(fn): name for name, fn in jobs}
            for future in as_completed(future_map):
                name = future_map[future]
                try:
                    result = future.result(timeout=30)
                    if result:
                        results[name] = result
                        self.log.success(f"{name} completed")
                except Exception as e:
                    self.log.error(f"{name} failed: {e}")

        self._print_api_summary(results)
        return results

    def _build_jobs(self) -> list:
        """Build list of (name, callable) based on enabled APIs."""
        all_enabled = self.args and self.args.all_apis
        jobs = []

        def wants(flag_name: str, key_name: str = None) -> bool:
            if all_enabled:
                return self.config.has_key(key_name or flag_name)
            flag_val = getattr(self.args, flag_name.replace("-", "_"), False) if self.args else False
            return flag_val and (not key_name or self.config.has_key(key_name))

        if wants("shodan", "shodan"):
            from apis.shodan_api import ShodanAPI
            jobs.append(("Shodan", lambda: ShodanAPI(self.target, self.config).run()))

        if wants("virustotal", "virustotal"):
            from apis.virustotal_api import VirusTotalAPI
            jobs.append(("VirusTotal", lambda: VirusTotalAPI(self.target, self.config).run()))

        if wants("censys", "censys_id"):
            from apis.censys_api import CensysAPI
            jobs.append(("Censys", lambda: CensysAPI(self.target, self.config).run()))

        if wants("securitytrails", "securitytrails"):
            from apis.securitytrails_api import SecurityTrailsAPI
            jobs.append(("SecurityTrails", lambda: SecurityTrailsAPI(self.target, self.config).run()))

        if wants("hunter", "hunter"):
            from apis.hunter_api import HunterAPI
            jobs.append(("Hunter.io", lambda: HunterAPI(self.target, self.config).run()))

        if wants("urlscan", "urlscan"):
            from apis.urlscan_api import URLScanAPI
            jobs.append(("URLScan", lambda: URLScanAPI(self.target, self.config).run()))

        if wants("abuseipdb", "abuseipdb"):
            from apis.abuseipdb_api import AbuseIPDBAPI
            jobs.append(("AbuseIPDB", lambda: AbuseIPDBAPI(self.target, self.config).run()))

        if wants("fofa", "fofa_key"):
            from apis.fofa_api import FOFAAPI
            jobs.append(("FOFA", lambda: FOFAAPI(self.target, self.config).run()))

        if wants("zoomeye", "zoomeye"):
            from apis.zoomeye_api import ZoomEyeAPI
            jobs.append(("ZoomEye", lambda: ZoomEyeAPI(self.target, self.config).run()))

        if wants("greynoise", "greynoise"):
            from apis.greynoise_api import GreyNoiseAPI
            jobs.append(("GreyNoise", lambda: GreyNoiseAPI(self.target, self.config).run()))

        if wants("binaryedge", "binaryedge"):
            from apis.binaryedge_api import BinaryEdgeAPI
            jobs.append(("BinaryEdge", lambda: BinaryEdgeAPI(self.target, self.config).run()))

        if wants("leakix", "leakix"):
            from apis.leakix_api import LeakIXAPI
            jobs.append(("LeakIX", lambda: LeakIXAPI(self.target, self.config).run()))

        if wants("ipinfo", "ipinfo") or all_enabled:
            from apis.ipinfo_api import IPInfoAPI
            jobs.append(("IPInfo", lambda: IPInfoAPI(self.target, self.config).run()))

        if wants("haveibeenpwned", "haveibeenpwned"):
            from apis.hibp_api import HIBPAPI
            jobs.append(("HaveIBeenPwned", lambda: HIBPAPI(self.target, self.config).run()))

        return jobs

    def _print_api_summary(self, results: dict):
        if not results:
            return
        table = Table(title="API Intelligence Summary", border_style="blue")
        table.add_column("API",      style="bold cyan",  width=18)
        table.add_column("Status",   style="bold green", width=10)
        table.add_column("Key Finding", style="white")
        for name, data in results.items():
            snippet = str(list(data.values())[0])[:60] if data else "—"
            table.add_row(name, "✓ OK", snippet)
        console.print(table)
