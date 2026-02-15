"""
dseedeep — Subdomain Enumeration
Brute-force + crt.sh + dnsx + VirusTotal passive sources
"""

import requests
import socket
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from core.logger import ScanLogger

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "admin", "smtp", "pop", "imap", "vpn", "remote",
    "api", "dev", "staging", "test", "beta", "prod", "app", "web", "blog",
    "shop", "portal", "m", "mobile", "cdn", "static", "media", "assets",
    "img", "images", "docs", "wiki", "help", "support", "secure", "login",
    "auth", "sso", "id", "accounts", "pay", "payment", "checkout", "store",
    "ns1", "ns2", "mx", "relay", "exchange", "autodiscover", "owa", "webmail",
    "cpanel", "whm", "plesk", "ftp", "sftp", "ssh", "rdp", "monitor",
    "status", "grafana", "kibana", "jenkins", "gitlab", "bitbucket", "git",
    "ci", "cd", "build", "deploy", "k8s", "kubernetes", "docker", "registry",
    "internal", "intranet", "corp", "office", "vpn2", "remote2", "old", "v2",
    "v1", "new", "demo", "sandbox", "uat", "qa", "pre", "stg", "backoffice",
    "panel", "dashboard", "crm", "erp", "jira", "confluence", "slack",
    "analytics", "tracking", "ads", "marketing", "email", "newsletter",
    "api2", "rest", "graphql", "gateway", "proxy", "lb", "haproxy", "nginx",
    "db", "database", "mysql", "postgres", "redis", "elastic", "mongo",
    "backup", "bk", "archive", "logs", "metrics", "prometheus", "alertmanager",
]


class SubdomainEnum:
    def __init__(self, target: str, config, args=None):
        self.target  = target
        self.config  = config
        self.args    = args
        self.threads = config.get("threads", 20)
        self.timeout = config.get("timeout", 10)
        self.log     = ScanLogger("SUBDOMAIN", config.get("verbose", False))
        self.found   = set()

    def run(self) -> list:
        self.log.info(f"Subdomain discovery for [cyan]{self.target}[/cyan]")

        # Load wordlist
        wordlist = list(DEFAULT_WORDLIST)
        if self.args and self.args.wordlist:
            p = Path(self.args.wordlist)
            if p.exists():
                wordlist = [l.strip() for l in p.read_text().splitlines() if l.strip()]
                self.log.info(f"Loaded wordlist: {len(wordlist)} entries")

        # Passive: crt.sh
        self._passive_crtsh()

        # Passive: HackerTarget
        self._passive_hackertarget()

        # Passive: web.archive.org
        self._passive_wayback_subdomains()

        # Active brute-force
        self._brute_force(wordlist)

        result = sorted(self.found)
        for sub in result[:10]:
            self.log.found("Subdomain", sub)
        if len(result) > 10:
            self.log.info(f"...and {len(result)-10} more")

        self.log.success(f"Total subdomains: {len(result)}")
        return result

    def _resolve(self, sub: str) -> bool:
        fqdn = f"{sub}.{self.target}"
        try:
            socket.setdefaulttimeout(self.timeout)
            socket.getaddrinfo(fqdn, None)
            self.found.add(fqdn)
            return True
        except Exception:
            return False

    def _brute_force(self, wordlist: list):
        self.log.info(f"Brute-forcing {len(wordlist)} subdomains ({self.threads} threads)…")
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._resolve, sub): sub for sub in wordlist}
            for future in as_completed(futures):
                pass  # Results added in _resolve

    def _passive_crtsh(self):
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            r = requests.get(url, timeout=self.timeout)
            if r.ok:
                data = r.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub.endswith(f".{self.target}") or sub == self.target:
                            self.found.add(sub)
                self.log.debug(f"crt.sh returned {len(data)} cert entries")
        except Exception as e:
            self.log.debug(f"crt.sh error: {e}")

    def _passive_hackertarget(self):
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.target}"
            r = requests.get(url, timeout=self.timeout)
            if r.ok and "error" not in r.text:
                for line in r.text.splitlines():
                    if "," in line:
                        host = line.split(",")[0].strip()
                        if host.endswith(self.target):
                            self.found.add(host)
        except Exception as e:
            self.log.debug(f"HackerTarget error: {e}")

    def _passive_wayback_subdomains(self):
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.target}/*&output=json&fl=original&collapse=urlkey&limit=500"
            r = requests.get(url, timeout=self.timeout)
            if r.ok:
                for entry in r.json()[1:]:
                    from urllib.parse import urlparse
                    host = urlparse(entry[0]).hostname or ""
                    if host and host.endswith(self.target):
                        self.found.add(host)
        except Exception as e:
            self.log.debug(f"Wayback subdomain error: {e}")
