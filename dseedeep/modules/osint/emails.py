"""
dseedeep — Email Harvester
Sources: Hunter.io API, crt.sh email extraction, web scraping, CommonCrawl
"""
import re
import requests
from core.logger import ScanLogger

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


class EmailHarvester:
    def __init__(self, target: str, config):
        self.target  = target
        self.config  = config
        self.timeout = config.get("timeout", 10)
        self.log     = ScanLogger("EMAILS", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"Harvesting emails for [cyan]{self.target}[/cyan]")
        emails = set()

        # Hunter.io API
        if self.config.has_key("hunter"):
            self._hunter_io(emails)

        # Web scraping main site
        self._scrape_site(emails)

        # crt.sh emails
        self._crtsh_emails(emails)

        result = sorted(emails)
        for e in result[:10]:
            self.log.found("Email", e)
        self.log.success(f"Found {len(result)} email addresses")
        return {"emails": result}

    def _hunter_io(self, emails: set):
        try:
            key = self.config.api_keys.hunter
            url = f"https://api.hunter.io/v2/domain-search?domain={self.target}&api_key={key}&limit=100"
            r = requests.get(url, timeout=self.timeout)
            if r.ok:
                data = r.json()
                for em in data.get("data", {}).get("emails", []):
                    emails.add(em["value"])
                self.log.debug(f"Hunter.io found {len(emails)} emails")
        except Exception as e:
            self.log.debug(f"Hunter.io error: {e}")

    def _scrape_site(self, emails: set):
        for scheme in ["https://", "http://"]:
            try:
                r = requests.get(f"{scheme}{self.target}", timeout=self.timeout,
                                 headers={"User-Agent": "Mozilla/5.0"})
                found = EMAIL_REGEX.findall(r.text)
                for e in found:
                    if not e.endswith(('.png', '.jpg', '.gif', '.svg', '.css')):
                        emails.add(e)
            except Exception:
                pass

    def _crtsh_emails(self, emails: set):
        try:
            url = f"https://crt.sh/?q={self.target}&output=json"
            r = requests.get(url, timeout=self.timeout)
            if r.ok:
                found = EMAIL_REGEX.findall(r.text)
                emails.update(found)
        except Exception:
            pass
