"""
dseedeep — Wayback Machine URL Discovery
"""
import requests
from core.logger import ScanLogger


class WaybackEnum:
    def __init__(self, target: str, config):
        self.target  = target
        self.timeout = config.get("timeout", 15)
        self.log     = ScanLogger("WAYBACK", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"Wayback Machine crawl for [cyan]{self.target}[/cyan]")
        urls, params = set(), set()
        try:
            api = (f"http://web.archive.org/cdx/search/cdx"
                   f"?url={self.target}/*&output=json&fl=original&collapse=urlkey&limit=2000")
            r = requests.get(api, timeout=self.timeout)
            if r.ok:
                data = r.json()[1:]  # skip header row
                for row in data:
                    url = row[0]
                    urls.add(url)
                    if "?" in url:
                        params.add(url.split("?")[0])
        except Exception as e:
            self.log.error(f"Wayback error: {e}")

        self.log.success(f"Wayback: {len(urls)} URLs, {len(params)} unique endpoints with params")
        return {
            "wayback_urls":      list(urls)[:500],
            "param_endpoints":   list(params)[:200],
        }
