"""
dseedeep — Web Crawler
Discovers URLs, forms, API endpoints, and JS files within scope.
"""
import re
import requests
from urllib.parse import urljoin, urlparse
from collections import deque
from urllib3.exceptions import InsecureRequestWarning
import warnings
warnings.filterwarnings("ignore", category=InsecureRequestWarning)
from core.logger import ScanLogger

LINK_RE     = re.compile(r'href=["\']([^"\'#>]+)["\']', re.IGNORECASE)
SRC_RE      = re.compile(r'src=["\']([^"\'#>]+)["\']', re.IGNORECASE)
ACTION_RE   = re.compile(r'action=["\']([^"\'#>]+)["\']', re.IGNORECASE)
API_PATH_RE = re.compile(r'["\'](/(?:api|v\d|rest|graphql|rpc)/[^"\'<>\s]+)["\']')


class WebCrawler:
    def __init__(self, target: str, config, args=None):
        self.target     = target
        self.config     = config
        self.max_depth  = args.crawl_depth if args else 2
        self.timeout    = config.get("timeout", 10)
        self.ua         = config.get("user_agent", "Mozilla/5.0")
        self.proxy      = config.proxy_dict()
        self.log        = ScanLogger("CRAWLER", config.get("verbose", False))
        self.base_host  = urlparse(target).netloc
        self.visited    = set()
        self.forms      = []
        self.js_files   = set()
        self.api_paths  = set()

    def run(self) -> dict:
        self.log.info(f"Crawling [cyan]{self.target}[/cyan] (depth={self.max_depth})")
        queue = deque([(self.target, 0)])
        urls_found = set([self.target])

        while queue:
            url, depth = queue.popleft()
            if url in self.visited or depth > self.max_depth:
                continue
            self.visited.add(url)

            try:
                r = requests.get(url, timeout=self.timeout, verify=False,
                                 headers={"User-Agent": self.ua}, proxies=self.proxy)
                body = r.text

                # Extract links
                for pattern in [LINK_RE, SRC_RE, ACTION_RE]:
                    for match in pattern.findall(body):
                        abs_url = urljoin(url, match)
                        parsed  = urlparse(abs_url)
                        if parsed.netloc == self.base_host and abs_url not in self.visited:
                            urls_found.add(abs_url)
                            if depth + 1 <= self.max_depth:
                                queue.append((abs_url, depth + 1))

                # JS files
                js_matches = re.findall(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', body)
                for js in js_matches:
                    self.js_files.add(urljoin(url, js))

                # API endpoints
                for match in API_PATH_RE.findall(body):
                    self.api_paths.add(match)

                # Forms
                form_actions = ACTION_RE.findall(body)
                for action in form_actions:
                    self.forms.append({"page": url, "action": urljoin(url, action)})

            except Exception:
                pass

        self.log.success(
            f"Crawled {len(self.visited)} pages | "
            f"JS: {len(self.js_files)} | API paths: {len(self.api_paths)}"
        )
        for p in list(self.api_paths)[:10]:
            self.log.found("API Path", p)

        return {
            "pages_crawled":  len(self.visited),
            "all_urls":       list(self.visited)[:500],
            "js_files":       list(self.js_files)[:100],
            "api_endpoints":  list(self.api_paths)[:100],
            "forms":          self.forms[:50],
        }
