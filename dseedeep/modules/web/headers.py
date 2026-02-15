"""
dseedeep — HTTP Header Analyzer
Extracts and scores security-relevant HTTP response headers.
"""
import requests
from urllib3.exceptions import InsecureRequestWarning
import warnings
warnings.filterwarnings("ignore", category=InsecureRequestWarning)
from core.logger import ScanLogger

SECURITY_HEADERS = {
    "strict-transport-security":  ("HSTS",       "CRITICAL"),
    "content-security-policy":    ("CSP",         "HIGH"),
    "x-frame-options":            ("Clickjacking","HIGH"),
    "x-content-type-options":     ("MIME Sniff",  "MEDIUM"),
    "referrer-policy":            ("Referrer",    "LOW"),
    "permissions-policy":         ("Permissions", "LOW"),
    "x-xss-protection":           ("XSS Filter",  "LOW"),
    "cross-origin-opener-policy": ("COOP",        "MEDIUM"),
    "cross-origin-resource-policy":("CORP",       "MEDIUM"),
}

INTERESTING_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "via", "x-varnish", "x-cache", "cf-ray", "x-amz-request-id",
    "x-served-by", "set-cookie", "access-control-allow-origin",
]


class HeaderAnalyzer:
    def __init__(self, target: str, config):
        self.target  = target
        self.timeout = config.get("timeout", 10)
        self.ua      = config.get("user_agent", "Mozilla/5.0")
        self.proxy   = config.proxy_dict()
        self.log     = ScanLogger("HEADERS", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"Analyzing HTTP headers for [cyan]{self.target}[/cyan]")
        result = {"url": self.target, "headers": {}, "missing_security": [], "interesting": {}}
        try:
            r = requests.get(self.target, timeout=self.timeout, verify=False,
                             headers={"User-Agent": self.ua}, proxies=self.proxy,
                             allow_redirects=True)
            result["status_code"]   = r.status_code
            result["final_url"]     = r.url
            result["redirect_chain"]= [rsp.url for rsp in r.history]
            result["headers"]       = dict(r.headers)

            # Check security headers
            lower_headers = {k.lower(): v for k, v in r.headers.items()}
            for hdr, (name, sev) in SECURITY_HEADERS.items():
                if hdr not in lower_headers:
                    result["missing_security"].append({"header": hdr, "name": name, "severity": sev})
                    self.log.warn(f"Missing [{sev}] {name} ({hdr})")
                else:
                    self.log.found(f"[PRESENT] {name}", lower_headers[hdr][:80])

            # Extract interesting headers
            for hdr in INTERESTING_HEADERS:
                if hdr in lower_headers:
                    result["interesting"][hdr] = lower_headers[hdr]
                    self.log.found(f"Info: {hdr}", lower_headers[hdr])

            result["score"] = max(0, 100 - len(result["missing_security"]) * 10)
            self.log.success(f"Security header score: {result['score']}/100")
        except Exception as e:
            self.log.error(f"Header analysis failed: {e}")
        return result
