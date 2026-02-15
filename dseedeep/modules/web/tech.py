"""
dseedeep — Technology Fingerprinting
Detects CMS, frameworks, servers, CDN, analytics, and more.
"""
import re
import requests
from urllib3.exceptions import InsecureRequestWarning
import warnings
warnings.filterwarnings("ignore", category=InsecureRequestWarning)
from core.logger import ScanLogger

SIGNATURES = [
    # (category, name, pattern — matched against headers+body)
    ("CMS",        "WordPress",     r"wp-content|wp-includes|xmlrpc\.php|WordPress"),
    ("CMS",        "Drupal",        r"Drupal|sites/default|\/drupal"),
    ("CMS",        "Joomla",        r"Joomla|\/components\/com_|option=com_"),
    ("CMS",        "Magento",       r"Mage\.|\/skin\/frontend|Magento"),
    ("CMS",        "Shopify",       r"myshopify\.com|Shopify\.theme"),
    ("Framework",  "React",         r"react(?:\.min)?\.js|__REACT|ReactDOM"),
    ("Framework",  "Angular",       r"ng-version|angular(?:\.min)?\.js|ng-app"),
    ("Framework",  "Vue.js",        r"vue(?:\.min)?\.js|__vue_|data-v-"),
    ("Framework",  "Next.js",       r"__NEXT_DATA__|_next/static"),
    ("Framework",  "Laravel",       r"laravel_session|Laravel"),
    ("Framework",  "Django",        r"csrfmiddlewaretoken|Django"),
    ("Framework",  "Ruby on Rails", r"X-Request-Id.*rails|csrf-token.*rails"),
    ("Server",     "Apache",        r"Apache(?:/[\d.]+)?"),
    ("Server",     "Nginx",         r"nginx(?:/[\d.]+)?"),
    ("Server",     "IIS",           r"Microsoft-IIS(?:/[\d.]+)?"),
    ("Server",     "Cloudflare",    r"cloudflare|cf-ray"),
    ("Server",     "AWS CloudFront",r"x-amz-cf-id|CloudFront"),
    ("Server",     "Fastly",        r"x-served-by.*cache|Fastly"),
    ("Database",   "MySQL",         r"MySQL|mysql_"),
    ("Analytics",  "Google Analytics",r"google-analytics\.com|ga\.js|gtag\("),
    ("Security",   "reCAPTCHA",     r"recaptcha|grecaptcha"),
    ("Payment",    "Stripe",        r"stripe\.com|js\.stripe\.com"),
    ("Language",   "PHP",           r"X-Powered-By: PHP|\.php|PHPSESSID"),
    ("Language",   "Python",        r"Python|Werkzeug|gunicorn|uWSGI"),
    ("Language",   "Java",          r"JSESSIONID|java\.sun\.com|\.jsp"),
    ("Language",   "ASP.NET",       r"ASP\.NET|__VIEWSTATE|__EVENTVALIDATION"),
]


class TechDetect:
    def __init__(self, target: str, config):
        self.target  = target
        self.timeout = config.get("timeout", 10)
        self.ua      = config.get("user_agent", "Mozilla/5.0")
        self.log     = ScanLogger("TECHDET", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"Technology fingerprinting [cyan]{self.target}[/cyan]")
        detected = []
        try:
            r = requests.get(self.target, timeout=self.timeout, verify=False,
                             headers={"User-Agent": self.ua})
            haystack = r.text + "\n" + "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            for cat, name, pattern in SIGNATURES:
                if re.search(pattern, haystack, re.IGNORECASE):
                    detected.append({"category": cat, "name": name})
                    self.log.found(cat, name)
        except Exception as e:
            self.log.error(f"Tech detection failed: {e}")
        self.log.success(f"Detected {len(detected)} technologies")
        return {"technologies": detected}
