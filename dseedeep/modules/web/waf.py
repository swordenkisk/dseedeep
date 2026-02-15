"""
dseedeep — WAF Detection
Identifies Web Application Firewalls by response analysis and fingerprinting.
"""
import requests
from urllib3.exceptions import InsecureRequestWarning
import warnings
warnings.filterwarnings("ignore", category=InsecureRequestWarning)
from core.logger import ScanLogger

WAF_SIGNATURES = {
    "Cloudflare":       ["cloudflare", "cf-ray", "__cfduid", "cf_clearance"],
    "AWS WAF":          ["x-amzn-requestid", "awselb", "x-amz-cf"],
    "Akamai":           ["akamai", "x-akamai-request-id", "akamaighost"],
    "Sucuri":           ["x-sucuri-id", "sucuri", "x-sucuri-block"],
    "ModSecurity":      ["mod_security", "modsec", "406 Not Acceptable"],
    "Imperva (Incapsula)":["visid_incap", "incap_ses", "x-iinfo"],
    "F5 BIG-IP ASM":    ["ts=", "f5_cspm", "BIGipServer"],
    "Barracuda":        ["barra_counter_session", "barracuda"],
    "Fortinet":         ["fortigate", "fortiweb", "FORTIWAFSID"],
    "DDoS-Guard":       ["ddos-guard", "__ddg1"],
    "Wallarm":          ["wallarm"],
    "Wordfence":        ["wordfence", "wfwaf"],
    "Radware AppWall":  ["rdwr_mb", "rdwr_src"],
    "Reblaze":          ["rbzid", "reblaze"],
    "Azure WAF":        ["x-ms-request-id", "x-azure-ref"],
    "Google Cloud Armor":["x-cloud-trace-context", "x-goog-"],
}

DETECTION_PAYLOADS = [
    "/?q=<script>alert(1)</script>",
    "/?id=1'OR'1'='1",
    "/?cmd=../../../etc/passwd",
    "/?file=../../etc/shadow",
]


class WAFDetect:
    def __init__(self, target: str, config):
        self.target  = target
        self.timeout = config.get("timeout", 10)
        self.log     = ScanLogger("WAF", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"WAF detection for [cyan]{self.target}[/cyan]")
        result = {"detected": [], "blocked_payloads": 0, "waf_headers": {}}

        try:
            # Normal request baseline
            baseline = requests.get(self.target, timeout=self.timeout, verify=False)
            baseline_code = baseline.status_code
            all_text = (baseline.text + " " + " ".join(f"{k}:{v}" for k,v in baseline.headers.items())).lower()

            # Fingerprint from headers/body
            for waf, sigs in WAF_SIGNATURES.items():
                if any(sig.lower() in all_text for sig in sigs):
                    result["detected"].append(waf)
                    result["waf_headers"].update({k: v for k, v in baseline.headers.items()
                                                  if any(s.lower() in k.lower() for s in sigs)})
                    self.log.found("WAF Detected", waf)

            # Send attack payloads and check for blocks
            base_url = self.target.rstrip("/")
            for payload in DETECTION_PAYLOADS:
                try:
                    r = requests.get(base_url + payload, timeout=self.timeout, verify=False)
                    if r.status_code in (403, 406, 429, 444, 501, 503):
                        result["blocked_payloads"] += 1
                except Exception:
                    pass

            if result["blocked_payloads"] > 1 and not result["detected"]:
                result["detected"].append("Unknown WAF (behavioral detection)")

            if not result["detected"]:
                self.log.info("No WAF fingerprinted — may be unconfigured or custom WAF")
            else:
                self.log.warn(f"WAF present: {', '.join(result['detected'])}")

        except Exception as e:
            self.log.error(f"WAF detection error: {e}")

        return result
