"""dseedeep — VirusTotal API"""
import requests
from core.logger import ScanLogger


class VirusTotalAPI:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, target: str, config):
        self.target  = target
        self.key     = config.api_keys.virustotal
        self.timeout = config.get("timeout", 10)
        self.log     = ScanLogger("VIRUSTOTAL", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"VirusTotal lookup: [cyan]{self.target}[/cyan]")
        result = {}
        hdrs = {"x-apikey": self.key}

        # Determine if IP or domain
        endpoint = "ip_addresses" if self._is_ip() else "domains"
        try:
            r = requests.get(f"{self.BASE}/{endpoint}/{self.target}", headers=hdrs, timeout=self.timeout)
            if r.ok:
                attrs = r.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                result["malicious"]    = stats.get("malicious", 0)
                result["suspicious"]   = stats.get("suspicious", 0)
                result["harmless"]     = stats.get("harmless", 0)
                result["reputation"]   = attrs.get("reputation", 0)
                result["categories"]   = list(attrs.get("categories", {}).values())[:5]
                result["tags"]         = attrs.get("tags", [])
                result["whois"]        = attrs.get("whois", "")[:300]
                result["last_dns_records"] = attrs.get("last_dns_records", [])[:10]

                if result["malicious"] > 0:
                    self.log.vuln(f"Malicious detections: {result['malicious']} vendors!")
                else:
                    self.log.found("VT Reputation", f"{result['malicious']} malicious / {result['harmless']} clean")

            # Passive DNS
            r2 = requests.get(f"{self.BASE}/{endpoint}/{self.target}/resolutions",
                              headers=hdrs, timeout=self.timeout)
            if r2.ok:
                resolutions = r2.json().get("data", [])
                result["passive_dns"] = [
                    {"hostname": x.get("attributes", {}).get("host_name", ""),
                     "ip":       x.get("attributes", {}).get("ip_address", "")}
                    for x in resolutions[:20]
                ]
        except Exception as e:
            self.log.error(f"VirusTotal: {e}")
        return result

    def _is_ip(self) -> bool:
        import re
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", self.target))
