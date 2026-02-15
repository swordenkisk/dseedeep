"""dseedeep — SecurityTrails API"""
import requests
from core.logger import ScanLogger


class SecurityTrailsAPI:
    BASE = "https://api.securitytrails.com/v1"

    def __init__(self, target: str, config):
        self.target  = target
        self.key     = config.api_keys.securitytrails
        self.timeout = config.get("timeout", 10)
        self.log     = ScanLogger("SECTRAILS", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"SecurityTrails: [cyan]{self.target}[/cyan]")
        hdrs   = {"APIKEY": self.key}
        result = {}
        try:
            # Domain details
            r = requests.get(f"{self.BASE}/domain/{self.target}", headers=hdrs, timeout=self.timeout)
            if r.ok:
                data = r.json()
                result["alexa_rank"]     = data.get("alexa_rank")
                result["apex_domain"]    = data.get("apex_domain")
                result["current_dns"]    = data.get("current_dns", {})
                result["subdomain_count"]= data.get("subdomain_count", 0)
                self.log.found("Subdomains", str(result["subdomain_count"]))

            # Historical DNS
            for rtype in ["a", "mx", "ns"]:
                r2 = requests.get(f"{self.BASE}/history/{self.target}/dns/{rtype}",
                                  headers=hdrs, timeout=self.timeout)
                if r2.ok:
                    hist = r2.json().get("records", [])
                    result[f"dns_history_{rtype}"] = hist[:10]

            # Subdomains
            r3 = requests.get(f"{self.BASE}/domain/{self.target}/subdomains",
                              headers=hdrs, timeout=self.timeout, params={"children_only": "true"})
            if r3.ok:
                subs = r3.json().get("subdomains", [])
                result["subdomains"] = [f"{s}.{self.target}" for s in subs[:50]]
                for s in result["subdomains"][:5]:
                    self.log.found("Subdomain", s)

            # Associated IPs
            r4 = requests.get(f"{self.BASE}/domain/{self.target}/associated-domains",
                              headers=hdrs, timeout=self.timeout)
            if r4.ok:
                result["associated_domains"] = r4.json().get("records", [])[:10]

        except Exception as e:
            self.log.error(f"SecurityTrails: {e}")
        return result
