"""dseedeep — Censys API"""
import requests, base64
from core.logger import ScanLogger


class CensysAPI:
    def __init__(self, target: str, config):
        self.target  = target
        self.uid     = config.api_keys.censys_id
        self.secret  = config.api_keys.censys_secret
        self.timeout = config.get("timeout", 10)
        self.log     = ScanLogger("CENSYS", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"Censys lookup: [cyan]{self.target}[/cyan]")
        result = {}
        auth = (self.uid, self.secret)
        try:
            # Hosts search
            r = requests.post("https://search.censys.io/api/v2/hosts/search",
                json={"q": self.target, "per_page": 10},
                auth=auth, timeout=self.timeout)
            if r.ok:
                hits = r.json().get("result", {}).get("hits", [])
                result["hosts"] = [
                    {"ip": h.get("ip"), "services": [s.get("port") for s in h.get("services", [])],
                     "country": h.get("location", {}).get("country", "")}
                    for h in hits
                ]
                for h in result["hosts"][:5]:
                    self.log.found("Host", f"{h['ip']} ports:{h['services']} ({h['country']})")

            # Certificates search
            r2 = requests.post("https://search.censys.io/api/v2/certificates/search",
                json={"q": f"parsed.names: {self.target}", "per_page": 10},
                auth=auth, timeout=self.timeout)
            if r2.ok:
                certs = r2.json().get("result", {}).get("hits", [])
                result["certificates"] = [c.get("parsed", {}).get("subject_dn", "") for c in certs[:10]]
        except Exception as e:
            self.log.error(f"Censys: {e}")
        return result
