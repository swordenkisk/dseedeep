"""
dseedeep — Shodan API Integration
"""
import requests, socket
from core.logger import ScanLogger


class ShodanAPI:
    BASE = "https://api.shodan.io"

    def __init__(self, target: str, config):
        self.target  = target
        self.key     = config.api_keys.shodan
        self.timeout = config.get("timeout", 10)
        self.log     = ScanLogger("SHODAN", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"Shodan lookup for [cyan]{self.target}[/cyan]")
        # Resolve to IP if domain
        try:
            ip = socket.gethostbyname(self.target)
        except Exception:
            ip = self.target

        result = {}
        try:
            # Host info
            r = requests.get(f"{self.BASE}/shodan/host/{ip}?key={self.key}", timeout=self.timeout)
            if r.ok:
                data = r.json()
                result["ip"]           = ip
                result["org"]          = data.get("org", "")
                result["isp"]          = data.get("isp", "")
                result["country"]      = data.get("country_name", "")
                result["city"]         = data.get("city", "")
                result["asn"]          = data.get("asn", "")
                result["hostnames"]    = data.get("hostnames", [])
                result["domains"]      = data.get("domains", [])
                result["tags"]         = data.get("tags", [])
                result["vulns"]        = list(data.get("vulns", {}).keys())
                result["open_ports"]   = data.get("ports", [])
                result["last_update"]  = data.get("last_update", "")
                result["services"]     = []
                for svc in data.get("data", [])[:20]:
                    result["services"].append({
                        "port":    svc.get("port"),
                        "product": svc.get("product", ""),
                        "version": svc.get("version", ""),
                        "banner":  svc.get("data", "")[:100],
                    })

                self.log.found("ASN",     result["asn"])
                self.log.found("Org",     result["org"])
                self.log.found("Ports",   str(result["open_ports"][:15]))
                if result["vulns"]:
                    self.log.vuln(f"Shodan CVEs: {', '.join(result['vulns'][:5])}")
        except Exception as e:
            self.log.error(f"Shodan: {e}")
        return result
