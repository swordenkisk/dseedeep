"""dseedeep — IPInfo API (geolocation, ASN, organization)"""
import requests, socket
from core.logger import ScanLogger


class IPInfoAPI:
    def __init__(self, target: str, config):
        self.target  = target
        self.key     = config.api_keys.ipinfo
        self.timeout = config.get("timeout", 10)
        self.log     = ScanLogger("IPINFO", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"IPInfo: [cyan]{self.target}[/cyan]")
        try:
            ip = socket.gethostbyname(self.target)
        except Exception:
            ip = self.target
        try:
            token = f"?token={self.key}" if self.key else ""
            r = requests.get(f"https://ipinfo.io/{ip}/json{token}", timeout=self.timeout)
            if r.ok:
                d = r.json()
                result = {
                    "ip":       d.get("ip", ""),
                    "hostname": d.get("hostname", ""),
                    "city":     d.get("city", ""),
                    "region":   d.get("region", ""),
                    "country":  d.get("country", ""),
                    "org":      d.get("org", ""),
                    "asn":      d.get("org", "").split()[0] if d.get("org") else "",
                    "timezone": d.get("timezone", ""),
                    "loc":      d.get("loc", ""),
                    "abuse":    d.get("abuse", {}),
                }
                self.log.found("IP",       result["ip"])
                self.log.found("Org/ASN",  result["org"])
                self.log.found("Location", f"{result['city']}, {result['region']}, {result['country']}")
                return result
        except Exception as e:
            self.log.error(f"IPInfo: {e}")
        return {}
