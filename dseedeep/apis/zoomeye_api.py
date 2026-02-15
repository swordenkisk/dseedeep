"""dseedeep — ZoomEye API (Global cyberspace mapping)"""
import requests
from core.logger import ScanLogger


class ZoomEyeAPI:
    def __init__(self, target: str, config):
        self.target  = target
        self.key     = config.api_keys.zoomeye
        self.timeout = config.get("timeout", 10)
        self.log     = ScanLogger("ZOOMEYE", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"ZoomEye: [cyan]{self.target}[/cyan]")
        hdrs = {"API-KEY": self.key}
        result = {}
        try:
            # Host search
            r = requests.get("https://api.zoomeye.org/host/search",
                params={"query": f"hostname:{self.target}", "page": 1},
                headers=hdrs, timeout=self.timeout)
            if r.ok:
                data = r.json()
                result["total"]  = data.get("total", 0)
                result["hosts"]  = []
                for match in data.get("matches", [])[:20]:
                    result["hosts"].append({
                        "ip":       match.get("ip", ""),
                        "port":     match.get("portinfo", {}).get("port", ""),
                        "service":  match.get("portinfo", {}).get("service", ""),
                        "banner":   match.get("portinfo", {}).get("banner", "")[:100],
                        "country":  match.get("geoinfo", {}).get("country", {}).get("names", {}).get("en", ""),
                    })
                for h in result["hosts"][:5]:
                    self.log.found("ZoomEye", f"{h['ip']}:{h['port']} {h['service']} ({h['country']})")
        except Exception as e:
            self.log.error(f"ZoomEye: {e}")
        return result
