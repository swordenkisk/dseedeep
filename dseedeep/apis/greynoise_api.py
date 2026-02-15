"""dseedeep — GreyNoise API (Internet noise classification)"""
import requests, socket
from core.logger import ScanLogger


class GreyNoiseAPI:
    def __init__(self, target: str, config):
        self.target  = target
        self.key     = config.api_keys.greynoise
        self.timeout = config.get("timeout", 10)
        self.log     = ScanLogger("GREYNOISE", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"GreyNoise: [cyan]{self.target}[/cyan]")
        try:
            ip = socket.gethostbyname(self.target)
        except Exception:
            ip = self.target
        try:
            r = requests.get(f"https://api.greynoise.io/v3/community/{ip}",
                headers={"key": self.key}, timeout=self.timeout)
            if r.ok:
                data = r.json()
                result = {
                    "ip":       ip,
                    "noise":    data.get("noise", False),
                    "riot":     data.get("riot", False),
                    "name":     data.get("name", ""),
                    "message":  data.get("message", ""),
                    "link":     data.get("link", ""),
                }
                if result["noise"]:
                    self.log.warn(f"IP is internet scanner/noise: {result['name']}")
                elif result["riot"]:
                    self.log.found("RIOT", f"Benign: {result['name']}")
                return result
        except Exception as e:
            self.log.error(f"GreyNoise: {e}")
        return {}
