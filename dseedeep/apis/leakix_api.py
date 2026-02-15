"""dseedeep — LeakIX API (exposed services and data leaks)"""
import requests
from core.logger import ScanLogger


class LeakIXAPI:
    BASE = "https://leakix.net"

    def __init__(self, target: str, config):
        self.target  = target
        self.key     = config.api_keys.leakix
        self.timeout = config.get("timeout", 10)
        self.log     = ScanLogger("LEAKIX", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"LeakIX: [cyan]{self.target}[/cyan]")
        hdrs = {"api-key": self.key, "Accept": "application/json"}
        result = {}
        try:
            # Host search
            r = requests.get(f"{self.BASE}/host/{self.target}",
                headers=hdrs, timeout=self.timeout)
            if r.ok:
                data = r.json()
                result["services"]  = []
                result["leaks"]     = []
                for svc in (data if isinstance(data, list) else [data])[:20]:
                    if not isinstance(svc, dict):
                        continue
                    entry = {
                        "port":     svc.get("port", ""),
                        "protocol": svc.get("protocol", ""),
                        "plugin":   svc.get("plugin", ""),
                        "tags":     svc.get("tags", []),
                    }
                    result["services"].append(entry)
                    # Check for leak tags
                    leak_tags = ["leak", "exposed", "unprotected", "default"]
                    if any(lt in str(entry["tags"]).lower() for lt in leak_tags):
                        result["leaks"].append(entry)
                        self.log.vuln(f"Potential data exposure: {entry['plugin']} port {entry['port']}")

                for svc in result["services"][:5]:
                    self.log.found(f":{svc['port']}", f"{svc['protocol']} — {svc['plugin']}")
        except Exception as e:
            self.log.error(f"LeakIX: {e}")
        return result
