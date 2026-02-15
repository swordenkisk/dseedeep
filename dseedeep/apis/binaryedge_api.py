"""dseedeep — BinaryEdge API"""
import requests, socket
from core.logger import ScanLogger


class BinaryEdgeAPI:
    BASE = "https://api.binaryedge.io/v2"

    def __init__(self, target: str, config):
        self.target  = target
        self.key     = config.api_keys.binaryedge
        self.timeout = config.get("timeout", 10)
        self.log     = ScanLogger("BINARYEDGE", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"BinaryEdge: [cyan]{self.target}[/cyan]")
        hdrs = {"X-Key": self.key}
        try:
            ip = socket.gethostbyname(self.target)
        except Exception:
            ip = self.target
        result = {}
        try:
            r = requests.get(f"{self.BASE}/query/ip/{ip}", headers=hdrs, timeout=self.timeout)
            if r.ok:
                data = r.json()
                result["total"]   = data.get("total", 0)
                result["events"]  = []
                for event in data.get("events", [])[:20]:
                    port_data = event.get("results", [{}])[0] if event.get("results") else {}
                    result["events"].append({
                        "port":     event.get("port", ""),
                        "proto":    event.get("protocol", ""),
                        "service":  str(port_data)[:80],
                    })
                for e in result["events"][:5]:
                    self.log.found(f"Port {e['port']}/{e['proto']}", e["service"][:60])
        except Exception as e:
            self.log.error(f"BinaryEdge: {e}")
        return result
