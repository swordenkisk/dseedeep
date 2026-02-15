"""dseedeep — FOFA API (Chinese cyberspace search engine)"""
import requests, base64
from core.logger import ScanLogger


class FOFAAPI:
    def __init__(self, target: str, config):
        self.target = target
        self.email  = config.api_keys.fofa_email
        self.key    = config.api_keys.fofa_key
        self.timeout= config.get("timeout", 10)
        self.log    = ScanLogger("FOFA", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"FOFA: [cyan]{self.target}[/cyan]")
        try:
            query   = f'domain="{self.target}"'
            qb64    = base64.b64encode(query.encode()).decode()
            r = requests.get("https://fofa.info/api/v1/search/all",
                params={"email": self.email, "key": self.key, "qbase64": qb64,
                        "size": 100, "fields": "ip,port,title,server,host"},
                timeout=self.timeout)
            if r.ok:
                data = r.json()
                results = data.get("results", [])
                hosts = [{"ip": x[0], "port": x[1], "title": x[2],
                          "server": x[3], "host": x[4]} for x in results]
                for h in hosts[:5]:
                    self.log.found("FOFA Host", f"{h['ip']}:{h['port']} — {h['title'][:40]}")
                return {"total": data.get("size", 0), "hosts": hosts}
        except Exception as e:
            self.log.error(f"FOFA: {e}")
        return {}
