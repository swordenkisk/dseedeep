"""dseedeep — Hunter.io API"""
import requests
from core.logger import ScanLogger


class HunterAPI:
    def __init__(self, target: str, config):
        self.target  = target
        self.key     = config.api_keys.hunter
        self.timeout = config.get("timeout", 10)
        self.log     = ScanLogger("HUNTER", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"Hunter.io: [cyan]{self.target}[/cyan]")
        try:
            r = requests.get(
                f"https://api.hunter.io/v2/domain-search",
                params={"domain": self.target, "api_key": self.key, "limit": 100},
                timeout=self.timeout
            )
            if r.ok:
                d = r.json().get("data", {})
                result = {
                    "organization":  d.get("organization", ""),
                    "total_emails":  d.get("meta", {}).get("total", 0),
                    "emails":        [e["value"] for e in d.get("emails", [])[:50]],
                    "email_pattern": d.get("pattern", ""),
                    "webmail":       d.get("webmail", False),
                    "disposable":    d.get("disposable", False),
                    "mx_records":    [mx.get("value") for mx in d.get("mx_records", [])],
                }
                self.log.found("Emails found", str(result["total_emails"]))
                self.log.found("Pattern",      result["email_pattern"])
                return result
        except Exception as e:
            self.log.error(f"Hunter.io: {e}")
        return {}
