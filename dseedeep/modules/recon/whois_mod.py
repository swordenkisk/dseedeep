"""
dseedeep — WHOIS Lookup Module
"""
import whois as pythonwhois
from core.logger import ScanLogger


class WhoisLookup:
    def __init__(self, target: str, config):
        self.target = target
        self.config = config
        self.log    = ScanLogger("WHOIS", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"WHOIS lookup for [cyan]{self.target}[/cyan]")
        try:
            w = pythonwhois.whois(self.target)
            result = {}
            fields = ["registrar", "creation_date", "expiration_date",
                      "updated_date", "status", "emails", "name_servers",
                      "org", "country", "registrant_name", "dnssec"]
            for f in fields:
                val = getattr(w, f, None)
                if val:
                    result[f] = str(val) if not isinstance(val, list) else [str(v) for v in val]
                    self.log.found(f.replace("_", " ").title(), str(val)[:80])
            self.log.success("WHOIS complete")
            return result
        except Exception as e:
            self.log.error(f"WHOIS failed: {e}")
            return {"error": str(e)}
