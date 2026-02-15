"""
dseedeep — Certificate Transparency Log Mining (crt.sh)
"""
import requests
from core.logger import ScanLogger


class CertTransparency:
    def __init__(self, target: str, config):
        self.target  = target
        self.timeout = config.get("timeout", 10)
        self.log     = ScanLogger("CERTS", config.get("verbose", False))

    def run(self) -> list:
        self.log.info(f"Certificate transparency lookup for [cyan]{self.target}[/cyan]")
        certs = []
        try:
            url = f"https://crt.sh/?q={self.target}&output=json"
            r   = requests.get(url, timeout=self.timeout)
            if r.ok:
                seen = set()
                for entry in r.json():
                    name   = entry.get("name_value", "").strip()
                    issuer = entry.get("issuer_name", "")
                    not_before = entry.get("not_before", "")
                    not_after  = entry.get("not_after", "")
                    key = name + issuer
                    if key not in seen:
                        seen.add(key)
                        rec = {"name": name, "issuer": issuer,
                               "not_before": not_before, "not_after": not_after}
                        certs.append(rec)
                        self.log.found("Cert CN", f"{name[:60]} | {issuer[:40]}")
        except Exception as e:
            self.log.error(f"crt.sh error: {e}")

        self.log.success(f"Found {len(certs)} certificate records")
        return certs
