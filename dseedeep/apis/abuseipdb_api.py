"""dseedeep — AbuseIPDB API"""
import requests, socket
from core.logger import ScanLogger


class AbuseIPDBAPI:
    def __init__(self, target: str, config):
        self.target  = target
        self.key     = config.api_keys.abuseipdb
        self.timeout = config.get("timeout", 10)
        self.log     = ScanLogger("ABUSEIPDB", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"AbuseIPDB: [cyan]{self.target}[/cyan]")
        try:
            ip = socket.gethostbyname(self.target)
        except Exception:
            ip = self.target
        try:
            r = requests.get("https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                headers={"Key": self.key, "Accept": "application/json"},
                timeout=self.timeout)
            if r.ok:
                d = r.json().get("data", {})
                result = {
                    "ip":              ip,
                    "abuse_score":     d.get("abuseConfidenceScore", 0),
                    "total_reports":   d.get("totalReports", 0),
                    "country":         d.get("countryCode", ""),
                    "isp":             d.get("isp", ""),
                    "domain":          d.get("domain", ""),
                    "is_whitelisted":  d.get("isWhitelisted", False),
                    "usage_type":      d.get("usageType", ""),
                    "last_reported":   d.get("lastReportedAt", ""),
                }
                score = result["abuse_score"]
                if score > 50:
                    self.log.vuln(f"High abuse score: {score}% — {result['total_reports']} reports!")
                else:
                    self.log.found("Abuse Score", f"{score}% ({result['total_reports']} reports)")
                return result
        except Exception as e:
            self.log.error(f"AbuseIPDB: {e}")
        return {}
