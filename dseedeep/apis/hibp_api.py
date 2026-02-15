"""dseedeep — HaveIBeenPwned API (breach detection for emails/domains)"""
import requests, time
from core.logger import ScanLogger


class HIBPAPI:
    BASE = "https://haveibeenpwned.com/api/v3"

    def __init__(self, target: str, config):
        self.target  = target
        self.key     = config.api_keys.haveibeenpwned
        self.timeout = config.get("timeout", 10)
        self.log     = ScanLogger("HIBP", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"HaveIBeenPwned: [cyan]{self.target}[/cyan]")
        hdrs = {
            "hibp-api-key": self.key,
            "user-agent":   "dseedeep-security-scanner",
        }
        result = {"breaches": [], "pastes": []}
        try:
            # Domain breach search
            r = requests.get(f"{self.BASE}/breacheddomain/{self.target}",
                headers=hdrs, timeout=self.timeout)
            if r.ok:
                emails_in_breach = r.json()
                result["breached_emails"] = emails_in_breach
                result["breach_count"]    = len(emails_in_breach)
                if emails_in_breach:
                    self.log.vuln(f"{len(emails_in_breach)} email accounts in breaches!")

            # All breaches metadata
            time.sleep(1.5)  # HIBP rate limit
            r2 = requests.get(f"{self.BASE}/breaches", headers=hdrs, timeout=self.timeout)
            if r2.ok:
                all_breaches = r2.json()
                # Filter breaches affecting this domain
                for breach in all_breaches:
                    if self.target.lower() in breach.get("Domain", "").lower():
                        result["breaches"].append({
                            "name":          breach.get("Name"),
                            "breach_date":   breach.get("BreachDate"),
                            "pwn_count":     breach.get("PwnCount"),
                            "data_classes":  breach.get("DataClasses", []),
                            "is_verified":   breach.get("IsVerified"),
                        })
                        self.log.vuln(f"Breach: {breach['Name']} — {breach['PwnCount']:,} accounts — {breach['BreachDate']}")

        except Exception as e:
            self.log.error(f"HIBP: {e}")
        return result
