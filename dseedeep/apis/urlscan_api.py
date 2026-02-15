"""dseedeep — URLScan.io API"""
import requests, time
from core.logger import ScanLogger


class URLScanAPI:
    def __init__(self, target: str, config):
        self.target  = target if target.startswith("http") else f"https://{target}"
        self.key     = config.api_keys.urlscan
        self.timeout = config.get("timeout", 10)
        self.log     = ScanLogger("URLSCAN", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"URLScan.io: [cyan]{self.target}[/cyan]")
        result = {}
        hdrs = {"API-Key": self.key, "Content-Type": "application/json"}
        try:
            # Submit scan
            r = requests.post("https://urlscan.io/api/v1/scan/",
                json={"url": self.target, "visibility": "public"},
                headers=hdrs, timeout=self.timeout)
            if r.ok:
                scan_id = r.json().get("uuid")
                result["scan_id"] = scan_id
                result["report_url"] = f"https://urlscan.io/result/{scan_id}/"
                self.log.found("Scan submitted", result["report_url"])

                # Wait and fetch result
                time.sleep(15)
                r2 = requests.get(f"https://urlscan.io/api/v1/result/{scan_id}/",
                                  headers=hdrs, timeout=self.timeout)
                if r2.ok:
                    data = r2.json()
                    result["screenshot"] = data.get("screenshot", "")
                    result["page"]       = data.get("page", {})
                    result["stats"]      = data.get("stats", {})
                    result["technologies"] = [t["name"] for t in data.get("meta", {}).get("processors", {}).get("wappa", {}).get("data", [])[:10]]
                    result["ips"]        = list(data.get("lists", {}).get("ips", []))[:20]
                    result["domains"]    = list(data.get("lists", {}).get("domains", []))[:20]
                    result["urls"]       = list(data.get("lists", {}).get("urls", []))[:20]

                    self.log.found("Screenshot", result["screenshot"])
                    self.log.found("IPs contacted", str(len(result["ips"])))
        except Exception as e:
            self.log.error(f"URLScan: {e}")
        return result
