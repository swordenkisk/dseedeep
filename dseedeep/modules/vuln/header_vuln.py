"""dseedeep — Security Headers Vulnerability Checker (re-uses web/headers.py)"""
from modules.web.headers import HeaderAnalyzer, SECURITY_HEADERS
from core.logger import ScanLogger


class HeaderVulnChecker:
    def __init__(self, target: str, config):
        self.target = target
        self.config = config
        self.log    = ScanLogger("HDR-VULN", config.get("verbose", False))

    def run(self) -> dict:
        analyzer = HeaderAnalyzer(self.target, self.config)
        data = analyzer.run()
        vulns = []
        for miss in data.get("missing_security", []):
            sev  = miss["severity"]
            vuln = {"severity": sev, "issue": f"Missing header: {miss['header']}",
                    "detail": f"No {miss['name']} header — {sev} risk"}
            vulns.append(vuln)
            if sev in ("CRITICAL", "HIGH"):
                self.log.vuln(f"[{sev}] Missing {miss['header']}")
        return vulns
