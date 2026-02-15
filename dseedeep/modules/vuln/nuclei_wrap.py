"""
dseedeep — Nuclei Template Scanner Wrapper
Uses ProjectDiscovery's Nuclei for template-based vulnerability scanning.
"""
import subprocess
import json
from core.logger import ScanLogger


class NucleiScanner:
    def __init__(self, target: str, config, args=None):
        self.target  = target
        self.config  = config
        self.args    = args
        self.timeout = 900
        self.log     = ScanLogger("NUCLEI", config.get("verbose", False))

    def run(self) -> list:
        self.log.info(f"Nuclei scan on [cyan]{self.target}[/cyan]")
        findings = []

        if not self._nuclei_available():
            self.log.warn("nuclei not found — install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            return [{"severity": "INFO", "issue": "Nuclei not installed"}]

        tags = self.args.nuclei_tags if self.args else "cve,exposure,misconfiguration"
        cmd  = [
            "nuclei", "-u", self.target,
            "-tags", tags,
            "-json", "-silent",
            "-timeout", str(self.config.get("timeout", 10)),
            "-c",     str(self.config.get("threads", 20)),
        ]

        if self.config.proxy_dict():
            proxy = list(self.config.proxy_dict().values())[0]
            cmd += ["-proxy", proxy]

        self.log.info(f"Tags: {tags}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    info    = data.get("info", {})
                    finding = {
                        "severity":  info.get("severity", "unknown").upper(),
                        "issue":     info.get("name", ""),
                        "url":       data.get("matched-at", ""),
                        "template":  data.get("template-id", ""),
                        "tags":      info.get("tags", []),
                        "detail":    info.get("description", "")[:200],
                        "reference": info.get("reference", [])[:3],
                    }
                    findings.append(finding)
                    icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","INFO":"🔵"}.get(finding["severity"], "⚪")
                    self.log.vuln(f"{icon} [{finding['severity']}] {finding['issue']}")
                except json.JSONDecodeError:
                    pass
        except subprocess.TimeoutExpired:
            self.log.error("Nuclei timed out")
        except Exception as e:
            self.log.error(f"Nuclei error: {e}")

        self.log.success(f"Nuclei: {len(findings)} findings")
        return findings

    def _nuclei_available(self) -> bool:
        try:
            subprocess.run(["nuclei", "-version"], capture_output=True, timeout=5)
            return True
        except Exception:
            return False
