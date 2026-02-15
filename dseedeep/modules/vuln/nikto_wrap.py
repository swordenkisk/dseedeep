"""
dseedeep — Nikto Web Scanner Wrapper
Executes Nikto and parses its JSON output for structured results.
"""
import subprocess
import json
import tempfile
from pathlib import Path
from core.logger import ScanLogger


class NiktoScanner:
    def __init__(self, target: str, config):
        self.target  = target
        self.config  = config
        self.timeout = 600
        self.log     = ScanLogger("NIKTO", config.get("verbose", False))

    def run(self) -> list:
        self.log.info(f"Nikto scan on [cyan]{self.target}[/cyan]")
        findings = []

        if not self._nikto_available():
            self.log.warn("nikto not found — install with: apt-get install nikto")
            return [{"severity": "INFO", "issue": "Nikto not installed", "detail": "apt-get install nikto"}]

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            outfile = f.name

        try:
            cmd = ["nikto", "-h", self.target, "-Format", "json",
                   "-output", outfile, "-nointeractive"]
            if self.config.proxy_dict():
                proxy = list(self.config.proxy_dict().values())[0]
                cmd += ["-useproxy", proxy]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)

            if Path(outfile).exists():
                with open(outfile) as f:
                    data = json.load(f)
                for vuln in data.get("vulnerabilities", []):
                    entry = {
                        "severity": self._map_severity(vuln.get("OSVDB", "")),
                        "issue":    vuln.get("msg", ""),
                        "url":      vuln.get("url", ""),
                        "method":   vuln.get("method", ""),
                        "detail":   f"OSVDB: {vuln.get('OSVDB', 'N/A')}",
                    }
                    findings.append(entry)
                    self.log.vuln(entry["issue"][:100])
        except subprocess.TimeoutExpired:
            self.log.error("Nikto timed out")
        except Exception as e:
            self.log.error(f"Nikto error: {e}")
        finally:
            Path(outfile).unlink(missing_ok=True)

        self.log.success(f"Nikto: {len(findings)} findings")
        return findings

    def _nikto_available(self) -> bool:
        try:
            subprocess.run(["nikto", "-Version"], capture_output=True, timeout=5)
            return True
        except Exception:
            return False

    def _map_severity(self, osvdb: str) -> str:
        if not osvdb or osvdb == "0":
            return "INFO"
        return "MEDIUM"
