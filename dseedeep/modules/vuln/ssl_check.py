"""
dseedeep — SSL/TLS Deep Analyzer
Checks certificate validity, chain, ciphers, protocols, and known vulnerabilities.
"""
import ssl
import socket
import datetime
import subprocess
from core.logger import ScanLogger

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ANON", "ADH", "AECDH"
]
WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]


class SSLChecker:
    def __init__(self, target: str, config):
        self.target  = target.replace("https://", "").replace("http://", "").split("/")[0]
        self.config  = config
        self.timeout = config.get("timeout", 10)
        self.log     = ScanLogger("SSL", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"SSL/TLS analysis for [cyan]{self.target}[/cyan]")
        result = {"target": self.target, "issues": [], "certificate": {}}

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            with socket.create_connection((self.target, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert    = ssock.getpeercert()
                    version = ssock.version()
                    cipher  = ssock.cipher()

            # Parse cert
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer  = dict(x[0] for x in cert.get("issuer", []))
            not_before = ssl.cert_time_to_seconds(cert.get("notBefore", ""))
            not_after  = ssl.cert_time_to_seconds(cert.get("notAfter", ""))
            exp_dt     = datetime.datetime.utcfromtimestamp(not_after)
            days_left  = (exp_dt - datetime.datetime.utcnow()).days

            result["certificate"] = {
                "subject":      subject.get("commonName", ""),
                "issuer":       issuer.get("organizationName", ""),
                "valid_from":   cert.get("notBefore", ""),
                "valid_until":  cert.get("notAfter", ""),
                "days_left":    days_left,
                "version":      version,
                "cipher":       cipher[0] if cipher else "",
                "san":          [v for _, v in cert.get("subjectAltName", [])],
            }

            self.log.found("Cert Subject", subject.get("commonName", ""))
            self.log.found("Issuer",       issuer.get("organizationName", ""))
            self.log.found("Expires",      f"{exp_dt.date()} ({days_left} days)")
            self.log.found("TLS Version",  version)
            self.log.found("Cipher Suite", cipher[0] if cipher else "unknown")

            # Check expiry
            if days_left < 0:
                result["issues"].append({"severity": "CRITICAL", "issue": "Certificate EXPIRED"})
                self.log.vuln("Certificate has EXPIRED!")
            elif days_left < 30:
                result["issues"].append({"severity": "HIGH", "issue": f"Certificate expires in {days_left} days"})
                self.log.warn(f"Certificate expires in {days_left} days!")

            # Weak protocol check
            if version in WEAK_PROTOCOLS:
                result["issues"].append({"severity": "HIGH", "issue": f"Weak protocol in use: {version}"})
                self.log.vuln(f"Weak TLS version: {version}")

            # Weak cipher check
            cipher_name = cipher[0] if cipher else ""
            for wc in WEAK_CIPHERS:
                if wc in cipher_name.upper():
                    result["issues"].append({"severity": "MEDIUM", "issue": f"Weak cipher: {cipher_name}"})
                    self.log.vuln(f"Weak cipher suite: {cipher_name}")
                    break

        except ssl.CertificateError as e:
            result["issues"].append({"severity": "HIGH", "issue": f"Certificate error: {e}"})
            self.log.vuln(f"Certificate error: {e}")
        except ConnectionRefusedError:
            result["issues"].append({"severity": "INFO", "issue": "Port 443 not open"})
        except Exception as e:
            self.log.error(f"SSL check failed: {e}")

        # Try testssl.sh if available
        self._testssl(result)

        self.log.success(f"SSL analysis complete — {len(result['issues'])} issues found")
        return result

    def _testssl(self, result: dict):
        """Optional: run testssl.sh for deep protocol tests."""
        try:
            r = subprocess.run(
                ["testssl", "--json", "-q", "--color", "0", self.target],
                capture_output=True, text=True, timeout=120
            )
            if r.returncode == 0:
                result["testssl_raw"] = r.stdout[:5000]
                self.log.debug("testssl.sh completed")
        except FileNotFoundError:
            self.log.debug("testssl.sh not found — skipping deep SSL test")
        except Exception:
            pass
