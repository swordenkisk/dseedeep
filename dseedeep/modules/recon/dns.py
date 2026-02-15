"""
dseedeep — DNS Enumeration Module
Full DNS record extraction: A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV, CAA
"""

import socket
import dns.resolver
import dns.reversename
import dns.zone
import dns.query
from core.logger import ScanLogger

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA", "SRV", "DMARC", "SPF"]


class DNSEnum:
    def __init__(self, target: str, config):
        self.target  = target
        self.config  = config
        self.timeout = config.get("timeout", 10)
        self.log     = ScanLogger("DNS", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"Enumerating DNS records for [cyan]{self.target}[/cyan]")
        records = {}

        resolver = dns.resolver.Resolver()
        resolver.timeout       = self.timeout
        resolver.lifetime      = self.timeout
        resolver.nameservers   = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

        for rtype in RECORD_TYPES:
            query_name = f"_dmarc.{self.target}" if rtype == "DMARC" else self.target
            qtype = "TXT" if rtype in ("DMARC", "SPF") else rtype
            try:
                answers = resolver.resolve(query_name, qtype)
                vals = []
                for ans in answers:
                    txt = ans.to_text().strip('"')
                    if rtype == "SPF" and not txt.startswith("v=spf"):
                        continue
                    vals.append(txt)
                if vals:
                    records[rtype] = vals
                    self.log.found(rtype, " | ".join(vals[:3]))
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
            except Exception:
                pass

        # Zone transfer attempt
        self._zone_transfer(records, resolver)

        # Reverse DNS
        try:
            a_records = records.get("A", [])
            reverse_map = {}
            for ip in a_records[:5]:
                try:
                    rev = dns.reversename.from_address(ip)
                    ptr = str(resolver.resolve(rev, "PTR")[0])
                    reverse_map[ip] = ptr
                except Exception:
                    pass
            if reverse_map:
                records["PTR"] = reverse_map
                for ip, name in reverse_map.items():
                    self.log.found("PTR", f"{ip} → {name}")
        except Exception:
            pass

        self.log.success(f"Found {len(records)} record types")
        return records

    def _zone_transfer(self, records: dict, resolver: dns.resolver.Resolver):
        """Attempt AXFR zone transfer — for authorized testing."""
        try:
            ns_records = records.get("NS", [])
            for ns in ns_records[:3]:
                ns_ip = str(resolver.resolve(ns.rstrip("."), "A")[0])
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.target, timeout=5))
                    names = [str(n) for n in zone.nodes.keys()]
                    records["AXFR"] = names[:100]
                    self.log.warn(f"⚡ ZONE TRANSFER SUCCESSFUL via {ns} — {len(names)} records!")
                    return
                except Exception:
                    pass
        except Exception:
            pass
