"""
dseedeep — Port Scanner (nmap wrapper + raw socket fallback)
"""

import subprocess
import socket
import json
import re
from concurrent.futures import ThreadPoolExecutor
from core.logger import ScanLogger

COMMON_PORTS = [
    21,22,23,25,53,69,80,88,110,111,119,123,135,139,143,161,179,
    389,443,445,465,500,512,513,514,587,631,636,873,902,993,995,
    1080,1194,1433,1521,1723,2049,2082,2083,2086,2087,2095,2096,
    2181,2375,2376,3000,3306,3389,3690,4444,4848,5000,5432,5900,
    5984,6379,6443,7001,7443,7474,8000,8080,8081,8088,8443,8888,
    9000,9090,9200,9300,9418,9443,10000,11211,27017,27018,50070,
]


class PortScanner:
    def __init__(self, target: str, config, args=None):
        self.target  = target
        self.config  = config
        self.args    = args
        self.timeout = config.get("timeout", 10)
        self.threads = config.get("threads", 50)
        self.stealth = config.get("stealth", False)
        self.log     = ScanLogger("PORTSCAN", config.get("verbose", False))

    def run(self) -> list:
        self.log.info(f"Port scanning [cyan]{self.target}[/cyan]")

        # Try nmap first
        if self._nmap_available():
            return self._nmap_scan()
        else:
            self.log.warn("nmap not found — falling back to raw socket scan")
            return self._socket_scan()

    def _nmap_available(self) -> bool:
        try:
            subprocess.run(["nmap", "--version"], capture_output=True, timeout=5)
            return True
        except Exception:
            return False

    def _nmap_scan(self) -> list:
        ports_arg = self.args.ports if self.args and self.args.ports != "all" else "1-65535"
        cmd = ["nmap", "-oX", "-"]
        if self.stealth:
            cmd += ["-sS", "-T2", "--randomize-hosts"]
        else:
            cmd += ["-sV", "-T4"]
        if self.args and self.args.os_detect:
            cmd += ["-O"]
        if self.args and self.args.service_version:
            cmd += ["-sV", "--version-intensity", "7"]
        cmd += [f"-p{ports_arg}", self.target]

        self.log.info(f"nmap: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return self._parse_nmap_xml(result.stdout)
        except subprocess.TimeoutExpired:
            self.log.error("nmap timed out")
            return []
        except Exception as e:
            self.log.error(f"nmap error: {e}")
            return []

    def _parse_nmap_xml(self, xml: str) -> list:
        import xml.etree.ElementTree as ET
        ports = []
        try:
            root = ET.fromstring(xml)
            for host in root.findall("host"):
                for port in host.findall(".//port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        svc   = port.find("service")
                        entry = {
                            "port":    int(port.get("portid")),
                            "proto":   port.get("protocol", "tcp"),
                            "state":   "open",
                            "service": svc.get("name", "") if svc is not None else "",
                            "version": svc.get("version", "") if svc is not None else "",
                            "product": svc.get("product", "") if svc is not None else "",
                        }
                        ports.append(entry)
                        self.log.found(
                            f"Port {entry['port']}/{entry['proto']}",
                            f"{entry['service']} {entry['version']}".strip()
                        )
        except Exception as e:
            self.log.error(f"nmap XML parse error: {e}")
        return ports

    def _socket_scan(self) -> list:
        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    if s.connect_ex((self.target, port)) == 0:
                        return {"port": port, "proto": "tcp", "state": "open",
                                "service": SERVICE_MAP.get(port, "unknown")}
            except Exception:
                pass
            return None

        self.log.info(f"Raw socket scan on {len(COMMON_PORTS)} common ports…")
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            for r in ex.map(check_port, COMMON_PORTS):
                if r:
                    results.append(r)
                    self.log.found(f"Port {r['port']}", r["service"])
        self.log.success(f"Found {len(results)} open ports")
        return results


SERVICE_MAP = {
    21:"ftp", 22:"ssh", 23:"telnet", 25:"smtp", 53:"dns", 80:"http",
    110:"pop3", 143:"imap", 443:"https", 445:"smb", 993:"imaps", 995:"pop3s",
    1433:"mssql", 1521:"oracle", 3306:"mysql", 3389:"rdp", 5432:"postgres",
    5900:"vnc", 6379:"redis", 8080:"http-alt", 8443:"https-alt", 27017:"mongodb",
    9200:"elasticsearch", 9300:"elasticsearch", 11211:"memcached",
}


# ─────────────────────────────────────────────────────────────────────
"""dseedeep — Banner Grabbing"""


class BannerGrab:
    def __init__(self, target: str, open_ports: list, config):
        self.target     = target
        self.open_ports = open_ports
        self.timeout    = config.get("timeout", 10)
        self.log        = ScanLogger("BANNER", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"Grabbing banners for {len(self.open_ports)} ports…")
        banners = {}
        for entry in self.open_ports:
            port = entry.get("port")
            if not port:
                continue
            banner = self._grab(port)
            if banner:
                banners[str(port)] = banner
                self.log.found(f":{port}", banner[:80])
        return banners

    def _grab(self, port: int) -> str:
        probes = {
            80:    b"GET / HTTP/1.0\r\nHost: {target}\r\n\r\n",
            8080:  b"GET / HTTP/1.0\r\nHost: {target}\r\n\r\n",
            443:   b"GET / HTTP/1.0\r\nHost: {target}\r\n\r\n",
            21:    None,
            22:    None,
            25:    None,
        }
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((self.target, port))
                probe = probes.get(port, b"HEAD / HTTP/1.0\r\n\r\n")
                if probe:
                    s.send(probe.replace(b"{target}", self.target.encode()))
                data = s.recv(1024)
                return data.decode("utf-8", errors="replace").strip()[:200]
        except Exception:
            return ""
