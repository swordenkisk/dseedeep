"""
dseedeep — Configuration Management
Loads API keys from YAML file, environment variables, or CLI args.
"""

import os
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class APIKeys:
    shodan:          Optional[str] = None
    virustotal:      Optional[str] = None
    censys_id:       Optional[str] = None
    censys_secret:   Optional[str] = None
    securitytrails:  Optional[str] = None
    hunter:          Optional[str] = None
    urlscan:         Optional[str] = None
    abuseipdb:       Optional[str] = None
    fofa_email:      Optional[str] = None
    fofa_key:        Optional[str] = None
    zoomeye:         Optional[str] = None
    greynoise:       Optional[str] = None
    binaryedge:      Optional[str] = None
    leakix:          Optional[str] = None
    ipinfo:          Optional[str] = None
    haveibeenpwned:  Optional[str] = None
    github:          Optional[str] = None
    fullhunt:        Optional[str] = None


class Config:
    """Central configuration object for dseedeep."""

    DEFAULT_CONFIG = {
        "threads":     20,
        "timeout":     10,
        "rate_limit":  0.0,
        "stealth":     False,
        "verbose":     False,
        "proxy":       None,
        "user_agent":  "Mozilla/5.0 (compatible; dseedeep/1.0; +https://github.com/dseedeep)",
        "ports":       "1-1024",
        "output_dir":  "reports",
        "report_fmt":  "all",
    }

    def __init__(self, config_file: str = "config.yaml"):
        self.api_keys = APIKeys()
        self.settings: Dict[str, Any] = dict(self.DEFAULT_CONFIG)
        self._load_file(config_file)
        self._load_env()

    def _load_file(self, path: str):
        """Load config from YAML file."""
        p = Path(path)
        if not p.exists():
            return
        try:
            with open(p) as f:
                data = yaml.safe_load(f) or {}
            keys = data.get("api_keys", {})
            for k, v in keys.items():
                if hasattr(self.api_keys, k) and v:
                    setattr(self.api_keys, k, str(v))
            settings = data.get("settings", {})
            self.settings.update(settings)
        except Exception as e:
            pass  # Silent — config is optional

    def _load_env(self):
        """Override with environment variables (DSEEDEEP_SHODAN, etc.)."""
        env_map = {
            "DSEEDEEP_SHODAN":          "shodan",
            "DSEEDEEP_VIRUSTOTAL":      "virustotal",
            "DSEEDEEP_CENSYS_ID":       "censys_id",
            "DSEEDEEP_CENSYS_SECRET":   "censys_secret",
            "DSEEDEEP_SECURITYTRAILS":  "securitytrails",
            "DSEEDEEP_HUNTER":          "hunter",
            "DSEEDEEP_URLSCAN":         "urlscan",
            "DSEEDEEP_ABUSEIPDB":       "abuseipdb",
            "DSEEDEEP_FOFA_EMAIL":      "fofa_email",
            "DSEEDEEP_FOFA_KEY":        "fofa_key",
            "DSEEDEEP_ZOOMEYE":         "zoomeye",
            "DSEEDEEP_GREYNOISE":       "greynoise",
            "DSEEDEEP_BINARYEDGE":      "binaryedge",
            "DSEEDEEP_LEAKIX":          "leakix",
            "DSEEDEEP_IPINFO":          "ipinfo",
            "DSEEDEEP_HIBP":            "haveibeenpwned",
            "DSEEDEEP_GITHUB":          "github",
            "DSEEDEEP_FULLHUNT":        "fullhunt",
        }
        for env, attr in env_map.items():
            val = os.environ.get(env)
            if val:
                setattr(self.api_keys, attr, val)

    def apply_args(self, args):
        """Apply CLI argument overrides."""
        overrides = {
            "threads":    args.threads,
            "timeout":    args.timeout,
            "rate_limit": args.rate_limit,
            "stealth":    args.stealth,
            "verbose":    args.verbose,
            "proxy":      args.proxy,
            "ports":      args.ports,
            "report_fmt": args.format,
        }
        if args.user_agent:
            overrides["user_agent"] = args.user_agent
        if args.output:
            overrides["output_dir"] = args.output
        self.settings.update({k: v for k, v in overrides.items() if v is not None})

    def has_key(self, name: str) -> bool:
        return bool(getattr(self.api_keys, name, None))

    def get(self, key: str, default=None):
        return self.settings.get(key, default)

    def proxy_dict(self) -> Optional[Dict]:
        p = self.settings.get("proxy")
        if p:
            return {"http": p, "https": p}
        return None
