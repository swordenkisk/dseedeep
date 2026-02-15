"""
dseedeep — Rich terminal output, logging, and banner
"""

import logging
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.theme import Theme
from rich.logging import RichHandler
from rich.text import Text

# Global console
theme = Theme({
    "info":    "bold cyan",
    "success": "bold green",
    "warn":    "bold yellow",
    "error":   "bold red",
    "module":  "bold magenta",
    "target":  "bold white",
    "dim":     "dim white",
    "data":    "bright_white",
    "vuln":    "bold red on dark_red",
    "found":   "bold green",
})
console = Console(theme=theme, highlight=True)

BANNER = r"""
[bold cyan]
██████╗ ███████╗███████╗███████╗██████╗ ███████╗███████╗██████╗ 
██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗
██║  ██║███████╗█████╗  █████╗  ██║  ██║█████╗  █████╗  ██████╔╝
██║  ██║╚════██║██╔══╝  ██╔══╝  ██║  ██║██╔══╝  ██╔══╝  ██╔═══╝ 
██████╔╝███████║███████╗███████╗██████╔╝███████╗███████╗██║      
╚═════╝ ╚══════╝╚══════╝╚══════╝╚═════╝ ╚══════╝╚══════╝╚═╝     
[/bold cyan]
[dim]  Advanced Security Reconnaissance Framework  v1.0
  [bold yellow]⚠  For authorized penetration testing ONLY[/bold yellow]
  Modules: Recon · Active · OSINT · Web · Vuln · 13 APIs[/dim]
"""


def banner():
    console.print(BANNER)


def get_logger(name: str, log_file: Path = None) -> logging.Logger:
    """Return a configured logger for a module."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    handler = RichHandler(console=console, show_path=False, markup=True)
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)

    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        fmt = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


class ScanLogger:
    """High-level scan-aware logger with structured output."""

    def __init__(self, module: str, verbose: bool = False):
        self.module = module
        self.verbose = verbose

    def info(self, msg: str):
        console.print(f"[dim][[/dim][module]{self.module}[/module][dim]][/dim] {msg}")

    def success(self, msg: str):
        console.print(f"[dim][[/dim][module]{self.module}[/module][dim]][/dim] [success]✓[/success] {msg}")

    def found(self, label: str, value: str):
        console.print(f"  [found]→[/found] [bold]{label}:[/bold] [data]{value}[/data]")

    def warn(self, msg: str):
        console.print(f"[dim][[/dim][module]{self.module}[/module][dim]][/dim] [warn]⚠[/warn]  {msg}")

    def error(self, msg: str):
        console.print(f"[dim][[/dim][module]{self.module}[/module][dim]][/dim] [error]✗[/error]  {msg}")

    def vuln(self, msg: str):
        console.print(f"  [vuln] VULN [/vuln] {msg}")

    def debug(self, msg: str):
        if self.verbose:
            console.print(f"[dim]  [{self.module}] {msg}[/dim]")

    def section(self, title: str):
        console.rule(f"[bold cyan]{title}[/bold cyan]")
