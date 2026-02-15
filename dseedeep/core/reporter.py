"""
dseedeep — Report Generator
Produces TXT, JSON, and interactive HTML reports from scan results.
"""
import json
from datetime import datetime
from pathlib import Path
from core.logger import ScanLogger, console


class Reporter:
    def __init__(self, results: dict, out_dir: Path, fmt: str = "all"):
        self.results = results
        self.out_dir = out_dir
        self.fmt     = fmt
        self.log     = ScanLogger("REPORT")

    def generate(self):
        meta   = self.results.get("meta", {})
        target = meta.get("target", "unknown")

        if self.fmt in ("json", "all"):
            self._write_json(target)
        if self.fmt in ("txt", "all"):
            self._write_txt(target)
        if self.fmt in ("html", "all"):
            self._write_html(target)

        self.log.success(f"Reports saved → [cyan]{self.out_dir}[/cyan]")

    # ─────────────────────────────────────────────────────────────────
    def _write_json(self, target: str):
        path = self.out_dir / f"dseedeep_{target}.json"
        with open(path, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        self.log.info(f"JSON report: {path.name}")

    # ─────────────────────────────────────────────────────────────────
    def _write_txt(self, target: str):
        path = self.out_dir / f"dseedeep_{target}.txt"
        lines = [
            "=" * 70,
            f"  dseedeep Security Report — {target}",
            f"  Generated: {datetime.utcnow().isoformat()}Z",
            "=" * 70, "",
        ]
        meta = self.results.get("meta", {})
        lines += [
            f"Target  : {meta.get('target','—')}",
            f"Mode    : {meta.get('mode','—')}",
            f"Started : {meta.get('started','—')}",
            f"Elapsed : {meta.get('elapsed_s','—')}s",
            "",
        ]

        # DNS
        dns = self.results.get("dns", {})
        if dns:
            lines += ["─" * 70, "DNS RECORDS", "─" * 70]
            for rtype, vals in dns.items():
                lines.append(f"  {rtype:8s}  {vals if isinstance(vals, str) else ' | '.join(str(v) for v in (vals if isinstance(vals, list) else [str(vals)]))[:120]}")
            lines.append("")

        # WHOIS
        whois = self.results.get("whois", {})
        if whois:
            lines += ["─" * 70, "WHOIS", "─" * 70]
            for k, v in whois.items():
                lines.append(f"  {k:20s} {str(v)[:80]}")
            lines.append("")

        # Subdomains
        subs = self.results.get("subdomains", [])
        if subs:
            lines += ["─" * 70, f"SUBDOMAINS ({len(subs)})", "─" * 70]
            for s in subs:
                lines.append(f"  {s}")
            lines.append("")

        # Open Ports
        ports = self.results.get("ports", [])
        if ports:
            lines += ["─" * 70, f"OPEN PORTS ({len(ports)})", "─" * 70]
            for p in ports:
                lines.append(f"  {str(p.get('port')):6s}  {p.get('proto','tcp'):5s}  {p.get('service',''):20s}  {p.get('product','')} {p.get('version','')}")
            lines.append("")

        # Vulnerabilities
        vulns = self.results.get("vuln", [])
        if vulns:
            lines += ["─" * 70, f"VULNERABILITIES / FINDINGS ({len(vulns)})", "─" * 70]
            for v in vulns:
                if isinstance(v, dict):
                    sev = v.get("severity", "INFO")
                    lines.append(f"  [{sev:8s}] {v.get('issue', '')[:80]}")
                    if v.get("detail"):
                        lines.append(f"             {v['detail'][:80]}")
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict):
                            sev = item.get("severity", "INFO")
                            lines.append(f"  [{sev:8s}] {item.get('issue', '')[:80]}")
            lines.append("")

        # Web
        web = self.results.get("web", {})
        if web:
            lines += ["─" * 70, "WEB ANALYSIS", "─" * 70]
            techs = web.get("technologies", [])
            if techs:
                lines.append(f"  Technologies: {', '.join(t.get('name','') for t in techs[:15])}")
            missing = web.get("missing_security", [])
            if missing:
                lines.append(f"  Missing Security Headers: {len(missing)}")
                for h in missing:
                    lines.append(f"    [{h.get('severity','?'):8s}] {h.get('header','')}")
            waf = web.get("detected", [])
            if waf:
                lines.append(f"  WAF: {', '.join(waf)}")
            lines.append("")

        # APIs
        apis = self.results.get("apis", {})
        if apis:
            lines += ["─" * 70, f"API INTELLIGENCE ({len(apis)} sources)", "─" * 70]
            for api_name, api_data in apis.items():
                lines.append(f"\n  [{api_name}]")
                if isinstance(api_data, dict):
                    for k, v in list(api_data.items())[:8]:
                        val_str = str(v)[:80] if not isinstance(v, list) else str(v[:3])[:80]
                        lines.append(f"    {k:25s} {val_str}")
            lines.append("")

        # OSINT
        osint = self.results.get("osint", {})
        if osint:
            lines += ["─" * 70, "OSINT", "─" * 70]
            emails = osint.get("emails", [])
            if emails:
                lines.append(f"  Emails ({len(emails)}): {', '.join(emails[:10])}")
            dorks = osint.get("google_dorks", [])
            if dorks:
                lines.append(f"  Google Dorks: {len(dorks)} generated (see JSON)")
            lines.append("")

        lines += ["=" * 70, "END OF REPORT — dseedeep v1.0", "=" * 70]

        with open(path, "w") as f:
            f.write("\n".join(lines))
        self.log.info(f"TXT report: {path.name}")

    # ─────────────────────────────────────────────────────────────────
    def _write_html(self, target: str):
        path   = self.out_dir / f"dseedeep_{target}.html"
        meta   = self.results.get("meta", {})
        dns    = self.results.get("dns", {})
        subs   = self.results.get("subdomains", [])
        ports  = self.results.get("ports", [])
        vulns  = self.results.get("vuln", [])
        web    = self.results.get("web", {})
        apis   = self.results.get("apis", {})
        osint  = self.results.get("osint", {})
        certs  = self.results.get("certs", [])
        whois  = self.results.get("whois", {})

        # Flatten vulns
        flat_vulns = []
        for v in vulns:
            if isinstance(v, list):
                flat_vulns.extend(v)
            elif isinstance(v, dict):
                flat_vulns.append(v)

        sev_color = {"CRITICAL": "#ff2d55", "HIGH": "#ff6b35",
                     "MEDIUM": "#ffd60a", "LOW": "#30d158", "INFO": "#64d2ff"}

        def sev_badge(sev):
            c = sev_color.get(sev.upper(), "#8e8e93")
            return f'<span style="background:{c};color:#000;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">{sev}</span>'

        def rows(items, keys):
            html = ""
            for item in items[:200]:
                if isinstance(item, dict):
                    html += "<tr>" + "".join(f"<td>{str(item.get(k,''))[:120]}</td>" for k in keys) + "</tr>"
                else:
                    html += f"<tr><td>{str(item)[:120]}</td></tr>"
            return html

        total_vulns  = len(flat_vulns)
        total_ports  = len(ports)
        total_subs   = len(subs)
        total_apis   = len(apis)
        elapsed      = meta.get("elapsed_s", "?")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>dseedeep — {target}</title>
<style>
:root{{--bg:#0a0a0f;--surface:#12121a;--border:#1e1e2e;--accent:#00d4ff;--accent2:#7b2fff;--text:#e0e0f0;--dim:#606080;--danger:#ff2d55;--warn:#ffd60a;--ok:#30d158}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,monospace;line-height:1.6}}
header{{background:linear-gradient(135deg,#0a0a1a 0%,#12003a 50%,#001a2e 100%);padding:32px 40px;border-bottom:1px solid var(--border)}}
header h1{{font-size:2rem;letter-spacing:4px;color:var(--accent);text-shadow:0 0 20px rgba(0,212,255,.4)}}
header .sub{{color:var(--dim);margin-top:4px;font-size:.9rem}}
.grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:16px;padding:24px 40px}}
.stat{{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px;text-align:center;position:relative;overflow:hidden}}
.stat::before{{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--accent),var(--accent2))}}
.stat .num{{font-size:2.4rem;font-weight:700;color:var(--accent);font-family:monospace}}
.stat .label{{font-size:.8rem;color:var(--dim);text-transform:uppercase;letter-spacing:2px;margin-top:4px}}
.content{{padding:0 40px 40px}}
section{{background:var(--surface);border:1px solid var(--border);border-radius:12px;margin-bottom:20px;overflow:hidden}}
section h2{{padding:14px 20px;background:rgba(0,212,255,.06);border-bottom:1px solid var(--border);font-size:.95rem;text-transform:uppercase;letter-spacing:2px;color:var(--accent)}}
table{{width:100%;border-collapse:collapse;font-size:.85rem}}
th{{padding:10px 16px;text-align:left;background:rgba(255,255,255,.03);color:var(--dim);text-transform:uppercase;font-size:.75rem;letter-spacing:1px;border-bottom:1px solid var(--border)}}
td{{padding:9px 16px;border-bottom:1px solid rgba(30,30,46,.8);word-break:break-all;vertical-align:top}}
tr:hover td{{background:rgba(0,212,255,.03)}}
.tag{{display:inline-block;background:rgba(0,212,255,.12);color:var(--accent);border:1px solid rgba(0,212,255,.25);padding:2px 8px;border-radius:4px;font-size:11px;margin:2px}}
.port-open{{color:var(--ok);font-weight:700}}
pre{{background:#080810;padding:12px 16px;font-size:.8rem;overflow-x:auto;color:#a0c0e0;margin:0}}
.empty{{padding:20px;text-align:center;color:var(--dim);font-style:italic}}
.api-block{{padding:12px 20px;border-bottom:1px solid var(--border)}}
.api-block:last-child{{border-bottom:none}}
.api-name{{color:var(--accent);font-weight:700;font-size:.85rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}}
.kv{{display:grid;grid-template-columns:200px 1fr;gap:4px;font-size:.8rem}}
.kv .k{{color:var(--dim)}}
.kv .v{{color:var(--text);word-break:break-all}}
footer{{text-align:center;padding:24px;color:var(--dim);font-size:.8rem;border-top:1px solid var(--border)}}
</style>
</head>
<body>
<header>
  <h1>⚡ dseedeep</h1>
  <div class="sub">
    Security Reconnaissance Report &nbsp;|&nbsp;
    <strong style="color:var(--accent)">{target}</strong> &nbsp;|&nbsp;
    Mode: {meta.get('mode','—').upper()} &nbsp;|&nbsp;
    {meta.get('started','')[:19]}Z &nbsp;|&nbsp;
    Elapsed: {elapsed}s
  </div>
</header>

<div class="grid">
  <div class="stat"><div class="num">{total_subs}</div><div class="label">Subdomains</div></div>
  <div class="stat"><div class="num">{total_ports}</div><div class="label">Open Ports</div></div>
  <div class="stat"><div class="num" style="color:{'var(--danger)' if total_vulns>0 else 'var(--ok)'}">{total_vulns}</div><div class="label">Vulnerabilities</div></div>
  <div class="stat"><div class="num">{len(certs)}</div><div class="label">Certificates</div></div>
  <div class="stat"><div class="num">{total_apis}</div><div class="label">API Sources</div></div>
</div>

<div class="content">
"""

        # ── VULNERABILITIES
        if flat_vulns:
            html += '<section><h2>🔴 Vulnerabilities &amp; Findings</h2><table>'
            html += '<tr><th>Severity</th><th>Finding</th><th>Detail</th><th>Source</th></tr>'
            for v in flat_vulns[:200]:
                sev = v.get("severity","INFO").upper()
                html += (f"<tr><td>{sev_badge(sev)}</td>"
                         f"<td>{v.get('issue','')[:100]}</td>"
                         f"<td>{v.get('detail','')[:120]}</td>"
                         f"<td>{v.get('template',v.get('url',''))[:60]}</td></tr>")
            html += "</table></section>\n"
        else:
            html += '<section><h2>Vulnerabilities</h2><div class="empty">No vulnerabilities found in this scan scope</div></section>\n'

        # ── DNS
        if dns:
            html += '<section><h2>🌐 DNS Records</h2><table><tr><th>Type</th><th>Value</th></tr>'
            for rtype, vals in dns.items():
                display = vals if isinstance(vals, str) else (", ".join(str(v) for v in (vals if isinstance(vals, list) else [str(vals)])))
                html += f"<tr><td><span class='tag'>{rtype}</span></td><td>{display[:200]}</td></tr>"
            html += "</table></section>\n"

        # ── WHOIS
        if whois:
            html += '<section><h2>📋 WHOIS</h2><table><tr><th>Field</th><th>Value</th></tr>'
            for k, v in whois.items():
                html += f"<tr><td>{k}</td><td>{str(v)[:200]}</td></tr>"
            html += "</table></section>\n"

        # ── SUBDOMAINS
        if subs:
            html += f'<section><h2>🔍 Subdomains ({len(subs)})</h2><table><tr><th>Hostname</th></tr>'
            for s in subs[:500]:
                html += f"<tr><td>{s}</td></tr>"
            html += "</table></section>\n"

        # ── PORTS
        if ports:
            html += f'<section><h2>🔓 Open Ports ({len(ports)})</h2><table><tr><th>Port</th><th>Proto</th><th>Service</th><th>Product</th><th>Version</th></tr>'
            for p in ports:
                html += (f"<tr><td class='port-open'>{p.get('port','')}</td>"
                         f"<td>{p.get('proto','tcp')}</td>"
                         f"<td>{p.get('service','')}</td>"
                         f"<td>{p.get('product','')}</td>"
                         f"<td>{p.get('version','')}</td></tr>")
            html += "</table></section>\n"

        # ── WEB
        techs   = web.get("technologies", [])
        missing = web.get("missing_security", [])
        waf_det = web.get("detected", [])
        if techs or missing or waf_det:
            html += '<section><h2>🌍 Web Analysis</h2>'
            if waf_det:
                html += f'<div style="padding:12px 20px;color:var(--warn)">⚠ WAF Detected: {", ".join(waf_det)}</div>'
            if techs:
                html += '<div style="padding:8px 20px">'
                for t in techs:
                    html += f"<span class='tag'>{t.get('category','')}: {t.get('name','')}</span>"
                html += '</div>'
            if missing:
                html += '<table><tr><th>Severity</th><th>Missing Header</th></tr>'
                for h in missing:
                    html += f"<tr><td>{sev_badge(h.get('severity','?'))}</td><td>{h.get('header','')}</td></tr>"
                html += "</table>"
            html += "</section>\n"

        # ── CERTS
        if certs:
            html += f'<section><h2>🔒 Certificates ({len(certs)})</h2><table><tr><th>Subject</th><th>Issuer</th><th>Valid From</th><th>Valid Until</th></tr>'
            for c in certs[:100]:
                html += (f"<tr><td>{c.get('name','')[:80]}</td>"
                         f"<td>{c.get('issuer','')[:60]}</td>"
                         f"<td>{c.get('not_before','')[:20]}</td>"
                         f"<td>{c.get('not_after','')[:20]}</td></tr>")
            html += "</table></section>\n"

        # ── OSINT
        osint_emails = osint.get("emails", [])
        osint_dorks  = osint.get("google_dorks", [])
        osint_wb     = osint.get("wayback_urls", [])
        if osint_emails or osint_dorks or osint_wb:
            html += '<section><h2>🕵️ OSINT</h2>'
            if osint_emails:
                html += f'<div style="padding:12px 20px"><strong>Emails ({len(osint_emails)}):</strong><br>'
                for e in osint_emails[:50]:
                    html += f"<span class='tag'>{e}</span>"
                html += '</div>'
            if osint_dorks:
                html += '<table><tr><th>Category</th><th>Dork Query</th></tr>'
                for d in osint_dorks:
                    html += f"<tr><td>{d.get('name','')}</td><td><a href='{d.get('url','')}' target='_blank' style='color:var(--accent)'>{d.get('query','')[:100]}</a></td></tr>"
                html += "</table>"
            html += "</section>\n"

        # ── API INTEL
        if apis:
            html += f'<section><h2>⚡ API Intelligence ({len(apis)} sources)</h2>'
            for api_name, api_data in apis.items():
                html += f'<div class="api-block"><div class="api-name">{api_name}</div>'
                if isinstance(api_data, dict):
                    for k, v in list(api_data.items())[:12]:
                        if v:
                            val_str = ", ".join(str(i) for i in v[:5]) if isinstance(v, list) else str(v)[:150]
                            html += f'<div class="kv"><span class="k">{k}</span><span class="v">{val_str}</span></div>'
                html += '</div>'
            html += "</section>\n"

        html += f"""</div>
<footer>
  dseedeep v1.0 — Security Reconnaissance Framework &nbsp;|&nbsp;
  Report generated {datetime.utcnow().isoformat()}Z &nbsp;|&nbsp;
  <strong style="color:var(--danger)">⚠ For authorized penetration testing ONLY</strong>
</footer>
</body></html>"""

        with open(path, "w") as f:
            f.write(html)
        self.log.info(f"HTML report: {path.name}")
