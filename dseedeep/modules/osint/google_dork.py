"""
dseedeep — Google Dorks Generator
Generates targeted dork queries for manual use or automated scraping.
"""
from core.logger import ScanLogger


DORK_TEMPLATES = [
    ('Exposed Config Files',   'site:{t} ext:env OR ext:xml OR ext:conf OR ext:config OR ext:yml'),
    ('Admin Panels',           'site:{t} inurl:admin OR inurl:administrator OR inurl:login OR inurl:panel'),
    ('Exposed Credentials',    'site:{t} intext:password OR intext:passwd OR intext:api_key'),
    ('Sensitive Docs',         'site:{t} ext:pdf OR ext:xls OR ext:xlsx OR ext:doc OR ext:docx'),
    ('Error Messages',         'site:{t} intext:"sql syntax" OR intext:"mysql error" OR intext:"Warning: mysql"'),
    ('Directory Listings',     'site:{t} intitle:"index of" OR intitle:"Directory Listing"'),
    ('Backup Files',           'site:{t} ext:bak OR ext:backup OR ext:old OR ext:save'),
    ('Log Files',              'site:{t} ext:log OR ext:logs OR inurl:/logs/'),
    ('Database Files',         'site:{t} ext:sql OR ext:db OR ext:sqlite'),
    ('Git Exposure',           'site:{t} inurl:.git OR inurl:/.git/config'),
    ('phpinfo Pages',          'site:{t} inurl:phpinfo.php OR intitle:"PHP Version"'),
    ('Docker/K8s Exposure',    'site:{t} inurl:docker OR inurl:kubernetes OR inurl:k8s'),
    ('Cloud Buckets',          '"{t}" site:s3.amazonaws.com OR site:blob.core.windows.net OR site:storage.googleapis.com'),
    ('Open Redirects',         'site:{t} inurl:"redirect=" OR inurl:"url=" OR inurl:"goto="'),
    ('API Keys in Code',       'site:{t} intext:"api_key" OR intext:"apikey" OR intext:"access_token"'),
    ('Subdomains',             'site:*.{t} -www'),
    ('Pastebin Mentions',      'site:pastebin.com "{t}"'),
    ('GitHub Secrets',         'site:github.com "{t}" password OR secret OR key OR token'),
    ('Jenkins/CI Exposure',    'site:{t} inurl:jenkins OR inurl:build OR intitle:"Dashboard [Jenkins]"'),
    ('Camera/IoT Exposure',    'site:{t} intitle:"webcam" OR intitle:"camera" OR inurl:view/view.shtml'),
    ('Wordpress Vulnerabilities','site:{t} inurl:wp-content OR inurl:wp-admin OR inurl:xmlrpc.php'),
    ('Jira/Confluence Public', 'site:{t} inurl:jira OR inurl:confluence OR intitle:JIRA'),
    ('AWS/GCP/Azure Mentions', '"{t}" "amazonaws.com" OR "s3://" OR "azure" OR "googleapi"'),
    ('LinkedIn Employees',     'site:linkedin.com/in "{t}"'),
]


class GoogleDorks:
    def __init__(self, target: str, config):
        self.target = target
        self.config = config
        self.log    = ScanLogger("DORKS", config.get("verbose", False))

    def run(self) -> dict:
        self.log.info(f"Generating Google Dorks for [cyan]{self.target}[/cyan]")
        dorks = []
        for name, template in DORK_TEMPLATES:
            query = template.replace("{t}", self.target)
            url   = f"https://www.google.com/search?q={query}"
            dorks.append({"name": name, "query": query, "url": url})
            self.log.found(name, query[:80])

        self.log.success(f"Generated {len(dorks)} dork queries — use them in a browser or automated tool")
        return {"google_dorks": dorks}
