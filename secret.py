#!/usr/bin/env python3
"""
SECRET OF BOUNTY - Advanced Security Scanner (CLI Edition)
Author: TehanG07
Version: 2.0
"""

import requests
import re
import math
import json
import base64
import time
import os
import sys
import hashlib
from datetime import datetime
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from collections import defaultdict
import threading

# ==================== CONFIGURATION ==================== #
class Config:
    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    TIMEOUT = 15
    THREADS = 20
    MAX_JS_SIZE = 5000000  # 5MB
    MAX_RETRIES = 2
    
    SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    
    COLORS = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH": "\033[95m",      # Magenta
        "MEDIUM": "\033[93m",    # Yellow
        "LOW": "\033[92m",       # Green
        "INFO": "\033[94m",      # Blue
        "RESET": "\033[0m",
        "BOLD": "\033[1m",
        "CYAN": "\033[96m",
        "WHITE": "\033[97m"
    }

# ==================== IGNORE LIST ==================== #
IGNORE_LIST = {
    "example", "sample", "test", "dummy", "fake", "xxxx", "xxxxx",
    "changeme", "your_api_key", "your_email", "insert_here", "localhost",
    "127.0.0.1", "development", "staging", "null", "undefined", "false",
    "00000000", "11111111", "12345678", "abcdefgh", "public", "common",
    "placeholder", "enter_your", "replace_this", "put_your", "0.0.0.0"
}

# ==================== PATTERNS DATABASE ==================== #
PATTERNS = {
    # Cloud Providers
    "AWS Access Key": (r'\b(AKIA[0-9A-Z]{16})\b', "CRITICAL"),
    "AWS Secret Key": (r'(?i)aws(.{0,20})?[\'"]?(secret|access)[\'"]?(.{0,20})?[=:\s]+[\'"]?([A-Za-z0-9/+=]{40})[\'"]?', "CRITICAL"),
    "AWS MWS Key": (r'\b(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b', "HIGH"),
    "Google API Key": (r'\b(AIza[0-9A-Za-z\-_]{35})\b', "HIGH"),
    "Google OAuth": (r'\b([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b', "HIGH"),
    "Azure Storage Key": (r'(?i)azure(.{0,20})?[\'"]?(key|storagekey)[\'"]?(.{0,20})?[=:\s]+[\'"]?([A-Za-z0-9/+=]{50,})[\'"]?', "CRITICAL"),
    "Firebase URL": (r'\b([a-z0-9-]+\.firebaseio\.com|[a-z0-9-]+\.firebase\.app)\b', "MEDIUM"),
    
    # Payment Providers
    "Stripe Live Key": (r'\b(sk_live_[0-9a-zA-Z]{24,})\b', "CRITICAL"),
    "Stripe Test Key": (r'\b(sk_test_[0-9a-zA-Z]{24,})\b', "HIGH"),
    "Stripe Publishable": (r'\b(pk_live_[0-9a-zA-Z]{24,})\b', "HIGH"),
    "Stripe Webhook": (r'\b(whsec_[a-zA-Z0-9]{32,})\b', "CRITICAL"),
    "PayPal Braintree": (r'\b(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})\b', "CRITICAL"),
    "Square Token": (r'\b(sq0atp-[0-9A-Za-z\-]{22,})\b', "HIGH"),
    "Razorpay Key": (r'\b(rzp_(live|test)_[A-Za-z0-9]{20,})\b', "HIGH"),
    
    # Version Control & CI/CD
    "GitHub Token": (r'\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b', "CRITICAL"),
    "GitLab Token": (r'\b(glpat-[A-Za-z0-9\-_]{20,})\b', "CRITICAL"),
    "GitLab Runner": (r'\b(glrt-[A-Za-z0-9\-_]{20,})\b', "HIGH"),
    "CircleCI Token": (r'\b([a-f0-9]{40})\b', "MEDIUM"),
    "Jenkins Token": (r'\b([0-9a-f]{32,64})\b', "MEDIUM"),
    
    # Communication & Monitoring
    "Slack Token": (r'\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9A-Za-z]{24,})\b', "CRITICAL"),
    "Slack Webhook": (r'\b(https://hooks\.slack\.com/services/[A-Z0-9]{9,}/[A-Z0-9]{9,}/[A-Za-z0-9]{24,})\b', "CRITICAL"),
    "Twilio API Key": (r'\b(SK[0-9a-fA-F]{32})\b', "CRITICAL"),
    "Twilio SID": (r'\b(AC[a-f0-9]{32})\b', "HIGH"),
    "SendGrid Key": (r'\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b', "CRITICAL"),
    "Mailgun Key": (r'\b(key-[0-9a-zA-Z]{32})\b', "HIGH"),
    "New Relic Key": (r'\b(NRAK-[A-Za-z0-9]{27})\b', "HIGH"),
    
    # Databases
    "MongoDB URI": (r'\b(mongodb(\+srv)?://[^\s\'"<>{},|\\^`]{10,})\b', "CRITICAL"),
    "PostgreSQL URI": (r'\b(postgres(ql)?://[^\s\'"<>{},|\\^`]{10,})\b', "CRITICAL"),
    "MySQL URI": (r'\b(mysql://[^\s\'"<>{},|\\^`]{10,})\b', "CRITICAL"),
    "Redis URI": (r'\b(redis://[^\s\'"<>{},|\\^`]{10,})\b', "CRITICAL"),
    
    # Authentication
    "JWT Token": (r'\b(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]*)\b', "HIGH"),
    "Bearer Token": (r'\b(Bearer\s+[A-Za-z0-9\-._~+/]+=*)\b', "HIGH"),
    "Basic Auth": (r'\b(Authorization:\s*Basic\s+[A-Za-z0-9+/=]{20,})\b', "CRITICAL"),
    "API Key Header": (r'(?i)(x-api-key|api-key|apikey)[\'"\s:=]+([A-Za-z0-9\-_]{20,})', "HIGH"),
    
    # Private Keys
    "RSA Private Key": (r'-----BEGIN [A-Z]+ PRIVATE KEY-----', "CRITICAL"),
    "SSH Private Key": (r'-----BEGIN OPENSSH PRIVATE KEY-----', "CRITICAL"),
    "PGP Private Key": (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', "CRITICAL"),
    
    # Endpoints & Paths
    "GraphQL Endpoint": (r'["\']?(/graphql/?|graphql/subscriptions)["\']?', "INFO"),
    "Admin Panel": (r'["\']?(/(admin|administrator|wp-admin|cpanel|dashboard)/?)["\']?', "MEDIUM"),
    "Internal API": (r'["\']?(/(internal|private|staff|dev|staging)/[a-z0-9_\-]+)["\']?', "HIGH"),
    "S3 Bucket": (r'\b([a-z0-9.-]+\.s3\.amazonaws\.com|s3://[a-z0-9.-]+)\b', "MEDIUM"),
    "Swagger UI": (r'(swagger-ui|api-docs|openapi\.json)', "INFO"),
    
    # Sensitive Data
    "Email Address": (r'\b([a-zA-Z0-9._%+-]+@(?!example\.com|test\.com|domain\.com)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', "MEDIUM"),
    "Credit Card": (r'\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b', "CRITICAL"),
    "SSN": (r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b', "CRITICAL"),
    "IP Address": (r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', "LOW"),
    "Phone Number": (r'(\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})', "MEDIUM"),
}

# ==================== UTILITY FUNCTIONS ==================== #
def get_entropy(s):
    """Calculate Shannon entropy of a string"""
    if not s:
        return 0
    s = s.strip()
    entropy = 0
    for x in set(s):
        p_x = float(s.count(x)) / len(s)
        if p_x > 0:
            entropy -= p_x * math.log(p_x, 2)
    return entropy

def luhn_check(card_number):
    """Validate credit card using Luhn algorithm"""
    try:
        card_number = re.sub(r'[-\s]', '', card_number)
        if not card_number.isdigit() or len(card_number) not in [13, 14, 15, 16, 19]:
            return False
        r = [int(x) for x in card_number[::-1]]
        return (sum(r[0::2]) + sum(sum(divmod(d*2, 10)) for d in r[1::2])) % 10 == 0
    except:
        return False

def decode_jwt(token):
    """Decode JWT token payload"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        payload_b64 = parts[1] + '=' * (-len(parts[1]) % 4)
        payload = json.loads(base64.b64decode(payload_b64))
        return payload
    except:
        return None

def is_valid_context(match_text, source_snippet, url):
    """Enhanced context validation to reduce false positives"""
    match_lower = match_text.lower()
    snippet_lower = source_snippet.lower()
    
    # Strict ignore check
    if any(x in match_lower for x in IGNORE_LIST):
        return False
    
    # Vendor file filtering
    vendor_indicators = ["installed.json", "composer.json", "package.json", "package-lock.json", "yarn.lock"]
    if any(indicator in url for indicator in vendor_indicators):
        # Ignore version numbers that look like IPs
        if re.match(r'\d+\.\d+\.\d+\.0$', match_text):
            return False
        # Ignore generic hex hashes
        if re.match(r'^[a-f0-9]{40}$', match_lower.strip()):
            return False
        # Ignore large numeric IDs
        if re.match(r'^\d{10,}$', match_text):
            return False
    
    # Phone number filtering for JS/JSON files
    if re.match(r'^\d{10,15}$', match_text):
        if any(ext in url for ext in ['.js', '.json']):
            if not any(k in snippet_lower for k in ["phone", "mobile", "contact", "tel", "fax", "cell"]):
                return False
    
    # Find match context
    idx = snippet_lower.find(match_lower)
    if idx == -1:
        return True
    
    context_window = snippet_lower[max(0, idx-80):idx+len(match_lower)+80]
    
    # Positive indicators
    positive_keywords = ["key", "secret", "token", "pass", "auth", "api", "credential", "private", "bearer"]
    if any(k in context_window for k in positive_keywords):
        return True
    
    # Negative indicators (examples/documentation)
    if re.search(r'(//|#|<!--|/\*)\s*.{0,50}(example|sample|demo)', context_window):
        return False
    
    return True

# ==================== TERMINAL UI UTILITIES ==================== #
class TerminalUI:
    @staticmethod
    def clear_screen():
        os.system('cls' if os.name == 'nt' else 'clear')
    
    @staticmethod
    def print_banner():
        banner = f"""
{Config.COLORS['CYAN']}{Config.COLORS['BOLD']}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║           ███████╗███████╗ ██████╗██████╗ ███████╗████████╗  ║
║           ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝  ║
║           ███████╗█████╗  ██║     ██████╔╝█████╗     ██║     ║
║           ╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║     ║
║           ███████║███████╗╚██████╗██║  ██║███████╗   ██║     ║
║           ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝     ║
║                                                               ║
║                    OF BOUNTY - SCANNER v2.0                   ║
║                    Advanced Security Scanner                  ║
║                      Author: TehanG07                         ║
╚═══════════════════════════════════════════════════════════════╝
{Config.COLORS['RESET']}
"""
        print(banner)
    
    @staticmethod
    def print_colored(text, color_key="WHITE", bold=False):
        color = Config.COLORS.get(color_key, Config.COLORS['WHITE'])
        bold_code = Config.COLORS['BOLD'] if bold else ''
        print(f"{bold_code}{color}{text}{Config.COLORS['RESET']}")
    
    @staticmethod
    def print_finding(finding_type, severity, value, url):
        color = Config.COLORS.get(severity, Config.COLORS['WHITE'])
        truncated_value = value[:80] + "..." if len(value) > 80 else value
        print(f"{color}[{severity}]{Config.COLORS['RESET']} {finding_type:30} | {truncated_value}")
    
    @staticmethod
    def progress_bar(current, total, prefix='', length=50):
        percent = current / total if total > 0 else 0
        filled = int(length * percent)
        bar = '█' * filled + '░' * (length - filled)
        print(f'\r{prefix} |{bar}| {percent*100:.1f}% ({current}/{total})', end='', flush=True)

# ==================== SCANNER ENGINE ==================== #
class SecurityScanner:
    def __init__(self):
        self.lock = threading.Lock()
        self.seen_findings = set()
        self.findings = defaultdict(list)
        self.stats = {
            "total_urls": 0,
            "scanned": 0,
            "failed": 0,
            "findings_count": 0
        }
    
    def _hash_finding(self, value, finding_type):
        """Generate unique hash for finding"""
        return hashlib.md5(f"{value}:{finding_type}".encode()).hexdigest()
    
    def _extract_value(self, match, pattern_name):
        """Extract the actual sensitive value from regex match"""
        if pattern_name == "AWS Secret Key":
            return match.group(4) if len(match.groups()) >= 4 else match.group(0)
        elif pattern_name == "API Key Header":
            return match.group(2) if len(match.groups()) >= 2 else match.group(0)
        else:
            return match.group(1) if match.groups() else match.group(0)
    
    def process_content(self, content, url):
        """Scan content for sensitive patterns"""
        local_findings = []
        
        for pattern_name, (regex, severity) in PATTERNS.items():
            try:
                for match in re.finditer(regex, content, re.IGNORECASE):
                    value = self._extract_value(match, pattern_name)
                    value = value.strip('\'"')
                    
                    # Skip if too long or invalid
                    if len(value) > 500 or len(value) < 3:
                        continue
                    
                    # Credit card validation
                    if pattern_name == "Credit Card":
                        if not luhn_check(value):
                            continue
                    
                    # Check if already found
                    finding_hash = self._hash_finding(value, pattern_name)
                    if finding_hash in self.seen_findings:
                        continue
                    
                    # Context validation
                    context_snippet = content[max(0, match.start()-100):match.end()+100]
                    if not is_valid_context(value, context_snippet, url):
                        continue
                    
                    # JWT enhancement
                    final_severity = severity
                    if pattern_name == "JWT Token":
                        payload = decode_jwt(value)
                        if payload:
                            if any(k in payload for k in ['admin', 'role', 'permissions']):
                                final_severity = "CRITICAL"
                    
                    # Add finding
                    with self.lock:
                        self.seen_findings.add(finding_hash)
                        local_findings.append({
                            "type": pattern_name,
                            "severity": final_severity,
                            "value": value,
                            "url": url,
                            "timestamp": datetime.now().isoformat()
                        })
                        self.stats["findings_count"] += 1
            
            except Exception as e:
                pass
        
        return local_findings
    
    def scan_url(self, url):
        """Scan a single URL"""
        try:
            response = requests.get(
                url,
                headers=Config.HEADERS,
                timeout=Config.TIMEOUT,
                allow_redirects=True,
                verify=True
            )
            
            # Scan main page
            findings = self.process_content(response.text, url)
            
            # Extract and scan JavaScript files
            soup = BeautifulSoup(response.text, "html.parser")
            js_urls = set()
            
            for script in soup.find_all("script", src=True):
                js_url = urljoin(url, script["src"])
                if js_url not in js_urls:
                    js_urls.add(js_url)
            
            # Scan JS files
            for js_url in list(js_urls)[:10]:  # Limit to 10 JS files per page
                try:
                    js_response = requests.get(
                        js_url,
                        headers=Config.HEADERS,
                        timeout=Config.TIMEOUT
                    )
                    
                    if len(js_response.content) > Config.MAX_JS_SIZE:
                        continue
                    
                    js_findings = self.process_content(js_response.text, js_url)
                    findings.extend(js_findings)
                
                except:
                    pass
            
            with self.lock:
                self.stats["scanned"] += 1
                if findings:
                    self.findings[url] = findings
            
            return True, findings
        
        except Exception as e:
            with self.lock:
                self.stats["failed"] += 1
            return False, []
    
    def scan_urls(self, urls):
        """Scan multiple URLs concurrently"""
        self.stats["total_urls"] = len(urls)
        
        TerminalUI.print_colored(f"\n[*] Starting scan of {len(urls)} URLs...", "CYAN", True)
        TerminalUI.print_colored(f"[*] Threads: {Config.THREADS} | Timeout: {Config.TIMEOUT}s\n", "WHITE")
        
        with ThreadPoolExecutor(max_workers=Config.THREADS) as executor:
            futures = {executor.submit(self.scan_url, url): url for url in urls}
            
            for i, future in enumerate(as_completed(futures), 1):
                url = futures[future]
                
                try:
                    success, findings = future.result()
                    
                    # Print findings in real-time
                    if findings:
                        print()  # New line after progress bar
                        for finding in findings:
                            TerminalUI.print_finding(
                                finding['type'],
                                finding['severity'],
                                finding['value'],
                                finding['url']
                            )
                
                except Exception as e:
                    pass
                
                # Update progress
                TerminalUI.progress_bar(i, len(urls), prefix="Progress")
        
        print("\n")  # Final newline after progress

# ==================== REPORT GENERATION ==================== #
class ReportGenerator:
    @staticmethod
    def generate_json(findings, filename="results.json"):
        """Generate JSON report"""
        data = {
            "scan_date": datetime.now().isoformat(),
            "total_findings": sum(len(f) for f in findings.values()),
            "findings": findings
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return filename
    
    @staticmethod
    def generate_html(findings, filename="results.html"):
        """Generate interactive HTML report"""
        flat_findings = []
        for url, items in findings.items():
            flat_findings.extend(items)
        
        findings_json = json.dumps(flat_findings, ensure_ascii=False)
        
        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SECRET OF BOUNTY - Security Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        :root {{
            --bg-dark: #0d1117;
            --bg-card: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --accent: #00ffcc;
            --critical: #b71c1c;
            --high: #f44336;
            --medium: #ff9800;
            --low: #4caf50;
            --info: #2196f3;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            padding: 20px;
        }}
        .header {{
            text-align: center;
            padding: 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            font-size: 2.5em;
            color: white;
            margin-bottom: 10px;
        }}
        .stats {{
            display: flex;
            justify-content: space-around;
            margin-bottom: 30px;
            gap: 20px;
        }}
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
            flex: 1;
            text-align: center;
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: var(--accent);
        }}
        .toolbar {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        button {{
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.3s;
        }}
        button:hover {{ opacity: 0.8; transform: translateY(-2px); }}
        .btn-filter {{ background: var(--accent); color: #000; }}
        .btn-export {{ background: #4caf50; color: white; }}
        .btn-clear {{ background: #f44336; color: white; }}
        select {{
            padding: 10px;
            border-radius: 5px;
            border: 1px solid var(--border);
            background: var(--bg-dark);
            color: var(--text);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #21262d;
            color: var(--accent);
            font-weight: bold;
            position: sticky;
            top: 0;
        }}
        tr:hover {{ background: #21262d; }}
        .badge {{
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 0.85em;
            font-weight: bold;
            color: white;
        }}
        .CRITICAL {{ background: var(--critical); }}
        .HIGH {{ background: var(--high); }}
        .MEDIUM {{ background: var(--medium); }}
        .LOW {{ background: var(--low); }}
        .INFO {{ background: var(--info); }}
        .value-cell {{
            font-family: 'Courier New', monospace;
            max-width: 400px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            cursor: pointer;
        }}
        .value-cell:hover {{
            white-space: normal;
            word-break: break-all;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 SECRET OF BOUNTY</h1>
        <p style="font-size: 1.2em;">Security Scan Report</p>
        <p style="margin-top: 10px; opacity: 0.9;">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <div class="stats">
        <div class="stat-card">
            <div class="stat-number" id="totalFindings">0</div>
            <div>Total Findings</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" id="criticalCount" style="color: var(--critical)">0</div>
            <div>Critical</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" id="highCount" style="color: var(--high)">0</div>
            <div>High</div>
        </div>
        <div class="stat-card">
            <div class="stat-number" id="mediumCount" style="color: var(--medium)">0</div>
            <div>Medium</div>
        </div>
    </div>

    <div class="toolbar">
        <select id="severityFilter" onchange="filterTable()">
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical Only</option>
            <option value="HIGH">High Only</option>
            <option value="MEDIUM">Medium Only</option>
            <option value="LOW">Low Only</option>
            <option value="INFO">Info Only</option>
        </select>
        <input type="text" id="searchBox" placeholder="Search..." 
               style="flex: 1; padding: 10px; border-radius: 5px; border: 1px solid var(--border); 
                      background: var(--bg-dark); color: var(--text);"
               oninput="filterTable()">
        <button class="btn-export" onclick="exportJSON()">📥 Export JSON</button>
        <button class="btn-export" onclick="exportCSV()">📊 Export CSV</button>
        <button class="btn-clear" onclick="clearFilters()">🔄 Clear Filters</button>
    </div>

    <table>
        <thead>
            <tr>
                <th width="120">Severity</th>
                <th width="200">Type</th>
                <th>Value</th>
                <th width="300">Source URL</th>
            </tr>
        </thead>
        <tbody id="tableBody"></tbody>
    </table>

    <script>
        const allFindings = {findings_json};
        let displayedFindings = [...allFindings];

        function renderTable() {{
            const tbody = document.getElementById('tableBody');
            tbody.innerHTML = '';
            
            if (displayedFindings.length === 0) {{
                tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 40px;">No findings match your filters</td></tr>';
                return;
            }}

            displayedFindings.forEach(finding => {{
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><span class="badge ${{finding.severity}}">${{finding.severity}}</span></td>
                    <td>${{escapeHtml(finding.type)}}</td>
                    <td class="value-cell" title="${{escapeHtml(finding.value)}}">${{escapeHtml(finding.value)}}</td>
                    <td><a href="${{finding.url}}" target="_blank" style="color: #58a6ff;">${{truncate(finding.url, 50)}}</a></td>
                `;
                tbody.appendChild(tr);
            }});

            updateStats();
        }}

        function updateStats() {{
            document.getElementById('totalFindings').textContent = allFindings.length;
            document.getElementById('criticalCount').textContent = allFindings.filter(f => f.severity === 'CRITICAL').length;
            document.getElementById('highCount').textContent = allFindings.filter(f => f.severity === 'HIGH').length;
            document.getElementById('mediumCount').textContent = allFindings.filter(f => f.severity === 'MEDIUM').length;
        }}

        function filterTable() {{
            const severity = document.getElementById('severityFilter').value;
            const search = document.getElementById('searchBox').value.toLowerCase();

            displayedFindings = allFindings.filter(finding => {{
                const matchesSeverity = severity === 'ALL' || finding.severity === severity;
                const matchesSearch = search === '' || 
                    finding.type.toLowerCase().includes(search) ||
                    finding.value.toLowerCase().includes(search) ||
                    finding.url.toLowerCase().includes(search);
                
                return matchesSeverity && matchesSearch;
            }});

            renderTable();
        }}

        function clearFilters() {{
            document.getElementById('severityFilter').value = 'ALL';
            document.getElementById('searchBox').value = '';
            filterTable();
        }}

        function exportJSON() {{
            const blob = new Blob([JSON.stringify(displayedFindings, null, 2)], {{type: 'application/json'}});
            downloadBlob(blob, 'findings.json');
        }}

        function exportCSV() {{
            let csv = 'Severity,Type,Value,URL\\n';
            displayedFindings.forEach(f => {{
                csv += `"${{f.severity}}","${{f.type}}","${{f.value}}","${{f.url}}"\\n`;
            }});
            const blob = new Blob([csv], {{type: 'text/csv'}});
            downloadBlob(blob, 'findings.csv');
        }}

        function downloadBlob(blob, filename) {{
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            a.click();
        }}

        function escapeHtml(text) {{
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }}

        function truncate(str, len) {{
            return str.length > len ? str.substring(0, len) + '...' : str;
        }}

        // Initialize
        renderTable();
    </script>
</body>
</html>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_template)
        
        return filename
    
    @staticmethod
    def print_summary(findings, stats):
        """Print scan summary to terminal"""
        print("\n" + "="*70)
        TerminalUI.print_colored("\n📊 SCAN SUMMARY", "CYAN", True)
        print("="*70)
        
        print(f"\nURLs Scanned: {stats['scanned']}/{stats['total_urls']}")
        print(f"Failed: {stats['failed']}")
        print(f"Total Findings: {stats['findings_count']}")
        
        # Count by severity
        severity_count = defaultdict(int)
        for url_findings in findings.values():
            for finding in url_findings:
                severity_count[finding['severity']] += 1
        
        print("\nFindings by Severity:")
        for severity in Config.SEVERITY_LEVELS:
            count = severity_count.get(severity, 0)
            if count > 0:
                color = Config.COLORS.get(severity)
                print(f"  {color}■{Config.COLORS['RESET']} {severity}: {count}")
        
        print("\n" + "="*70 + "\n")

# ==================== MAIN APPLICATION ==================== #
def main():
    TerminalUI.clear_screen()
    TerminalUI.print_banner()
    
    # Get file path
    TerminalUI.print_colored("Enter the path to your URLs file:", "CYAN", True)
    file_path = input(f"{Config.COLORS['WHITE']}> {Config.COLORS['RESET']}").strip()
    
    # Validate file
    if not os.path.isfile(file_path):
        TerminalUI.print_colored(f"\n❌ Error: File not found: {file_path}", "HIGH", True)
        sys.exit(1)
    
    # Read URLs
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and line.strip().startswith(('http://', 'https://'))]
    except Exception as e:
        TerminalUI.print_colored(f"\n❌ Error reading file: {e}", "HIGH", True)
        sys.exit(1)
    
    if not urls:
        TerminalUI.print_colored("\n❌ No valid URLs found in file!", "HIGH", True)
        sys.exit(1)
    
    TerminalUI.print_colored(f"\n✓ Loaded {len(urls)} URLs", "LOW", True)
    
    # Ask for configuration
    print(f"\n{Config.COLORS['CYAN']}Configure scan settings (press Enter for defaults):{Config.COLORS['RESET']}")
    
    try:
        threads_input = input(f"Threads [{Config.THREADS}]: ").strip()
        if threads_input:
            Config.THREADS = int(threads_input)
        
        timeout_input = input(f"Timeout (seconds) [{Config.TIMEOUT}]: ").strip()
        if timeout_input:
            Config.TIMEOUT = int(timeout_input)
    except:
        pass
    
    # Initialize scanner
    scanner = SecurityScanner()
    
    # Start scan
    start_time = time.time()
    scanner.scan_urls(urls)
    scan_duration = time.time() - start_time
    
    # Print summary
    ReportGenerator.print_summary(scanner.findings, scanner.stats)
    
    TerminalUI.print_colored(f"⏱️  Scan Duration: {scan_duration:.2f} seconds", "INFO")
    
    # Generate reports
    if scanner.findings:
        TerminalUI.print_colored("\n📝 Generating reports...", "CYAN", True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        json_file = ReportGenerator.generate_json(scanner.findings, f"results_{timestamp}.json")
        TerminalUI.print_colored(f"✓ JSON report saved: {json_file}", "LOW")
        
        html_file = ReportGenerator.generate_html(scanner.findings, f"results_{timestamp}.html")
        TerminalUI.print_colored(f"✓ HTML report saved: {html_file}", "LOW")
        
        # Ask to open HTML report
        print(f"\n{Config.COLORS['CYAN']}Open HTML report in browser? (y/n):{Config.COLORS['RESET']}", end=" ")
        if input().lower() == 'y':
            import webbrowser
            webbrowser.open('file://' + os.path.abspath(html_file))
    else:
        TerminalUI.print_colored("\n⚠️  No findings detected!", "MEDIUM", True)
    
    TerminalUI.print_colored("\n✅ Scan complete!\n", "LOW", True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        TerminalUI.print_colored("\n\n⚠️  Scan interrupted by user!", "MEDIUM", True)
        sys.exit(0)
    except Exception as e:
        TerminalUI.print_colored(f"\n❌ Fatal error: {e}", "CRITICAL", True)
        sys.exit(1)
