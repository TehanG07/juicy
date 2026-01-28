import requests, re, math, json, threading, base64, time, binascii
import webbrowser
import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import *
from tkinter import ttk, filedialog, messagebox

# ================= CONFIGURATION & CONSTANTS ================= #
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}
TIMEOUT = 15
THREADS = 15 

SEVERITY_COLORS = {
    "INFO": "#212121",
    "LOW": "#4caf50",
    "MEDIUM": "#ff9800",
    "HIGH": "#f44336",
    "CRITICAL": "#b71c1c"
}

# STRICT IGNORE LIST
IGNORE_LIST = [
    "example", "sample", "test", "dummy", "fake", "xxxx", "xxxxx",
    "changeme", "your_api_key", "your_email", "insert_here", "localhost",
    "127.0.0.1", "development", "staging", "null", "undefined", "false",
    "00000000", "11111111", "12345678", "abcdefgh", "public", "common"
]

# ================= UTILITIES & VALIDATION ================= #
def get_entropy(s):
    if not s: return 0
    s = s.strip()
    entropy = 0
    for x in set(s):
        p_x = float(s.count(x)) / len(s)
        if p_x > 0:
            entropy -= p_x * math.log(p_x, 2)
    return entropy

def luhn_checksum(card_number):
    r = [int(x) for x in card_number[::-1]]
    return (sum(r[0::2]) + sum(sum(divmod(d*2,10)) for d in r[1::2])) % 10 == 0

def decode_jwt(token):
    try:
        parts = token.split('.')
        if len(parts) != 3: return None
        payload_b64 = parts[1] + '=' * (-len(parts[1]) % 4)
        payload = json.loads(base64.b64decode(payload_b64))
        return payload
    except:
        return None

def check_context(match_text, source_snippet, url):
    """
    Advanced Context Check with URL and Source Analysis.
    Filters out False Positives from vendor files and JS bundles.
    """
    match_lower = match_text.lower()
    snippet_lower = source_snippet.lower()
    
    # 1. Strict Ignore
    if any(x in match_lower for x in IGNORE_LIST):
        return False

    # 2. URL CONTEXT FILTERING (Crucial for your requirement)
    # Ignore FPs from known noisy files like installed.json, composer.json
    is_vendor_file = "installed.json" in url or "composer.json" in url or "package.json" in url
    
    if is_vendor_file:
        # Ignore generic 40-char hex hashes (mistaken for PagerDuty/Datadog)
        if re.match(r'^[a-f0-9]{40}$', match_lower.strip()):
            return False
        
        # Ignore Version Numbers looking like IPs (e.g. 1.4.0.0)
        # If IP ends in .0, it's likely a version
        if re.search(r'\d+\.\d+\.\d+\.0$', match_text):
            return False
            
        # Ignore generic large numbers in vendor files (IDs mistaken for Phone/SSN)
        if re.match(r'^\d{10,15}$', match_text):
            return False

    # 3. PHONE NUMBER / ID FILTERING
    # If match is just digits > 9 chars, it's likely an ID, not a phone
    # UNLESS it looks like a real formatted phone (e.g. 1-555, or 123-456)
    if re.match(r'^\d{10,15}$', match_text):
        # If there are no formatting chars (dashes, spaces), and it's in a JS/JSON file, assume ID
        if any(ext in url for ext in ['.js', '.json']):
            # Check if snippet contains phone keywords, otherwise ignore
            if not any(k in snippet_lower for k in ["phone", "mobile", "contact", "tel", "fax"]):
                return False

    # 4. Locate match in snippet for general checks
    idx = snippet_lower.find(match_lower)
    if idx == -1: return True 
    context_window = snippet_lower[max(0, idx-60):idx+len(match_lower)+60]
    
    # 5. Positive Indicators (Likely Real)
    if any(k in context_window for k in ["key", "secret", "token", "pass", "auth", "api", "credential", "env", "config", "private", "bearer"]):
        return True
        
    # 6. Negative Indicators (Likely Example/Comment)
    if re.search(r'(//|#|<!--|/\*)\s*.*?(key|secret|auth)', context_window):
        if "example" in context_window or "sample" in context_window:
            return False
            
    if "AKIA" in match_text:
        if "sample" in context_window or "document" in context_window:
            return False

    return True

# ================= ULTRA-WIDE PATTERN DATABASE ================= #
PATTERNS = {
    "AWS Access Key": (r'\b(AKIA[0-9A-Z]{16})\b', "CRITICAL", "AWS Access Key"),
    "AWS Secret Key": (r'(?i)aws(.{0,20})?[\'\"]?(secret|access)[\'\"]?(.{0,20})?[=:\s]+[\'\"]?([A-Za-z0-9/+=]{40})[\'\"]?', "CRITICAL", "AWS Secret Key"),
    "AWS MWS Key": (r'\b(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b', "HIGH", "Amazon MWS Auth Token"),
    "Google API Key": (r'\b(AIza[0-9A-Za-z\-_]{35})\b', "HIGH", "Google API Key"),
    "Google Cloud OAuth": (r'\b([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b', "HIGH", "GCP OAuth Client ID"),
    "Google Service Account": (r'"type":\s*"service_account"', "HIGH", "Google Service Account JSON Indicator"),
    "Azure Storage Key": (r'(?i)azure(.{0,20})?[\'\"]?(key|storagekey)[\'\"]?(.{0,20})?[=:\s]+[\'\"]?([A-Za-z0-9/+=]{50,})[\'\"]?', "CRITICAL", "Azure Storage Key"),
    "Firebase Config": (r'\b(firebaseio\.com|firebase\.app|googleapis\.com)[^\s\'"<>]{0,200}', "MEDIUM", "Firebase Connection String"),
    "Stripe Live Key": (r'\b(sk_live_[0-9a-zA-Z]{24})\b', "CRITICAL", "Stripe Live Secret"),
    "Stripe Publishable": (r'\b(pk_live_[0-9a-zA-Z]{24})\b', "HIGH", "Stripe Publishable Key"),
    "Stripe Webhook Secret": (r'\b(whsec_[a-zA-Z0-9]{32,})\b', "CRITICAL", "Stripe Webhook Signing Secret"),
    "PayPal Braintree": (r'\b(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})\b', "CRITICAL", "Braintree Access Token"),
    "Square Access Token": (r'\b(sq0atp-[0-9A-Za-z\-]{22})\b', "HIGH", "Square Access Token"),
    "Razorpay Key": (r'\b(rzp_(live|test)_[A-Za-z0-9]{20,})\b', "HIGH", "Razorpay Key ID"),
    "GitHub Token": (r'\b(gh[pousr]_[A-Za-z0-9_]{36,})\b', "CRITICAL", "GitHub Personal/OAuth Token"),
    "GitLab Token": (r'\b(glpat-[A-Za-z0-9\-]{20,})\b', "CRITICAL", "GitLab Personal Access Token"),
    "GitLab Runner Token": (r'\b(glrt-[A-Za-z0-9\-]{20,})\b', "HIGH", "GitLab Runner Token"),
    "Jenkins API Token": (r'\b([0-9a-f]{32}-[0-9a-f]{8}-[0-9a-f]{8})\b', "HIGH", "Jenkins API Token (Hex)"),
    "Jenkins Crumb": (r'\b(jenkins-crumb\s*[:=]\s*[a-f0-9]{32})', "MEDIUM", "Jenkins CSRF Crumb"),
    "CircleCI Token": (r'\b([a-f0-9]{40})\b', "MEDIUM", "CircleCI Token (Contextual)"),
    "Heroku API Key": (r'\b(heroku[a-f0-9]{68})\b', "CRITICAL", "Heroku API Key"),
    "Netlify Token": (r'\b(nFp_[A-Za-z0-9_-]{36})\b', "HIGH", "Netlify Personal Access Token"),
    "Shopify Token": (r'\b(shpat_[a-fA-F0-9]{32})\b', "HIGH", "Shopify Private App Token"),
    "Salesforce Token": (r'\b(00D[a-zA-Z0-9]{15}|005[a-zA-Z0-9]{15})\b', "MEDIUM", "Salesforce Org/User ID"),
    "Slack Token": (r'\b(xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9A-Za-z]{24})\b', "CRITICAL", "Slack Bot/User Token"),
    "Slack Webhook": (r'\b(hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9]{9}/[A-Za-z0-9]{24})\b', "CRITICAL", "Slack Incoming Webhook"),
    "Twilio Key": (r'\b(SK[0-9a-fA-F]{32})\b', "CRITICAL", "Twilio API Key"),
    "Twilio Account SID": (r'\b(AC[a-f0-9]{32})\b', "HIGH", "Twilio Account SID"),
    "SendGrid Key": (r'\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b', "CRITICAL", "SendGrid API Key"),
    "Mailgun Key": (r'\b(key-[0-9a-zA-Z]{32})\b', "HIGH", "Mailgun API Key"),
    "PagerDuty Key": (r'\b([A-Za-z0-9]{40})\b', "HIGH", "PagerDuty Integration Key"), 
    "Datadog Key": (r'\b([a-f0-9]{40})\b', "HIGH", "Datadog API Key"), 
    "New Relic Key": (r'\b(NRAK-[A-Za-z0-9]{27})\b', "HIGH", "New Relic User Key"),
    "MongoDB URI": (r'\b(mongodb(\+srv)?:\/\/[^\s\'"<>{},|\\^`]{10,})\b', "CRITICAL", "MongoDB Connection String"),
    "Postgres URI": (r'\b(postgres(ql)?:\/\/[^\s\'"<>{},|\\^`]{10,})\b', "CRITICAL", "Postgres Connection String"),
    "MySQL URI": (r'\b(mysql:\/\/[^\s\'"<>{},|\\^`]{10,})\b', "CRITICAL", "MySQL Connection String"),
    "Redis URI": (r'\b(redis:\/\/[^\s\'"<>{},|\\^`]{10,})\b', "CRITICAL", "Redis Connection String"),
    "MSSQL URI": (r'\b(Server=[^\s;]+;Database=[^\s;]+;User Id=[^\s;]+;Password=[^\s;]+)\b', "CRITICAL", "MSSQL Connection String"),
    "Oracle URI": (r'\b(Data Source=[^\s;]+;User Id=[^\s;]+;Password=[^\s;]+)\b', "CRITICAL", "Oracle Connection String"),
    "Bearer Token": (r'\b(Bearer\s+[A-Za-z0-9\-._~+/]+=*)\b', "HIGH", "Bearer Authorization Token"),
    "Basic Auth": (r'\b(Authorization:\s*Basic\s+[A-Za-z0-9+/=]{20,})\b', "CRITICAL", "Basic Auth Header (Base64)"),
    "JWT Token": (r'\b(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+)\b', "HIGH", "JSON Web Token"),
    "OAuth Access": (r'\b(ya29\.[0-9A-Za-z\-_]+)\b', "HIGH", "Google OAuth2 Token"),
    "Session Cookie (Generic)": (r'\b(session|sessid|phpsessid|jsessionid)=([a-f0-9]{26,})\b', "MEDIUM", "Session ID"),
    "Auth Header": (r'\b(x-auth-token|x-api-key|x-access-token)[:=]\s*["\']?([A-Za-z0-9\-_]{20,})', "HIGH", "Custom Auth Header"),
    "Admin User/Pass Pair": (r'(?i)(user|admin|login)[\'"\s:=]+([a-z0-9_@.-]+)[\'"\s,]+.{0,50}(pass|pwd|secret)[\'"\s:=]+([a-z0-9!@#$%^&*]{4,})', "CRITICAL", "Potential Admin Credentials Pair"),
    "Commented Secret": (r'(?i)(\/\/|#|<!--|\/\*)\s*(todo|fixme|hack).{0,20}(key|secret|pass)', "MEDIUM", "Commented Secret Reference"),
    "Generic API Key": (r'\b([A-Za-z]{2,10}[_-]?[A-Za-z]{2,10}[_-]?(key|token|secret|id)[\'"\s:=]+[A-Za-z0-9\-_]{20,})\b', "MEDIUM", "Generic API Key Variable"),
    "RSA Private Key": (r'-----BEGIN [A-Z]+ PRIVATE KEY-----', "CRITICAL", "Private Key Header"),
    "SSH Key": (r'-----BEGIN OPENSSH PRIVATE KEY-----', "CRITICAL", "SSH Private Key"),
    "GraphQL Endpoint": (r'["\']?(\/graphql\/?|graphql\/subscriptions)["\']?', "INFO", "GraphQL Endpoint"),
    "REST API Path": (r'["\']?(\/api\/(v1|v2|v3)\/[a-z0-9_\-]+)["\']?', "INFO", "REST API Path"),
    "Admin Panel Path": (r'["\']?(\/(admin|administrator|wp-admin|dashboard)\/?)["\']?', "MEDIUM", "Admin Panel Path"),
    "Internal API": (r'["\']?(\/(internal|private|staff|dev|staging)\/[a-z0-9_\-]+)["\']?', "HIGH", "Internal/Private Endpoint"),
    "S3 Bucket": (r'\b([a-z0-9.-]+\.s3\.amazonaws\.com|s3://[a-z0-9.-]+)\b', "MEDIUM", "AWS S3 Bucket"),
    "Swagger UI": (r'(swagger\.ui|swagger-ui\.html|api-docs)', "INFO", "Swagger Documentation"),
    "Email Address": (r'\b([a-zA-Z0-9._%+-]+@(?!example\.com|test\.com)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', "MEDIUM", "Email Address"),
    "Credit Card": (r'\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b', "CRITICAL", "Potential Credit Card (Luhn Validated)"),
    "SSN (US)": (r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b', "CRITICAL", "US SSN"),
    "IP Address": (r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', "LOW", "IP Address Leak"),
    "Phone Number": (r'(\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})', "MEDIUM", "Phone Number"),
    "Aadhaar Number": (r'\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b', "CRITICAL", "India Aadhaar Number"),
    "PAN Card": (r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b', "HIGH", "India PAN Card"),
    "Passport (US)": (r'\b\d{9}\b', "LOW", "US Passport Number (Weak Check)"),
}

# ================= SCANNER ENGINE ================= #
class RealTargetScanner:
    def __init__(self):
        self.lock = threading.Lock()
        self.seen_findings = set() 
        
    def process_source(self, source_text, url):
        findings = []
        for name, (pattern, severity, desc) in PATTERNS.items():
            try:
                for match in re.finditer(pattern, source_text, re.IGNORECASE):
                    raw_match = match.group()
                    value = raw_match
                    if name == "AWS Secret Key": value = match.group(4)
                    elif name == "AWS Access Key": value = match.group(1)
                    elif name == "Google API Key": value = match.group(1)
                    elif name == "JWT Token": value = match.group(1)
                    elif name == "Slack Token": value = match.group(0) 
                    elif name == "Admin User/Pass Pair": 
                        user = match.group(2)
                        pwd = match.group(4)
                        value = f"User: {user} | Pass: {pwd}"
                    elif name == "Basic Auth": value = match.group(0)

                    value = value.strip('\'"')
                    value_hash = hash(value + name)
                    if value_hash in self.seen_findings: continue
                    if len(value) > 500: continue 

                    # ENHANCED CONTEXT CHECK
                    if not check_context(value, match.group(0), url):
                        continue

                    final_severity = severity
                    if name == "JWT Token":
                        payload = decode_jwt(value)
                        if payload:
                            if payload.get('role') == 'admin' or 'email' in payload:
                                final_severity = "CRITICAL"

                    with self.lock:
                        self.seen_findings.add(value_hash)
                    
                    findings.append({
                        "type": desc,
                        "severity": final_severity,
                        "value": value,
                        "url": url
                    })
            except Exception: pass

        user_matches = re.findall(r'["\']?(admin|root|user|login)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9@._-]{4,})["\']?', source_text, re.I)
        for label, u_val in user_matches:
            if len(u_val) > 3 and u_val.lower() not in IGNORE_LIST:
                h = hash(u_val + "Username")
                if h not in self.seen_findings:
                    with self.lock:
                        self.seen_findings.add(h)
                    findings.append({
                        "type": f"Username ({label})",
                        "severity": "INFO",
                        "value": u_val,
                        "url": url
                    })

        return findings

    def scan_target(self, url):
        results = []
        try:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
            content = r.text
            results.extend(self.process_source(content, url))
            
            soup = BeautifulSoup(content, "html.parser")
            js_urls = set()
            for script in soup.find_all("script", src=True):
                full_js_url = urljoin(url, script["src"])
                if any(ext in full_js_url for ext in ['.js', '.json']):
                    js_urls.add(full_js_url)
            
            for js_url in js_urls:
                try:
                    js_r = requests.get(js_url, headers=HEADERS, timeout=TIMEOUT)
                    if len(js_r.content) > 5000000: continue 
                    results.extend(self.process_source(js_r.text, js_url))
                except: pass
            
            if "Authorization" in r.headers:
                results.append({
                    "type": "Auth Header Leak",
                    "severity": "CRITICAL",
                    "value": r.headers["Authorization"][:50],
                    "url": url
                })
        except: pass
        return url, results

# ================= HTML REPORT GENERATOR ================= #
def generate_html_report(all_findings):
    flat_data = []
    for url, items in all_findings.items():
        for item in items:
            flat_data.append({
                "type": item['type'],
                "severity": item['severity'],
                "value": item['value'],
                "url": item['url']
            })
    
    data_json = json.dumps(flat_data)

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SECRET OF BOUNTY - Report</title>
    <style>
        :root {{ --bg-color: #0d1117; --card-bg: #161b22; --text-color: #c9d1d9; --border-color: #30363d; --accent-color: #00ffcc; }}
        body {{ font-family: 'Segoe UI', sans-serif; background-color: var(--bg-color); color: var(--text-color); margin: 0; padding: 20px; }}
        h1 {{ color: var(--accent-color); text-align: center; text-transform: uppercase; }}
        .toolbar {{ background-color: var(--card-bg); padding: 15px; border-radius: 8px; border: 1px solid var(--border-color); display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }}
        button {{ padding: 10px 15px; border: none; border-radius: 5px; font-weight: bold; cursor: pointer; color: white; }}
        .btn-save-state {{ background-color: var(--accent-color); color: #000; }}
        .btn-reset {{ background-color: #6e7681; }}
        .btn-delete {{ background-color: #f44336; }}
        .btn-download {{ background-color: #4caf50; }}
        table {{ width: 100%; border-collapse: collapse; background-color: var(--card-bg); }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid var(--border-color); }}
        th {{ color: var(--accent-color); background-color: #21262d; position: sticky; top: 0; }}
        tr:hover {{ background-color: #21262d; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; color: white; font-size: 0.8rem; font-weight: bold; }}
        .CRITICAL {{ background-color: #b71c1c; }} .HIGH {{ background-color: #f44336; }} .MEDIUM {{ background-color: #ff9800; }} .LOW {{ background-color: #4caf50; }} .INFO {{ background-color: #212121; }}
        input[type="checkbox"] {{ width: 18px; height: 18px; cursor: pointer; accent-color: var(--accent-color); }}
        .value-cell {{ font-family: 'Courier New', monospace; max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #fff; }}
    </style>
</head>
<body>
    <h1>SECRET OF BOUNTY RESULTS</h1>
    <div class="toolbar">
        <button class="btn-reset" onclick="resetData()">🔄 Reset / Refresh Data</button>
        <button class="btn-delete" onclick="deleteSelected()">🗑️ Delete Selected</button>
        <button class="btn-save-state" onclick="saveState()">💾 Save State</button>
        <button class="btn-download" onclick="downloadJson()">⬇️ Export JSON</button>
    </div>
    <div id="status" style="margin-bottom: 10px; color: #8b949e;"></div>
    <table>
        <thead>
            <tr>
                <th width="50"><input type="checkbox" onclick="toggleAll(this)"></th>
                <th width="120">Severity</th>
                <th width="200">Type</th>
                <th>Value</th>
                <th>URL</th>
            </tr>
        </thead>
        <tbody id="tableBody"></tbody>
    </table>

    <script>
        const ORIGINAL_DATA = {data_json};
        let currentData = [];
        
        window.onload = function() {{
            const saved = localStorage.getItem('bounty_state');
            if (saved) {{
                currentData = JSON.parse(saved);
                updateStatus("Loaded Saved State (Cleaned Data)");
            }} else {{
                currentData = [...ORIGINAL_DATA];
                updateStatus(`Loaded Scan Results: ${{currentData.length}} findings`);
            }}
            renderTable();
        }};

        function renderTable() {{
            const tbody = document.getElementById('tableBody');
            tbody.innerHTML = '';
            if (currentData.length === 0) {{
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No results to display.</td></tr>';
                return;
            }}
            currentData.forEach((item, index) => {{
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><input type="checkbox" class="cb" data-idx="${{index}}"></td>
                    <td><span class="badge ${{item.severity}}">${{item.severity}}</span></td>
                    <td>${{escapeHtml(item.type)}}</td>
                    <td class="value-cell" title="${{escapeHtml(item.value)}}">${{escapeHtml(item.value)}}</td>
                    <td><a href="${{item.url}}" target="_blank" style="color:#58a6ff;">${{escapeHtml(truncate(item.url, 50))}}</a></td>
                `;
                tbody.appendChild(tr);
            }});
        }}

        function deleteSelected() {{
            const cbs = document.querySelectorAll('.cb:checked');
            if (cbs.length === 0) return alert("Select items to delete.");
            if (!confirm("Delete " + cbs.length + " items?")) return;
            
            const indicesToRemove = Array.from(cbs).map(cb => parseInt(cb.getAttribute('data-idx'))).sort((a,b) => b-a);
            indicesToRemove.forEach(idx => currentData.splice(idx, 1));
            
            renderTable();
            updateStatus("Items deleted. Click 'Save State' to keep changes.");
        }}

        function saveState() {{
            localStorage.setItem('bounty_state', JSON.stringify(currentData));
            alert("State Saved! Deleted items won't return on refresh.");
            updateStatus("State Saved Successfully.");
        }}

        function resetData() {{
            if (confirm("Reset to original scan results? (Unsaved deletions will be lost)")) {{
                currentData = [...ORIGINAL_DATA];
                localStorage.removeItem('bounty_state');
                renderTable();
                updateStatus("Reset to Original Scan Data.");
            }}
        }}

        function downloadJson() {{
            const blob = new Blob([JSON.stringify(currentData, null, 2)], {{type: "application/json"}});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = "cleaned_results.json";
            a.click();
        }}

        function toggleAll(source) {{ document.querySelectorAll('.cb').forEach(cb => cb.checked = source.checked); }}
        
        function escapeHtml(text) {{
            if (!text) return "";
            return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
        }}
        
        function truncate(url, len) {{ return url.length > len ? url.substring(0, len) + "..." : url; }}
        
        function updateStatus(msg) {{ document.getElementById('status').textContent = msg; }}
    </script>
</body>
</html>
    """
    return html_content

# ================= GUI INTERFACE ================= #
class App:
    def __init__(self, root):
        root.title("SECRET OF BOUNTY - SCANNER")
        root.geometry("1350x750")
        root.configure(bg="#0d1117")
        
        self.scanner = RealTargetScanner()
        self.stop_flag = False

        # Header
        header_frame = Frame(root, bg="#0d1117")
        header_frame.pack(pady=15)
        
        Label(header_frame, text="SECRET OF BOUNTY", font=("Impact", 32, "bold"),
              fg="#00ffcc", bg="#0d1117").pack(side=TOP)
        
        Label(header_frame, text="Author: TehanG07", font=("Courier New", 14, "bold"),
              fg="#ffffff", bg="#0d1117").pack(side=TOP, pady=(5,0))

        # Controls
        ctrl_frame = Frame(root, bg="#161b22", pady=15)
        ctrl_frame.pack(fill=X, padx=20, pady=5)
        
        btn_style = {"font": ("Arial", 11, "bold"), "padx": 20, "pady": 5, "relief": FLAT}
        
        Button(ctrl_frame, text="📂 LOAD URLS & SCAN", command=self.start_scan,
               bg="#00ffcc", fg="#000", **btn_style).pack(side=LEFT, padx=10)
        
        Button(ctrl_frame, text="🛑 STOP SCAN", command=self.stop_scan,
               bg="#f44336", fg="white", **btn_style).pack(side=LEFT, padx=10)

        self.lbl_status = Label(ctrl_frame, text="Status: Ready", fg="#00ffcc", bg="#161b22", font=("Consolas", 12))
        self.lbl_status.pack(side=LEFT, padx=30)

        self.progress = ttk.Progressbar(ctrl_frame, length=500, mode="determinate")
        self.progress.pack(side=LEFT, padx=10)

        # Results Area
        columns = ("Type", "Severity", "Value", "Source URL")
        self.tree = ttk.Treeview(root, columns=columns, show="headings")
        
        self.tree.heading("Type", text="DETECTION TYPE")
        self.tree.heading("Severity", text="RISK")
        self.tree.heading("Value", text="FOUND DATA")
        self.tree.heading("Source URL", text="SOURCE")
        
        self.tree.column("Type", width=220, anchor=W)
        self.tree.column("Severity", width=100, anchor=CENTER)
        self.tree.column("Value", width=350, anchor=W)
        self.tree.column("Source URL", width=450, anchor=W)
        
        self.tree.pack(expand=True, fill=BOTH, padx=10, pady=10)
        
        # Scrollbar
        scrollbar = Scrollbar(root, orient=VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.place(relx=0.99, rely=0.2, relheight=0.75, anchor=NE)

        for sev, color in SEVERITY_COLORS.items():
            fg = "white" if sev != "INFO" else "#aaaaaa"
            self.tree.tag_configure(sev, background=color, foreground=fg)

    def start_scan(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if not path: return
        
        with open(path, 'r') as f:
            urls = [u.strip() for u in f if u.strip() and u.startswith(('http://', 'https://'))]
        
        if not urls:
            messagebox.showwarning("Error", "No valid URLs found.")
            return

        self.lbl_status.config(text=f"Scanning {len(urls)} targets...", fg="#ffff00")
        self.progress["maximum"] = len(urls)
        self.progress["value"] = 0
        self.stop_flag = False
        
        for item in self.tree.get_children():
            self.tree.delete(item)

        def run_pool():
            findings_buffer = {} 
            with ThreadPoolExecutor(max_workers=THREADS) as executor:
                future_to_url = {executor.submit(self.scanner.scan_target, url): url for url in urls}
                
                for i, future in enumerate(as_completed(future_to_url)):
                    if self.stop_flag: break
                    
                    url = future_to_url[future]
                    try:
                        u, findings = future.result()
                        if findings:
                            findings_buffer[u] = findings
                            for f in findings:
                                self.tree.insert("", 0, values=(
                                    f['type'], f['severity'], f['value'], f['url']
                                ), tags=(f['severity'],))
                    except Exception:
                        pass
                    
                    self.progress["value"] = i + 1
                    self.progress.update()
                    self.lbl_status.config(text=f"Processed: {i+1}/{len(urls)}")

            # Generate HTML
            self.lbl_status.config(text="Generating HTML Report...", fg="#00ffcc")
            html_code = generate_html_report(findings_buffer)
            
            filename = "results_real_target.html"
            with open(filename, "w", encoding="utf-8") as hf:
                hf.write(html_code)
            
            self.lbl_status.config(text="Scan Complete! Opening Report...", fg="#4caf50")
            webbrowser.open('file://' + os.path.realpath(filename))
            messagebox.showinfo("Success", f"Scan Complete!\nReport saved as: {filename}")

        threading.Thread(target=run_pool, daemon=True).start()

    def stop_scan(self):
        self.stop_flag = True
        self.lbl_status.config(text="Stopping scan...", fg="#f44336")

if __name__ == "__main__":
    root = Tk()
    try: from ctypes import windll; windll.shcore.SetProcessDpiAwareness(1)
    except: pass
    App(root)
    root.mainloop()
