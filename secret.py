import requests, re, math, json, threading, base64, time
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
THREADS = 15  # Increased for aggressive crawling

SEVERITY_COLORS = {
    "INFO": "#212121",      # Dark Grey for informational endpoints
    "LOW": "#4caf50",       # Green
    "MEDIUM": "#ff9800",    # Orange
    "HIGH": "#f44336",      # Red
    "CRITICAL": "#b71c1c"   # Deep Red
}

# STRICT IGNORE LIST: These values trigger immediate discard if found in matches
IGNORE_LIST = [
    "example", "sample", "test", "dummy", "fake", "xxxx", "xxxxx",
    "changeme", "your_api_key", "your_email", "insert_here", "localhost",
    "127.0.0.1", "development", "staging", "null", "undefined", "false"
]

# ================= UTILITIES & VALIDATION ================= #
def get_entropy(s):
    """Calculates Shannon entropy to detect high-information strings like keys."""
    if not s: return 0
    s = s.strip()
    # Normalize to avoid length bias
    entropy = 0
    for x in set(s):
        p_x = float(s.count(x)) / len(s)
        if p_x > 0:
            entropy -= p_x * math.log(p_x, 2)
    return entropy

def luhn_checksum(card_number):
    """Validates Credit Card using Luhn algorithm."""
    r = [int(x) for x in card_number[::-1]]
    return (sum(r[0::2]) + sum(sum(divmod(d*2,10)) for d in r[1::2])) % 10 == 0

def decode_jwt(token):
    """Attempts to decode JWT payload to inspect claims without verifying signature."""
    try:
        parts = token.split('.')
        if len(parts) != 3: return None
        # Add padding if necessary
        payload_b64 = parts[1] + '=' * (-len(parts[1]) % 4)
        payload = json.loads(base64.b64decode(payload_b64))
        return payload
    except:
        return None

def check_context(match_text, source_snippet):
    """
    Advanced False Positive Reduction:
    Checks if the match appears in a context that implies it is a variable assignment,
    JSON key, or configuration value.
    """
    match_lower = match_text.lower()
    snippet_lower = source_snippet.lower()
    
    # 1. Hard ignore
    if any(x in match_lower for x in IGNORE_LIST):
        return False

    # 2. Contextual Heuristics
    # Look for assignment keywords nearby (within 50 chars)
    idx = snippet_lower.find(match_lower)
    if idx == -1: return True # Fallback to true if context extraction fails
    
    context_window = snippet_lower[max(0, idx-50):idx+len(match_lower)+50]
    
    # Positive indicators (likely a real key)
    if any(k in context_window for k in ["key", "secret", "token", "pass", "auth", "api", "credential", "env", "config"]):
        return True
        
    # Negative indicators (likely an example, ID, or comment)
    if any(k in context_window for k in ["//", "#", "<!--", "example", "sample", "placeholder", "format", "e.g."]):
        return False

    return True

# ================= SIGNATURE DATABASE ================= #
# Tuple structure: (Regex, Severity, "Description")
PATTERNS = {
    # -------- CLOUD & INFRA --------
    "AWS Access Key": (r'(?i)\b(AKIA[0-9A-Z]{16})\b', "CRITICAL", "AWS Access Key ID"),
    "AWS Secret Key": (r'(?i)aws(.{0,20})?[\'\"]?secret[\'\"]?(.{0,20})?[=:\s]+[\'\"]?([A-Za-z0-9/+=]{40})[\'\"]?', "CRITICAL", "AWS Secret Access Key"),
    "Google API Key": (r'\b(AIza[0-9A-Za-z\-_]{35})\b', "HIGH", "Google Cloud API Key"),
    "Google Cloud OAuth": (r'\b([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b', "HIGH", "GCP OAuth Client ID"),
    "Firebase DB": (r'\b(firebaseio\.com|firebase\.app)\b', "MEDIUM", "Firebase Database URL"),
    "Azure Key": (r'(?i)azure(.{0,20})?[\'\"]?(key|secret|value)[\'\"]?(.{0,20})?[=:\s]+[\'\"]?([A-Za-z0-9/+=]{32,})[\'\"]?', "HIGH", "Azure Storage/Key"),

    # -------- PAYMENT & FINTECH --------
    "Stripe Live Key": (r'\b(sk_live_[0-9a-zA-Z]{24})\b', "CRITICAL", "Stripe Live Secret Key"),
    "Stripe Publishable": (r'\b(pk_live_[0-9a-zA-Z]{24})\b', "HIGH", "Stripe Live Publishable Key"),
    "PayPal Braintree": (r'\b(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})\b', "CRITICAL", "Braintree Access Token"),

    # -------- DEVOPS & VERSION CONTROL --------
    "GitHub Token": (r'\b(gh[pousr]_[A-Za-z0-9_]{36,})\b', "CRITICAL", "GitHub Personal/OAuth Token"),
    "GitLab Token": (r'\b(glpat-[A-Za-z0-9\-]{20,})\b', "CRITICAL", "GitLab Personal Access Token"),
    "Slack Token": (r'\b(xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9A-Za-z]{24})\b', "CRITICAL", "Slack Bot/User Token"),
    "Jira Token": (r'\b([0-9]{26}@[A-Z0-9]{12})\b', "HIGH", "Atlassian API Token"),

    # -------- DATABASES --------
    "Mongo URI": (r'\b(mongodb(\+srv)?:\/\/[^\s\'"<>{},|\\^`]{10,})\b', "CRITICAL", "MongoDB Connection String"),
    "Postgres URI": (r'\b(postgres(ql)?:\/\/[^\s\'"<>{},|\\^`]{10,})\b', "CRITICAL", "PostgreSQL Connection String"),
    "MySQL URI": (r'\b(mysql:\/\/[^\s\'"<>{},|\\^`]{10,})\b', "CRITICAL", "MySQL Connection String"),
    "Redis URI": (r'\b(redis:\/\/[^\s\'"<>{},|\\^`]{10,})\b', "CRITICAL", "Redis Connection String"),

    # -------- AUTH TOKENS --------
    "Bearer Token": (r'\b(Bearer\s+[A-Za-z0-9\-._~+/]+=*)\b', "HIGH", "Generic Bearer Authorization"),
    "JWT Token": (r'\b(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+)\b', "HIGH", "JSON Web Token"),
    "OAuth Access": (r'\b(ya29\.[0-9A-Za-z\-_]+)\b', "HIGH", "Google OAuth2 Token"),
    
    # -------- GENERAL SECRETS --------
    "Generic API Key": (r'\b([A-Za-z0-9]{32})\b', "MEDIUM", "Generic 32-char Key (Entropy Check)"), # Will rely heavily on entropy
    "Private Key Marker": (r'-----BEGIN [A-Z]+ PRIVATE KEY-----', "CRITICAL", "PEM Private Key Header"),
    
    # -------- ENDPOINTS & PATHS (Hidden APIs) --------
    "GraphQL Endpoint": (r'["\']?(\/graphql\/?)["\']?', "INFO", "GraphQL Endpoint"),
    "REST API v1": (r'["\']?(\/api\/v1\/[a-z0-9_\-]+)["\']?', "INFO", "REST API v1 Path"),
    "REST API v2": (r'["\']?(\/api\/v2\/[a-z0-9_\-]+)["\']?', "INFO", "REST API v2 Path"),
    "Admin Path": (r'["\']?(\/(admin|dashboard|settings|config|console)\/?)["\']?', "MEDIUM", "Admin/Management Path"),
    "Debug Path": (r'["\']?(\/(debug|test|healthcheck|status)\/?)["\']?', "LOW", "Debug/Monitoring Path"),
    "S3 Bucket": (r'\b([a-z0-9.-]+\.s3\.amazonaws\.com)\b', "MEDIUM", "AWS S3 Bucket URL"),

    # -------- PII --------
    "Email Address": (r'\b([a-zA-Z0-9._%+-]+@(?!example\.com)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', "MEDIUM", "Email Address"),
    "Credit Card": (r'\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b', "CRITICAL", "Potential Credit Card (Luhn Validated)"),
    "IP Address": (r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', "LOW", "IP Address Leak"),
    "Phone Number": (r'(\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})', "MEDIUM", "Phone Number"),
}

# ================= SCANNER ENGINE ================= #
class RealTargetScanner:
    def __init__(self):
        self.lock = threading.Lock()
        self.seen_findings = set() # Global deduplication
        
    def process_source(self, source_text, url):
        findings = []
        # 1. REGEX SCANNING
        for name, (pattern, severity, desc) in PATTERNS.items():
            # Skip scanning for endpoints in HTML body to save noise, do it in JS mostly? 
            # No, scan everything but let logic filter.
            for match in re.finditer(pattern, source_text):
                raw_match = match.group()
                
                # Extract specific groups for complex patterns
                if name == "AWS Secret Key": raw_match = match.group(4)
                elif name == "AWS Access Key": raw_match = match.group(1)
                elif name == "Google API Key": raw_match = match.group(1)
                elif name == "JWT Token": raw_match = match.group(1)

                value = raw_match.strip('\'"')
                value_hash = hash(value + name)
                
                # DEDUPLICATION
                if value_hash in self.seen_findings:
                    continue
                
                # VALIDATION
                if len(value) > 200: continue # Ignore massive blobs
                
                # Entropy check for keys
                if severity in ["CRITICAL", "HIGH"] and "Token" not in name and "Endpoint" not in name:
                    ent = get_entropy(value)
                    if len(value) > 10 and ent < 3.0: 
                        continue # Low entropy long string is likely an ID or sentence

                # Specific Card Validation
                if name == "Credit Card":
                    clean_card = re.sub(r'\D', '', value)
                    if len(clean_card) < 13 or not luhn_checksum(clean_card):
                        continue
                
                # Context Check
                if not check_context(value, match.group(0)):
                    continue

                # JWT Logic
                final_severity = severity
                if name == "JWT Token":
                    payload = decode_jwt(value)
                    if payload:
                        # Escalate if sensitive claims found
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

        # 2. SMART JS ENDPOINT EXTRACTION (Beyond Regex)
        # Look for relative paths used in fetch() calls or URL definitions
        # Pattern: "/path" or "http://domain/path" inside script-like structures
        if '.js' in url or '<script' in source_text[:500]:
            # Extract strings that look like paths
            path_candidates = re.findall(r'["\']((?:\/[a-zA-Z0-9._-]{2,}){2,})["\']', source_text)
            for path in path_candidates:
                if len(path) > 3 and any(x in path for x in ['api', 'v1', 'v2', 'user', 'admin', 'graphql']):
                    val_hash = hash(path + "endpoint")
                    if val_hash not in self.seen_findings:
                        with self.lock:
                            self.seen_findings.add(val_hash)
                        findings.append({
                            "type": "JS API Path",
                            "severity": "INFO",
                            "value": path,
                            "url": url
                        })
        
        return findings

    def scan_target(self, url):
        results = []
        try:
            # 1. Fetch Main Page
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
            content = r.text
            
            # Scan HTML
            results.extend(self.process_source(content, url))
            
            # 2. Extract JS Files
            soup = BeautifulSoup(content, "html.parser")
            js_urls = set()
            for script in soup.find_all("script", src=True):
                full_js_url = urljoin(url, script["src"])
                # Filter external CDNs if desired, but for bounties we want to check everything
                if any(ext in full_js_url for ext in ['.js', '.json']):
                    js_urls.add(full_js_url)
            
            # 3. Crawl JS Files
            for js_url in js_urls:
                try:
                    # Limit JS size to prevent memory bombs
                    js_r = requests.get(js_url, headers=HEADERS, timeout=TIMEOUT)
                    if len(js_r.content) > 5000000: # Skip files > 5MB
                        continue
                    results.extend(self.process_source(js_r.text, js_url))
                except Exception as e:
                    pass # Fail silently for individual JS files
            
            # 4. Scan Headers (Real World Session Leaks)
            for header, value in r.headers.items():
                if "cookie" in header.lower() or "set-cookie" in header.lower():
                     # Look for session IDs in headers
                     if re.search(r'(sess|auth|token|id)=[a-f0-9]{20,}', value, re.I):
                         results.append({
                             "type": "Session Cookie Header",
                             "severity": "MEDIUM",
                             "value": value[:100] + "...",
                             "url": url
                         })

        except Exception as e:
            pass # Ignore connection errors during scan run
            
        return url, results

# ================= GUI INTERFACE ================= #
class App:
    def __init__(self, root):
        root.title("SECRET OF BOUNTY: REAL TARGET MODE v5.1")
        root.geometry("1300x700")
        root.configure(bg="#0d1117")
        
        self.scanner = RealTargetScanner()
        self.stop_flag = False

        # --- Header ---
        header_frame = Frame(root, bg="#0d1117")
        header_frame.pack(pady=10)
        
        Label(header_frame, text="SECRET OF BOUNTY", font=("Consolas", 26, "bold"),
              fg="#00ffcc", bg="#0d1117").pack(side=LEFT, padx=10)
        Label(header_frame, text="[ELITE EDITION]", font=("Consolas", 12),
              fg="#f44336", bg="#0d1117").pack(side=LEFT, padx=5)

        # --- Control Panel ---
        ctrl_frame = Frame(root, bg="#161b22", pady=10)
        ctrl_frame.pack(fill=X, padx=20, pady=5)
        
        Button(ctrl_frame, text="📂 Load URL File & Scan", command=self.start_scan,
               bg="#00ffcc", fg="#000", font=("Arial", 10, "bold"), padx=15).pack(side=LEFT, padx=10)
        
        Button(ctrl_frame, text="🛑 Stop", command=self.stop_scan,
               bg="#f44336", fg="white", font=("Arial", 10, "bold"), padx=15).pack(side=LEFT, padx=10)

        self.lbl_status = Label(ctrl_frame, text="Idle", fg="#00ffcc", bg="#161b22", font=("Consolas", 12))
        self.lbl_status.pack(side=LEFT, padx=20)

        self.progress = ttk.Progressbar(ctrl_frame, length=400, mode="determinate")
        self.progress.pack(side=LEFT, padx=10)

        # --- Results Area ---
        columns = ("Type", "Severity", "Value", "Source URL")
        self.tree = ttk.Treeview(root, columns=columns, show="headings")
        
        self.tree.heading("Type", text="FINDING TYPE")
        self.tree.heading("Severity", text="SEVERITY")
        self.tree.heading("Value", text="DETECTED VALUE")
        self.tree.heading("Source URL", text="LOCATION")
        
        self.tree.column("Type", width=200, anchor=W)
        self.tree.column("Severity", width=100, anchor=CENTER)
        self.tree.column("Value", width=400, anchor=W)
        self.tree.column("Source URL", width=400, anchor=W)
        
        self.tree.pack(expand=True, fill=BOTH, padx=10, pady=10)
        
        # Scrollbar
        scrollbar = Scrollbar(root, orient=VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.place(relx=0.98, rely=0.2, relheight=0.7, anchor=NE)

        # Configure Tags for Colors
        for sev, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(sev, background=color, foreground="white" if sev != "INFO" else "#aaaaaa")

    def start_scan(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if not path: return
        
        with open(path, 'r') as f:
            urls = [u.strip() for u in f if u.strip() and u.startswith(('http://', 'https://'))]
        
        if not urls:
            messagebox.showwarning("Input Error", "No valid URLs found.")
            return

        self.lbl_status.config(text=f"Scanning {len(urls)} targets...", fg="#ffff00")
        self.progress["maximum"] = len(urls)
        self.progress["value"] = 0
        self.stop_flag = False
        
        # Clear old results
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Thread pool execution
        def run_pool():
            findings_buffer = {} # Store by URL for JSON export
            with ThreadPoolExecutor(max_workers=THREADS) as executor:
                future_to_url = {executor.submit(self.scanner.scan_target, url): url for url in urls}
                
                for i, future in enumerate(as_completed(future_to_url)):
                    if self.stop_flag: break
                    
                    url = future_to_url[future]
                    try:
                        u, findings = future.result()
                        if findings:
                            findings_buffer[u] = findings
                            # GUI Update
                            for f in findings:
                                self.tree.insert("", 0, values=(
                                    f['type'], f['severity'], f['value'], f['url']
                                ), tags=(f['severity'],))
                    except Exception as e:
                        print(f"Error processing {url}: {e}")
                    
                    # Progress Update
                    self.progress["value"] = i + 1
                    self.progress.update()
                    self.lbl_status.config(text=f"Processed {i+1}/{len(urls)}")

            # Save JSON
            with open("results_real_target.json", "w") as jf:
                json.dump(findings_buffer, jf, indent=2)
            
            self.lbl_status.config(text="Scan Complete. Results saved.", fg="#00ffcc")

        threading.Thread(target=run_pool, daemon=True).start()

    def stop_scan(self):
        self.stop_flag = True
        self.lbl_status.config(text="Stopping...", fg="#f44336")

# ================= ENTRY POINT ================= #
if __name__ == "__main__":
    root = Tk()
    try:
        # High DPI fix for Windows
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass
    App(root)
    root.mainloop()
