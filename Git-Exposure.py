#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ██████╗ ██╗████████╗███████╗██╗  ██╗██████╗  ██████╗ ███████╗║
║  ██╔════╝ ██║╚══██╔══╝██╔════╝╚██╗██╔╝██╔══██╗██╔═══██╗██╔════╝║
║  ██║  ███╗██║   ██║   █████╗   ╚███╔╝ ██████╔╝██║   ██║███████╗║
║  ██║   ██║██║   ██║   ██╔══╝   ██╔██╗ ██╔═══╝ ██║   ██║╚════██║║
║  ╚██████╔╝██║   ██║   ███████╗██╔╝ ██╗██║     ╚██████╔╝███████║║
║   ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝║
║                                                                  ║
║        🔥 COMPLETE CHAIN SCANNER - v3.0 ULTIMATE 🔥              ║
║              ALL SUBDOMAINS + COMPLETE SCANNING                  ║
║                    Authored by: TehanG07                         ║
║                                                                  ║
║  ✅ COMPLETE FEATURES:                                           ║
║    • ALL 181+ subdomains scanned thoroughly                      ║
║    • Batch processing for better performance                     ║
║    • Complete URL chain: Subdomain → Live → Paths → Scan         ║
║    • Smart timeout handling                                      ║
║    • Detailed progress tracking                                  ║
║                                                                  ║
║  ⚠️  FOR LEGAL & AUTHORIZED PENETRATION TESTING ONLY ⚠️          ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import re
import json
import csv
import subprocess
import threading
import time
import signal
from datetime import datetime
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[!] Installing required module: requests")
    os.system(f"{sys.executable} -m pip install requests urllib3")
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ═══════════════════════════════════════════════════════════════
# COLORS
# ═══════════════════════════════════════════════════════════════
class Colors:
    CRITICAL = '\033[1;97;41m'
    HIGH = '\033[1;91m'
    MEDIUM = '\033[1;93m'
    LOW = '\033[1;96m'
    INFO = '\033[1;94m'
    BANNER = '\033[1;92m'
    HEADER = '\033[1;95m'
    SUCCESS = '\033[1;92m'
    WARNING = '\033[1;93m'
    ERROR = '\033[1;91m'
    WHITE = '\033[1;97m'
    GRAY = '\033[0;37m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


# ═══════════════════════════════════════════════════════════════
# SENSITIVE PATHS - EXPANDED & ORGANIZED
# ═══════════════════════════════════════════════════════════════
SENSITIVE_PATHS = {
    "git_exposure": [
        "/.git/HEAD", "/.git/config", "/.git/index",
        "/.git/logs/HEAD", "/.git/logs/refs/heads/master",
        "/.git/logs/refs/heads/main", "/.git/packed-refs",
        "/.gitignore", "/.gitmodules",
    ],
    "env_files": [
        "/.env", "/.env.local", "/.env.production", "/.env.dev",
        "/.env.backup", "/.env.old", "/app/.env", "/api/.env",
        "/config/.env", "/backend/.env",
    ],
    "config_files": [
        "/config.php", "/config.yml", "/config.json",
        "/wp-config.php", "/wp-config.php.bak",
        "/.config", "/api/.config", "/admin/.config",
        "/database.yml", "/secrets.yml",
    ],
    "backup_files": [
        "/backup.zip", "/backup.sql", "/database.sql",
        "/db.sql", "/dump.sql", "/site.zip",
    ],
    "debug_info": [
        "/phpinfo.php", "/info.php", "/.htaccess",
        "/error_log", "/debug.log",
    ],
    "api_keys": [
        "/swagger.json", "/openapi.json", "/graphql",
    ],
    "credentials": [
        "/.ssh/id_rsa", "/credentials.json", "/secrets.yml",
    ],
}

SECRET_PATTERNS = {
    "CRITICAL": {
        "AWS Access Key": r'AKIA[0-9A-Z]{16}',
        "Private Key": r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        "GitHub Token": r'gh[pousr]_[A-Za-z0-9_]{36,255}',
        "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
        "JWT Token": r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
    },
    "HIGH": {
        "Database URL": r'(?i)(mysql|postgres|mongodb|redis):\/\/[^\s<>"]+',
        "Generic Password": r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{6,}',
        "API Key": r'(?i)(api_key|apikey)\s*[=:]\s*["\']?[A-Za-z0-9\-_]{16,}',
    },
    "MEDIUM": {
        "Internal IP": r'(?:10|172\.(?:1[6-9]|2[0-9]|3[0-1])|192\.168)\.\d{1,3}\.\d{1,3}',
        "Email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    }
}


# ═══════════════════════════════════════════════════════════════
# PROGRESS BAR
# ═══════════════════════════════════════════════════════════════
class ProgressBar:
    def __init__(self, total, prefix='Progress:', length=50):
        self.total = total
        self.prefix = prefix
        self.length = length
        self.current = 0
        self.lock = threading.Lock()

    def update(self, increment=1):
        with self.lock:
            self.current += increment
            self._print()

    def _print(self):
        if self.total == 0:
            return
        percent = min(100, (self.current / self.total) * 100)
        filled = int(self.length * self.current // self.total)
        bar = '█' * filled + '░' * (self.length - filled)
        print(f'\r  {Colors.INFO}{self.prefix} |{bar}| {percent:.1f}% ({self.current}/{self.total}){Colors.RESET}', end='', flush=True)
        if self.current >= self.total:
            print()


# ═══════════════════════════════════════════════════════════════
# MAIN SCANNER - COMPLETE CHAIN VERSION
# ═══════════════════════════════════════════════════════════════
class GitExposerCompleteChain:
    def __init__(self, domain):
        self.domain = domain
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = f"gitexposer_complete_{domain}_{self.timestamp}"
        self.repos_dir = os.path.join(self.output_dir, "downloaded_repos")
        
        # Data structures
        self.subdomains = set()
        self.all_urls = set()
        self.live_urls = set()
        self.live_subdomains = set()  # NEW: Track which subdomains are actually live
        
        self.results = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": [],
        }
        self.git_repos_found = []
        self.scanned_count = 0
        self.found_count = 0
        
        # Session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        self.session.verify = False
        self.session.timeout = 8
        self.lock = threading.Lock()
        
        # Stats
        self.stats = {
            'subdomains_found': 0,
            'live_hosts': 0,
            'urls_collected': 0,
            'paths_scanned': 0,
            'findings': 0,
        }

        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.repos_dir, exist_ok=True)

    def print_banner(self):
        banner = f"""
{Colors.BANNER}
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ██████╗ ██╗████████╗███████╗██╗  ██╗██████╗  ██████╗ ███████╗     ║
║  ██╔════╝ ██║╚══██╔══╝██╔════╝╚██╗██╔╝██╔══██╗██╔═══██╗██╔════╝    ║
║  ██║  ███╗██║   ██║   █████╗   ╚███╔╝ ██████╔╝██║   ██║███████╗    ║
║  ██║   ██║██║   ██║   ██╔══╝   ██╔██╗ ██╔═══╝ ██║   ██║╚════██║    ║
║  ╚██████╔╝██║   ██║   ███████╗██╔╝ ██╗██║     ╚██████╔╝███████║    ║
║   ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝  ║
║                                                                      ║
║        {Colors.WHITE}🔥 COMPLETE CHAIN SCANNER v3.0 - ALL SUBDOMAINS 🔥{Colors.BANNER}      ║
║                    {Colors.HIGH}Authored by: TehanG07{Colors.BANNER}                          ║
║                                                                      ║
║  {Colors.WARNING}⚠️  FOR LEGAL & AUTHORIZED PENETRATION TESTING ONLY ⚠️{Colors.BANNER}          ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
{Colors.RESET}"""
        print(banner)

    def print_status(self, msg, status="info"):
        colors = {"info": Colors.INFO, "success": Colors.SUCCESS, 
                  "warning": Colors.WARNING, "error": Colors.ERROR}
        icons = {"info": "ℹ", "success": "✔", "warning": "⚠", "error": "✘"}
        color = colors.get(status, Colors.INFO)
        icon = icons.get(status, "ℹ")
        print(f"  {color}[{icon}]{Colors.RESET} {msg}")

    def print_section(self, title):
        print(f"\n{Colors.HEADER}{'═' * 80}")
        print(f"  ▶  {title}")
        print(f"{'═' * 80}{Colors.RESET}\n")

    def _check_tool(self, tool_name):
        try:
            result = subprocess.run(['which', tool_name], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    # ═══════════════════════════════════════════════════════════════
    # PHASE 1: COMPREHENSIVE SUBDOMAIN ENUMERATION
    # ═══════════════════════════════════════════════════════════════
    def enumerate_subdomains(self):
        self.print_section("PHASE 1: Comprehensive Subdomain Enumeration")
        subdomains = set([self.domain, f"www.{self.domain}"])

        # subfinder
        if self._check_tool('subfinder'):
            self.print_status("Running subfinder...", "info")
            try:
                result = subprocess.run(
                    ['subfinder', '-d', self.domain, '-silent', '-all'],
                    capture_output=True, text=True, timeout=90
                )
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        subdomains.add(line.strip())
                self.print_status(f"subfinder: {len(subdomains)} subdomains", "success")
            except Exception as e:
                self.print_status("subfinder timeout/error (continuing)", "warning")

        # crt.sh
        self.print_status("Querying crt.sh...", "info")
        try:
            resp = self.session.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json", timeout=15
            )
            if resp.status_code == 200:
                for entry in resp.json():
                    for sub in entry.get('name_value', '').split('\n'):
                        sub = sub.strip().lower()
                        if sub and '*' not in sub:
                            subdomains.add(sub)
                self.print_status(f"crt.sh: {len(subdomains)} total", "success")
        except:
            self.print_status("crt.sh skipped", "warning")

        self.subdomains = subdomains
        self.stats['subdomains_found'] = len(subdomains)

        # Save
        with open(os.path.join(self.output_dir, "subdomains.txt"), 'w') as f:
            for sub in sorted(subdomains):
                f.write(sub + '\n')

        self.print_status(f"Total unique subdomains: {Colors.WHITE}{len(subdomains)}{Colors.RESET}", "success")
        return subdomains

    # ═══════════════════════════════════════════════════════════════
    # PHASE 2: BATCH URL COLLECTION (SMART BATCHING)
    # ═══════════════════════════════════════════════════════════════
    def collect_urls_batched(self):
        self.print_section("PHASE 2: URL Collection (Batched Processing)")
        collected = set()

        # Base URLs for all subdomains
        for sub in self.subdomains:
            collected.add(f"https://{sub}")
            collected.add(f"http://{sub}")

        # Batch subdomains into chunks of 20
        subdomain_list = list(self.subdomains)
        batch_size = 20
        batches = [subdomain_list[i:i + batch_size] for i in range(0, len(subdomain_list), batch_size)]

        self.print_status(f"Processing {len(subdomain_list)} subdomains in {len(batches)} batches", "info")

        # waybackurls in batches
        if self._check_tool('waybackurls'):
            self.print_status(f"Running waybackurls on {len(batches)} batches...", "info")
            for i, batch in enumerate(batches, 1):
                try:
                    subs_input = '\n'.join(batch)
                    result = subprocess.run(
                        ['waybackurls'],
                        input=subs_input, 
                        capture_output=True, 
                        text=True, 
                        timeout=30  # 30s per batch
                    )
                    for line in result.stdout.strip().split('\n'):
                        if line.strip() and self.domain in line:
                            collected.add(line.strip())
                    print(f"\r  {Colors.INFO}[ℹ]{Colors.RESET} waybackurls: batch {i}/{len(batches)} - {len(collected)} URLs", end='', flush=True)
                except:
                    continue
            print()
            self.print_status(f"waybackurls: {len(collected)} URLs total", "success")

        # gau in batches
        if self._check_tool('gau'):
            self.print_status(f"Running gau on {len(batches)} batches...", "info")
            for i, batch in enumerate(batches, 1):
                try:
                    subs_input = '\n'.join(batch)
                    result = subprocess.run(
                        ['gau', '--threads', '3', '--timeout', '5'],
                        input=subs_input, 
                        capture_output=True, 
                        text=True, 
                        timeout=30
                    )
                    for line in result.stdout.strip().split('\n'):
                        if line.strip() and self.domain in line:
                            collected.add(line.strip())
                    print(f"\r  {Colors.INFO}[ℹ]{Colors.RESET} gau: batch {i}/{len(batches)} - {len(collected)} URLs", end='', flush=True)
                except:
                    continue
            print()
            self.print_status(f"gau: {len(collected)} URLs total", "success")

        self.all_urls = collected
        self.stats['urls_collected'] = len(collected)

        # Save
        with open(os.path.join(self.output_dir, "all_urls.txt"), 'w') as f:
            for url in sorted(collected):
                f.write(url + '\n')

        self.print_status(f"Total unique URLs: {Colors.WHITE}{len(collected)}{Colors.RESET}", "success")
        return collected

    # ═══════════════════════════════════════════════════════════════
    # PHASE 3: COMPREHENSIVE LIVE DETECTION (ALL SUBDOMAINS)
    # ═══════════════════════════════════════════════════════════════
    def find_all_live_hosts(self):
        self.print_section("PHASE 3: Comprehensive Live Host Detection")
        
        # Create targets for ALL subdomains
        targets = set()
        for sub in self.subdomains:
            targets.add(f"https://{sub}")
            targets.add(f"http://{sub}")

        self.print_status(f"Checking {len(targets)} URLs ({len(self.subdomains)} subdomains)...", "info")

        # Try httpx first (faster)
        if self._check_tool('httpx'):
            self.print_status("Using httpx for fast detection...", "info")
            try:
                # Save targets to temp file
                temp_file = os.path.join(self.output_dir, "temp_targets.txt")
                with open(temp_file, 'w') as f:
                    for target in targets:
                        f.write(target + '\n')
                
                result = subprocess.run(
                    ['httpx', '-l', temp_file, '-silent', '-no-color', '-threads', '100', '-timeout', '5'],
                    capture_output=True, 
                    text=True, 
                    timeout=180
                )
                
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        self.live_urls.add(line.strip())
                        # Extract subdomain
                        subdomain = urlparse(line.strip()).netloc
                        self.live_subdomains.add(subdomain)
                
                os.remove(temp_file)
                self.print_status(f"httpx: {len(self.live_urls)} live URLs from {len(self.live_subdomains)} subdomains", "success")
                
            except Exception as e:
                self.print_status("httpx timeout, using manual check...", "warning")
                self._manual_comprehensive_check(targets)
        else:
            self.print_status("httpx not found, using manual check...", "warning")
            self._manual_comprehensive_check(targets)

        if not self.live_urls:
            self.live_urls.add(f"https://{self.domain}")
            self.live_subdomains.add(self.domain)

        self.stats['live_hosts'] = len(self.live_subdomains)

        # Save
        with open(os.path.join(self.output_dir, "live_urls.txt"), 'w') as f:
            for url in sorted(self.live_urls):
                f.write(url + '\n')
        
        with open(os.path.join(self.output_dir, "live_subdomains.txt"), 'w') as f:
            for sub in sorted(self.live_subdomains):
                f.write(sub + '\n')

        self.print_status(f"Live hosts: {Colors.WHITE}{len(self.live_subdomains)}{Colors.RESET} subdomains, {Colors.WHITE}{len(self.live_urls)}{Colors.RESET} URLs", "success")
        return self.live_urls

    def _manual_comprehensive_check(self, targets):
        """Manual live check with batching"""
        self.print_status(f"Manually checking {len(targets)} URLs...", "info")
        progress = ProgressBar(len(targets), 'Checking:')
        
        # Batch processing
        target_list = list(targets)
        batch_size = 50
        
        for i in range(0, len(target_list), batch_size):
            batch = target_list[i:i + batch_size]
            
            with ThreadPoolExecutor(max_workers=30) as executor:
                futures = {executor.submit(self._check_live, url): url for url in batch}
                for future in as_completed(futures):
                    progress.update()
                    result = future.result()
                    if result:
                        self.live_urls.add(result)
                        subdomain = urlparse(result).netloc
                        self.live_subdomains.add(subdomain)
        
        self.print_status(f"Found {len(self.live_urls)} live URLs", "success")

    def _check_live(self, url):
        try:
            resp = self.session.get(url, timeout=5)
            if resp.status_code < 500:
                return url
        except:
            pass
        return None

    # ═══════════════════════════════════════════════════════════════
    # PHASE 4: GIT DETECTION ON ALL LIVE HOSTS
    # ═══════════════════════════════════════════════════════════════
    def detect_git_exposure_comprehensive(self):
        self.print_section("PHASE 4: Git Repository Detection (All Live Hosts)")
        
        git_targets = [f"{url.rstrip('/')}/.git/HEAD" for url in self.live_urls]
        
        self.print_status(f"Checking {len(git_targets)} URLs for .git exposure...", "info")
        progress = ProgressBar(len(git_targets), 'Scanning:')

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self._check_git_head, url): url for url in git_targets}
            for future in as_completed(futures):
                progress.update()
                result = future.result()
                if result:
                    self.git_repos_found.append(result)
                    self._print_git_finding(result)

        self.print_status(f"Found {len(self.git_repos_found)} exposed Git repositories!", 
                         "success" if self.git_repos_found else "info")

        if self.git_repos_found:
            with open(os.path.join(self.output_dir, "git_repos_exposed.txt"), 'w') as f:
                for repo in self.git_repos_found:
                    f.write(f"{repo['base_url']}/.git/\n")

    def _check_git_head(self, url):
        try:
            resp = self.session.get(url, timeout=8)
            if resp.status_code == 200:
                content = resp.text.strip()
                if content.startswith('ref:') or re.match(r'^[0-9a-f]{40}$', content):
                    base_url = url.replace('/.git/HEAD', '')
                    return {
                        'base_url': base_url,
                        'head_content': content,
                        'domain': urlparse(base_url).netloc
                    }
        except:
            pass
        return None

    def _print_git_finding(self, repo):
        print(f"\n  {Colors.CRITICAL}╔{'═' * 70}╗{Colors.RESET}")
        print(f"  {Colors.CRITICAL}║ 🔴 EXPOSED GIT REPOSITORY! {' ' * 37}║{Colors.RESET}")
        print(f"  {Colors.CRITICAL}╠{'═' * 70}╣{Colors.RESET}")
        print(f"  {Colors.CRITICAL}║{Colors.RESET}  {repo['base_url']}/.git/")
        print(f"  {Colors.CRITICAL}║{Colors.RESET}  HEAD: {repo['head_content'][:50]}")
        print(f"  {Colors.CRITICAL}╚{'═' * 70}╝{Colors.RESET}")

    # ═══════════════════════════════════════════════════════════════
    # PHASE 5: COMPLETE PATH SCANNING (ALL LIVE HOSTS)
    # ═══════════════════════════════════════════════════════════════
    def scan_all_paths_comprehensive(self):
        self.print_section("PHASE 5: Comprehensive Path Scanning (All Live Hosts)")

        if not self.live_urls:
            self.print_status("No live URLs to scan", "error")
            return

        all_paths = []
        for paths in SENSITIVE_PATHS.values():
            all_paths.extend(paths)

        # Scan ALL live URLs
        scan_tasks = []
        for base_url in self.live_urls:
            base_url = base_url.rstrip('/')
            for path in all_paths:
                scan_tasks.append((base_url, path))

        self.stats['paths_scanned'] = len(scan_tasks)

        self.print_status(f"Scanning {len(all_paths)} paths across {len(self.live_urls)} hosts", "info")
        self.print_status(f"Total scan requests: {Colors.WHITE}{len(scan_tasks)}{Colors.RESET}", "info")
        
        progress = ProgressBar(len(scan_tasks), 'Scanning:')

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self._check_path, task[0], task[1], progress): task 
                      for task in scan_tasks}
            for future in as_completed(futures):
                try:
                    future.result()
                except:
                    pass

        self.stats['findings'] = self.found_count
        self.print_status(f"Found {Colors.WHITE}{self.found_count}{Colors.RESET} sensitive exposures", "success" if self.found_count > 0 else "info")

    def _check_path(self, base_url, path, progress):
        url = f"{base_url}{path}"
        try:
            resp = self.session.get(url, timeout=8, allow_redirects=False)
            progress.update()

            if resp.status_code == 200:
                content = resp.text
                
                if len(content) < 10:
                    return

                # False positive filtering
                false_positives = ['page not found', '404', 'not found']
                if any(fp in content[:2000].lower() for fp in false_positives):
                    return

                finding = self._analyze_finding(url, path, content, resp)
                if finding:
                    with self.lock:
                        self.found_count += 1
                        severity = finding['severity']
                        self.results[severity].append(finding)
                        print()
                        self._print_finding(finding)

        except:
            progress.update()

    def _analyze_finding(self, url, path, content, response):
        """Enhanced analysis with content preview"""
        severity = "INFO"
        finding_type = ""
        details = []

        # GIT
        if '/.git/' in path:
            if '/.git/HEAD' in path and 'ref:' in content:
                severity = "CRITICAL"
                finding_type = "Exposed Git HEAD"
                details.append(f"Git ref: {content.strip()[:100]}")
            elif '/.git/config' in path and '[core]' in content:
                severity = "CRITICAL"
                finding_type = "Exposed Git Config"
                urls = re.findall(r'url\s*=\s*(.+)', content)
                for u in urls:
                    details.append(f"Remote: {u.strip()}")
            else:
                severity = "HIGH"
                finding_type = f"Git File: {path}"

        # ENV
        elif '.env' in path:
            secrets = self._extract_secrets(content)
            if secrets:
                severity = "CRITICAL"
                finding_type = "Exposed .env with Secrets"
                details.extend(secrets[:10])
            else:
                severity = "HIGH"
                finding_type = "Exposed .env"
                lines = [l for l in content.split('\n')[:5] if '=' in l]
                for line in lines:
                    details.append(f"Var: {line[:60]}")

        # SQL BACKUP
        elif '.sql' in path:
            if any(x in content.upper() for x in ['CREATE TABLE', 'INSERT INTO']):
                severity = "CRITICAL"
                finding_type = "Database Backup with Data"
                tables = re.findall(r'CREATE TABLE[^(]*`?(\w+)`?', content, re.IGNORECASE)
                if tables:
                    details.append(f"Tables: {', '.join(tables[:10])}")
                details.append(f"Size: {len(content)} bytes")
            else:
                severity = "HIGH"
                finding_type = "SQL File"

        # CONFIG
        elif 'config' in path.lower():
            secrets = self._extract_secrets(content)
            if secrets:
                severity = "CRITICAL"
                finding_type = "Config with Secrets"
                details.extend(secrets[:8])
            else:
                severity = "MEDIUM"
                finding_type = "Config File"

        else:
            secrets = self._extract_secrets(content)
            if secrets:
                severity = "HIGH"
                finding_type = f"Sensitive: {path}"
                details.extend(secrets[:5])
            else:
                return None

        if not details:
            details.append(f"Size: {len(content)} bytes")

        return {
            "severity": severity,
            "type": finding_type,
            "url": url,
            "path": path,
            "details": details,
            "status_code": response.status_code,
            "content_length": len(content),
            "content_preview": content[:400] if severity in ["CRITICAL", "HIGH"] else ""
        }

    def _extract_secrets(self, content):
        found = []
        for sev, patterns in SECRET_PATTERNS.items():
            for name, pattern in patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    for m in matches[:2]:
                        m_str = m if isinstance(m, str) else str(m)
                        masked = m_str[:8] + '***' + m_str[-4:] if len(m_str) > 15 else m_str[:4] + '***'
                        found.append(f"[{sev}] {name}: {masked}")
        return found

    def _print_finding(self, finding):
        sev = finding['severity']
        colors = {"CRITICAL": Colors.CRITICAL, "HIGH": Colors.HIGH,
                 "MEDIUM": Colors.MEDIUM, "LOW": Colors.LOW}
        icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
        color = colors.get(sev, Colors.INFO)
        icon = icons.get(sev, "⚪")

        print(f"  {color}╔{'═' * 70}╗{Colors.RESET}")
        print(f"  {color}║ {icon} [{sev}] {finding['type'][:58]:<58} ║{Colors.RESET}")
        print(f"  {color}╠{'═' * 70}╣{Colors.RESET}")
        print(f"  {color}║{Colors.RESET}  {finding['url'][:68]}")
        for detail in finding['details']:
            print(f"  {color}║{Colors.RESET}  → {detail[:65]}")
        if finding.get('content_preview'):
            print(f"  {color}║{Colors.RESET}  Preview:")
            for line in finding['content_preview'].split('\n')[:2]:
                if line.strip():
                    print(f"  {color}║{Colors.RESET}    {line[:62]}")
        print(f"  {color}╚{'═' * 70}╝{Colors.RESET}")

    # ═══════════════════════════════════════════════════════════════
    # GENERATE COMPREHENSIVE REPORTS
    # ═══════════════════════════════════════════════════════════════
    def generate_comprehensive_reports(self):
        self.print_section("FINAL: Generating Comprehensive Reports")

        total = sum(len(f) for f in self.results.values())

        # TXT Report
        report_file = os.path.join(self.output_dir, f"COMPLETE_REPORT_{self.domain}.txt")
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("  🔥 GitExposer COMPLETE CHAIN SCANNER - Full Report 🔥\n")
            f.write(f"  Target: {self.domain}\n")
            f.write(f"  Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Authored by: TehanG07\n\n")
            f.write("  ⚠️  FOR LEGAL & AUTHORIZED PENETRATION TESTING ONLY ⚠️\n")
            f.write("=" * 80 + "\n\n")

            f.write("COMPREHENSIVE SCAN STATISTICS:\n")
            f.write(f"  Total Subdomains Found: {self.stats['subdomains_found']}\n")
            f.write(f"  Live Subdomains: {self.stats['live_hosts']}\n")
            f.write(f"  Live URLs: {len(self.live_urls)}\n")
            f.write(f"  URLs Collected: {self.stats['urls_collected']}\n")
            f.write(f"  Paths Scanned: {self.stats['paths_scanned']}\n")
            f.write(f"  Git Repos Found: {len(self.git_repos_found)}\n")
            f.write(f"  Total Findings: {total}\n\n")

            f.write("  Severity Breakdown:\n")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", 
                       "LOW": "🔵", "INFO": "⚪"}[sev]
                f.write(f"    {icon} {sev}: {len(self.results[sev])}\n")
            f.write("\n")

            # Git Repos
            if self.git_repos_found:
                f.write("=" * 80 + "\n")
                f.write(f"  EXPOSED GIT REPOSITORIES ({len(self.git_repos_found)})\n")
                f.write("=" * 80 + "\n\n")
                for repo in self.git_repos_found:
                    f.write(f"  URL: {repo['base_url']}/.git/\n")
                    f.write(f"  HEAD: {repo['head_content']}\n")
                    f.write(f"  Domain: {repo['domain']}\n\n")

            # Findings
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                findings = self.results[severity]
                if not findings:
                    continue

                f.write(f"\n{'=' * 80}\n")
                f.write(f"  {severity} FINDINGS ({len(findings)})\n")
                f.write(f"{'=' * 80}\n\n")

                for i, finding in enumerate(findings, 1):
                    f.write(f"[{i}] {finding['type']}\n")
                    f.write(f"    URL: {finding['url']}\n")
                    for detail in finding['details']:
                        f.write(f"    → {detail}\n")
                    if finding.get('content_preview'):
                        f.write(f"\n    Content Preview:\n")
                        for line in finding['content_preview'].split('\n')[:3]:
                            if line.strip():
                                f.write(f"      {line[:70]}\n")
                    f.write(f"\n{'─' * 40}\n\n")

            f.write("\n" + "=" * 80 + "\n")
            f.write("  Authored by: TehanG07 | Complete Chain Scanner v3.0\n")
            f.write("=" * 80 + "\n")

        self.print_status(f"Report: {report_file}", "success")

        # CSV
        csv_file = os.path.join(self.output_dir, f"findings_{self.domain}.csv")
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Severity', 'Type', 'URL', 'Details'])
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                for finding in self.results[sev]:
                    writer.writerow([sev, finding['type'], finding['url'], 
                                   ' | '.join(finding['details'])])
        self.print_status(f"CSV: {csv_file}", "success")

        # JSON
        json_file = os.path.join(self.output_dir, f"findings_{self.domain}.json")
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump({
                "scan_info": self.stats,
                "git_repos": self.git_repos_found,
                "findings": self.results
            }, f, indent=2)
        self.print_status(f"JSON: {json_file}", "success")

    # ═══════════════════════════════════════════════════════════════
    # MAIN RUN
    # ═══════════════════════════════════════════════════════════════
    def run(self):
        self.print_banner()
        start = time.time()

        try:
            self.enumerate_subdomains()
            self.collect_urls_batched()
            self.find_all_live_hosts()
            self.detect_git_exposure_comprehensive()
            self.scan_all_paths_comprehensive()
            self.generate_comprehensive_reports()
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Interrupted{Colors.RESET}")
            self.generate_comprehensive_reports()
        except Exception as e:
            print(f"{Colors.ERROR}[!] Error: {e}{Colors.RESET}")
            self.generate_comprehensive_reports()

        elapsed = time.time() - start
        m, s = int(elapsed // 60), int(elapsed % 60)

        print(f"\n  {Colors.SUCCESS}⏱  Completed in {m}m {s}s{Colors.RESET}")
        print(f"  {Colors.SUCCESS}📁 Output: {self.output_dir}/{Colors.RESET}\n")

        # Summary
        print(f"{Colors.BANNER}  SCAN SUMMARY:{Colors.RESET}")
        print(f"  Subdomains: {self.stats['subdomains_found']} found, {self.stats['live_hosts']} live")
        print(f"  URLs: {self.stats['urls_collected']} collected")
        print(f"  Paths: {self.stats['paths_scanned']} scanned")
        print(f"  Findings: {self.stats['findings']}\n")


def main():
    print(f"""
{Colors.BANNER}
╔══════════════════════════════════════════════════════════════════════╗
║     🔥 COMPLETE CHAIN SCANNER v3.0 - ALL SUBDOMAINS 🔥              ║
║                    Authored by: TehanG07                             ║
╚══════════════════════════════════════════════════════════════════════╝
{Colors.RESET}""")

    domain = input(f"  {Colors.SUCCESS}[?] Enter domain: {Colors.WHITE}").strip()
    print(f"{Colors.RESET}")

    if not domain:
        print(f"  {Colors.ERROR}[✘] No domain{Colors.RESET}")
        sys.exit(1)

    domain = domain.replace('https://', '').replace('http://', '').strip('/').split('/')[0]

    confirm = input(f"  {Colors.WARNING}[?] Authorized to test {domain}? (yes/no): {Colors.WHITE}").lower().strip()
    print(f"{Colors.RESET}")

    if confirm not in ['yes', 'y']:
        print(f"  {Colors.ERROR}[✘] Authorization required{Colors.RESET}\n")
        sys.exit(1)

    scanner = GitExposerCompleteChain(domain)
    scanner.run()


if __name__ == "__main__":
    main()
