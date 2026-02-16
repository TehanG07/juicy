#!/usr/bin/env python3
"""
Subdomain Takeover Hunter - Auto Discord Notification
Just run: python3 sub-takeover.py
"""

import sys
import subprocess
import json
import requests
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import urllib3

# ✅ FIX 1: Disable SSL warnings completely
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# HARDCODED WEBHOOK - No need to provide
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1469932856603054152/Fs4K5LPduyEzNpMi4MxVhP6qYTk2gPAXTojj73c0xTHJWFrJANgSfKH8GuZmnID6fNGh"

class SubdomainTakeoverHunter:
    def __init__(self):
        self.webhook_url = DISCORD_WEBHOOK
        self.domain = None
        self.all_subs_file = None
        self.takeover_file = None
        self.vulnerables = []
        
    def print_banner(self):
        banner = """
\033[91m╔═══════════════════════════════════════════════════════╗
║                                                       ║
║        🎯 SUBDOMAIN TAKEOVER HUNTER 🎯               ║
║         Automated Takeover Detection                  ║
║          With Discord Notifications                   ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝\033[0m
        """
        print(banner)
    
    def get_domain_input(self):
        print("\033[96m[?] Enter target domain:\033[0m ", end="")
        self.domain = input().strip()
        
        if not self.domain:
            print("\033[91m[!] Domain cannot be empty!\033[0m")
            sys.exit(1)
        
        self.domain = self.domain.replace("http://", "").replace("https://", "").rstrip("/")
        
        self.all_subs_file = f"{self.domain}_all_subs.txt"
        self.takeover_file = f"{self.domain}_takeovers.txt"
        
        print(f"\n\033[92m[✓] Target Set: {self.domain}\033[0m")
        print(f"\033[93m[*] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m\n")
    
    def run_command(self, command):
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True,
                timeout=300
            )
            return result.stdout.strip() if result.stdout else ""
        except subprocess.TimeoutExpired:
            print(f"\033[91m[!] Command timed out: {command}\033[0m")
            return ""
        except Exception as e:
            print(f"\033[91m[!] Error: {e}\033[0m")
            return ""
    
    def tool_exists(self, tool):
        return subprocess.run(f"which {tool}", shell=True, capture_output=True).returncode == 0
    
    def find_subdomains(self):
        print("\033[94m[+] Hunting Subdomains...\033[0m")
        subdomains = set()
        
        # subfinder
        print("    \033[96m→ Running subfinder...\033[0m")
        result = self.run_command(f"subfinder -d {self.domain} -silent")
        if result:
            subs = [s.strip() for s in result.split('\n') if s.strip()]
            subdomains.update(subs)
            print(f"      \033[92m✓ Found {len(subs)} subdomains\033[0m")
        
        # assetfinder
        if self.tool_exists("assetfinder"):
            print("    \033[96m→ Running assetfinder...\033[0m")
            result = self.run_command(f"assetfinder --subs-only {self.domain}")
            if result:
                subs = [s.strip() for s in result.split('\n') if s.strip()]
                subdomains.update(subs)
                print(f"      \033[92m✓ Found {len(subs)} subdomains\033[0m")
        
        # amass
        if self.tool_exists("amass"):
            print("    \033[96m→ Running amass...\033[0m")
            result = self.run_command(f"amass enum -passive -d {self.domain} -silent 2>/dev/null")
            if result:
                subs = [s.strip() for s in result.split('\n') if s.strip()]
                subdomains.update(subs)
                print(f"      \033[92m✓ Found {len(subs)} subdomains\033[0m")
        
        # findomain
        if self.tool_exists("findomain"):
            print("    \033[96m→ Running findomain...\033[0m")
            result = self.run_command(f"findomain -t {self.domain} -q 2>/dev/null")
            if result:
                subs = [s.strip() for s in result.split('\n') if s.strip()]
                subdomains.update(subs)
                print(f"      \033[92m✓ Found {len(subs)} subdomains\033[0m")
        
        subdomains = sorted([sub for sub in subdomains if sub])
        
        with open(self.all_subs_file, 'w') as f:
            for sub in subdomains:
                f.write(f"{sub}\n")
        
        print(f"\n\033[92m[✓] Total Unique Subdomains: {len(subdomains)}\033[0m")
        return subdomains
    
    def check_takeover_subjack(self):
        print("\n\033[94m[+] Checking with Subjack...\033[0m")
        
        if not os.path.exists(self.all_subs_file):
            print("\033[91m[!] No subdomains file found\033[0m")
            return []
        
        result = self.run_command(f"subjack -w {self.all_subs_file} -t 100 -timeout 30 -ssl -v 2>/dev/null")
        
        vulnerables = []
        if result:
            for line in result.split('\n'):
                if 'Vulnerable' in line or '[Vulnerable]' in line:
                    vulnerables.append(line.strip())
                    print(f"    \033[91m[!] VULNERABLE: {line.strip()}\033[0m")
        
        if not vulnerables:
            print("    \033[93m[-] No vulnerabilities found with subjack\033[0m")
        
        return vulnerables
    
    # ✅ FIX 2: Verify CNAME is actually dangling (not just pointing to service)
    def verify_cname_dangling(self, subdomain, cname):
        """Verify if the CNAME target actually resolves or is dead"""
        try:
            # Check if CNAME target has an A record
            result = self.run_command(f"dig +short A {cname.rstrip('.')}")
            if not result:
                return True  # No A record = dangling = vulnerable
            
            # Also check HTTP response for error pages
            for proto in ['https', 'http']:
                try:
                    resp = requests.get(
                        f"{proto}://{subdomain}", 
                        timeout=5, 
                        verify=False, 
                        allow_redirects=True
                    )
                    
                    # Check for common takeover error pages
                    error_indicators = [
                        'nosuchbucket', 'no such app', 'there isn\'t a github pages',
                        'site not found', 'project not found', 'unknown domain',
                        'web site not found', 'error 404', 'domain is not configured',
                        'the specified bucket does not exist', 'repository not found',
                        'help center closed', 'fastly error', '404 error unknown site',
                        'whatever you were looking for', 'not found - request id',
                        'this uservoice subdomain', 'project doesnt exist',
                        'sorry, this shop is currently unavailable',
                        'the thing you were looking for is no longer here',
                        'no settings were found', 'status page push'
                    ]
                    
                    content_lower = resp.text.lower()
                    for indicator in error_indicators:
                        if indicator in content_lower:
                            return True
                    
                    # If status is 404/503 with very small body, likely dangling
                    if resp.status_code in [404, 503] and len(resp.text) < 500:
                        return True
                        
                except:
                    continue
            
            return False  # CNAME resolves fine, not dangling
            
        except:
            return True  # Can't verify = treat as potentially vulnerable
    
    def check_cname_records(self, subdomain):
        """Check CNAME records for potential takeover"""
        try:
            result = self.run_command(f"dig +short CNAME {subdomain}")
            if result:
                vulnerable_services = {
                    'amazonaws.com': 'AWS S3',
                    's3.amazonaws.com': 'AWS S3',
                    'azurewebsites.net': 'Azure',
                    'cloudapp.net': 'Azure',
                    'cloudfront.net': 'AWS CloudFront',
                    'github.io': 'GitHub Pages',
                    'gitlab.io': 'GitLab Pages',
                    'herokuapp.com': 'Heroku',
                    'herokudns.com': 'Heroku',
                    'surge.sh': 'Surge',
                    'bitbucket.io': 'Bitbucket',
                    'ghost.io': 'Ghost',
                    'zendesk.com': 'Zendesk',
                    'helpscoutdocs.com': 'HelpScout',
                    'readme.io': 'Readme',
                    'statuspage.io': 'StatusPage',
                    'uservoice.com': 'UserVoice',
                    'wordpress.com': 'WordPress',
                    'pantheonsite.io': 'Pantheon',
                    'netlify.app': 'Netlify',
                    'netlify.com': 'Netlify',
                    'cargo.site': 'Cargo',
                    'feedpress.me': 'FeedPress',
                    'freshdesk.com': 'Freshdesk',
                    'shopify.com': 'Shopify',
                    'tumblr.com': 'Tumblr',
                    'fly.dev': 'Fly.io',
                    'unbouncepages.com': 'Unbounce'
                }
                
                cname_lower = result.lower()
                for pattern, service in vulnerable_services.items():
                    if pattern in cname_lower:
                        return True, result.strip(), service
            return False, None, None
        except:
            return False, None, None
    
    def manual_takeover_check(self, subdomains):
        """Check CNAME records and verify if dangling"""
        print("\n\033[94m[+] Performing CNAME Analysis...\033[0m")
        cname_candidates = []
        
        # Step 1: Find subdomains with suspicious CNAMEs (fast)
        print("    \033[96m→ Resolving CNAME records...\033[0m")
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(self.check_cname_records, sub): sub 
                      for sub in subdomains}
            
            for future in as_completed(futures):
                subdomain = futures[future]
                try:
                    is_suspicious, cname, service = future.result()
                    if is_suspicious:
                        cname_candidates.append((subdomain, cname, service))
                        print(f"    \033[93m[~] Suspicious CNAME: {subdomain}\033[0m")
                        print(f"        \033[93m→ {cname} ({service})\033[0m")
                except:
                    pass
        
        if not cname_candidates:
            print("    \033[93m[-] No suspicious CNAME records found\033[0m")
            return []
        
        # ✅ Step 2: Verify which ones are actually dangling (important!)
        print(f"\n    \033[96m→ Verifying {len(cname_candidates)} candidates for dangling records...\033[0m")
        confirmed_vulns = []
        
        for subdomain, cname, service in cname_candidates:
            is_dangling = self.verify_cname_dangling(subdomain, cname)
            if is_dangling:
                vuln_info = f"{subdomain} → CNAME: {cname} ({service}) [DANGLING]"
                confirmed_vulns.append(vuln_info)
                print(f"    \033[91m[!] CONFIRMED TAKEOVER: {subdomain}\033[0m")
                print(f"        \033[91mCNAME: {cname}\033[0m")
                print(f"        \033[91mService: {service}\033[0m")
            else:
                print(f"    \033[92m[✓] Safe (resolves): {subdomain}\033[0m")
        
        if not confirmed_vulns:
            print("    \033[92m[✓] All CNAMEs are resolving properly - no dangling records\033[0m")
        
        return confirmed_vulns
    
    def check_http_fingerprints(self, subdomain):
        """Check HTTP response for takeover fingerprints"""
        fingerprints = {
            'GitHub Pages': ['there isn\'t a github pages site here', 'site not found · github pages'],
            'Heroku': ['no such app', 'no-such-app', 'herokucdn.com/error-pages/no-such-app'],
            'AWS S3': ['nosuchbucket', 'the specified bucket does not exist'],
            'Shopify': ['sorry, this shop is currently unavailable', 'only one step left'],
            'Tumblr': ['whatever you were looking for doesn\'t currently exist'],
            'Ghost': ['the thing you were looking for is no longer here'],
            'Surge': ['project not found'],
            'Azure': ['404 web site not found', 'error 404 - web app not found'],
            'Bitbucket': ['repository not found'],
            'Smartling': ['domain is not configured'],
            'Acquia': ['web site not found'],
            'Fastly': ['fastly error: unknown domain'],
            'Pantheon': ['404 error unknown site!'],
            'Zendesk': ['help center closed'],
            'Readme.io': ['project doesnt exist'],
            'StatusPage': ['status page push was not enabled', 'you are being redirected'],
            'HelpScout': ['no settings were found for this company'],
            'Cargo': ['if you\'re moving your domain away from cargo'],
            'Feedpress': ['the feed has not been found'],
            'Freshdesk': ['may be this is still fresh'],
            'UserVoice': ['this uservoice subdomain is currently available'],
            'Netlify': ['not found - request id'],
            'Fly.io': ['404 not found'],
            'Unbounce': ['the requested url was not found']
        }
        
        for proto in ['http', 'https']:
            try:
                response = requests.get(
                    f"{proto}://{subdomain}", 
                    timeout=8, 
                    verify=False, 
                    allow_redirects=True,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'}
                )
                content = response.text.lower()
                
                for service, patterns in fingerprints.items():
                    for pattern in patterns:
                        if pattern in content:
                            return True, service
            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.Timeout:
                continue
            except:
                continue
        
        return False, None
    
    def http_fingerprint_scan(self, subdomains):
        """Scan HTTP fingerprints"""
        print("\n\033[94m[+] Scanning HTTP Fingerprints...\033[0m")
        http_vulns = []
        
        scan_list = subdomains[:150] if len(subdomains) > 150 else subdomains
        total = len(scan_list)
        done = 0
        
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {executor.submit(self.check_http_fingerprints, sub): sub 
                      for sub in scan_list}
            
            for future in as_completed(futures):
                subdomain = futures[future]
                done += 1
                
                # ✅ Progress indicator
                sys.stdout.write(f"\r    \033[96m→ Progress: {done}/{total} subdomains checked\033[0m")
                sys.stdout.flush()
                
                try:
                    is_vuln, service = future.result()
                    if is_vuln:
                        vuln_info = f"{subdomain} → Service: {service} [HTTP FINGERPRINT]"
                        http_vulns.append(vuln_info)
                        print(f"\n    \033[91m[!] Takeover Fingerprint: {subdomain}\033[0m")
                        print(f"        \033[91mService: {service}\033[0m")
                except:
                    pass
        
        print()  # New line after progress
        
        if not http_vulns:
            print("    \033[93m[-] No HTTP fingerprints found\033[0m")
        
        return http_vulns
    
    def send_discord_notification(self, vulnerables):
        """Send to Discord webhook using requests (like curl)"""
        if not vulnerables:
            return
        
        print("\n\033[94m[+] Sending Discord Alert...\033[0m")
        
        vuln_list = "\n".join([f"• {v}" for v in vulnerables[:15]])
        if len(vulnerables) > 15:
            vuln_list += f"\n... and {len(vulnerables) - 15} more"
        
        embed = {
            "title": "🚨 SUBDOMAIN TAKEOVER DETECTED 🚨",
            "description": f"Found **{len(vulnerables)}** potential subdomain takeovers",
            "color": 15158332,
            "fields": [
                {
                    "name": "🎯 Target Domain",
                    "value": f"```{self.domain}```",
                    "inline": True
                },
                {
                    "name": "⚠️ Severity",
                    "value": "```CRITICAL```",
                    "inline": True
                },
                {
                    "name": "📊 Total Found",
                    "value": f"```{len(vulnerables)}```",
                    "inline": True
                },
                {
                    "name": "🔍 Vulnerable Subdomains",
                    "value": f"```\n{vuln_list}\n```",
                    "inline": False
                },
                {
                    "name": "📝 Action Required",
                    "value": "• Remove dangling DNS records\n• Claim unclaimed services\n• Verify subdomain ownership",
                    "inline": False
                }
            ],
            "footer": {
                "text": f"Takeover Hunter | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            }
        }
        
        webhook_data = {
            "username": "Takeover Hunter",
            "content": f"🚨 **TAKEOVER ALERT: `{self.domain}`** 🚨",
            "embeds": [embed]
        }
        
        try:
            response = requests.post(
                self.webhook_url,
                json=webhook_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 204:
                print("\033[92m[✓] Discord notification sent successfully!\033[0m")
            elif response.status_code == 200:
                print("\033[92m[✓] Discord notification sent successfully!\033[0m")
            else:
                print(f"\033[91m[!] Discord returned status: {response.status_code}\033[0m")
                print(f"    Response: {response.text[:200]}")
                
        except Exception as e:
            print(f"\033[91m[!] Error sending Discord notification: {e}\033[0m")
    
    def save_results(self):
        if self.vulnerables:
            with open(self.takeover_file, 'w') as f:
                f.write(f"{'='*60}\n")
                f.write(f"  SUBDOMAIN TAKEOVER REPORT\n")
                f.write(f"{'='*60}\n")
                f.write(f"  Domain    : {self.domain}\n")
                f.write(f"  Date      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"  Total     : {len(self.vulnerables)} vulnerabilities\n")
                f.write(f"{'='*60}\n\n")
                
                for i, vuln in enumerate(self.vulnerables, 1):
                    f.write(f"  {i}. {vuln}\n")
                
                f.write(f"\n{'='*60}\n")
            
            print(f"\033[92m[✓] Results saved to: {self.takeover_file}\033[0m")
    
    def run(self):
        self.print_banner()
        self.get_domain_input()
        
        # Check tools
        print("\033[94m[*] Checking required tools...\033[0m")
        required = ['subfinder']
        optional = ['subjack', 'assetfinder', 'amass', 'findomain']
        missing_required = []
        
        for tool in required:
            if self.tool_exists(tool):
                print(f"    \033[92m✓ {tool} found\033[0m")
            else:
                missing_required.append(tool)
                print(f"    \033[91m✗ {tool} NOT FOUND (required)\033[0m")
        
        for tool in optional:
            if self.tool_exists(tool):
                print(f"    \033[92m✓ {tool} found\033[0m")
            else:
                print(f"    \033[93m- {tool} not found (optional)\033[0m")
        
        if missing_required:
            print(f"\n\033[91m[!] Missing required tools: {', '.join(missing_required)}\033[0m")
            print("\n\033[93mInstall:\033[0m")
            print("  \033[96mgo install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\033[0m")
            sys.exit(1)
        
        print("\n" + "="*60)
        
        # Step 1: Find subdomains
        subdomains = self.find_subdomains()
        
        if not subdomains:
            print(f"\n\033[91m[!] No subdomains found for {self.domain}\033[0m")
            return
        
        print("\n" + "="*60)
        
        # Step 2: Subjack check (if available)
        if self.tool_exists("subjack"):
            subjack_vulns = self.check_takeover_subjack()
            if subjack_vulns:
                self.vulnerables.extend(subjack_vulns)
        else:
            print("\n\033[93m[*] Skipping subjack (not installed)\033[0m")
        
        # Step 3: CNAME analysis with verification
        manual_vulns = self.manual_takeover_check(subdomains)
        if manual_vulns:
            self.vulnerables.extend(manual_vulns)
        
        # Step 4: HTTP fingerprints
        http_vulns = self.http_fingerprint_scan(subdomains)
        if http_vulns:
            self.vulnerables.extend(http_vulns)
        
        # Remove duplicates
        self.vulnerables = list(set(self.vulnerables))
        
        # Results
        print("\n" + "="*60)
        if self.vulnerables:
            print(f"\033[91m")
            print(f"  ██████╗ FOUND {len(self.vulnerables)} TAKEOVER(S)!")
            print(f"  ██╔═══╝ Domain: {self.domain}")
            print(f"  ██████╗ Status: CRITICAL")
            print(f"  ╚═══██║")
            print(f"  ██████║")
            print(f"  ╚═════╝\033[0m")
            print("="*60)
            
            for i, vuln in enumerate(self.vulnerables, 1):
                print(f"\033[91m  {i}. {vuln}\033[0m")
            
            print("="*60)
            
            self.save_results()
            self.send_discord_notification(self.vulnerables)
            
            print(f"\n\033[91m[⚠] IMMEDIATE ACTION REQUIRED!\033[0m")
            print(f"\033[93m    These subdomains can be claimed by attackers.\033[0m")
            
        else:
            print(f"\033[92m[✓] No subdomain takeover vulnerabilities found\033[0m")
            print(f"\033[92m[✓] {self.domain} appears to be secure\033[0m")
        
        print(f"\n{'='*60}")
        print(f"\033[92m[✓] Scan completed at {datetime.now().strftime('%H:%M:%S')}\033[0m\n")
        
        # Cleanup
        if os.path.exists(self.all_subs_file):
            os.remove(self.all_subs_file)


def main():
    try:
        hunter = SubdomainTakeoverHunter()
        hunter.run()
    except KeyboardInterrupt:
        print("\n\n\033[93m[!] Scan interrupted by user\033[0m")
        sys.exit(0)
    except Exception as e:
        print(f"\n\033[91m[!] Unexpected error: {e}\033[0m")
        sys.exit(1)

if __name__ == "__main__":
    main()
            
