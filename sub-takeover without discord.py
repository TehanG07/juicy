#!/usr/bin/env python3
import sys
import subprocess
import json
import requests
import os
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

# Disable SSL warnings for mass scanning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Color formatting
RED, GREEN, YELLOW, CYAN, BOLD, RESET = "\033[91m", "\033[92m", "\033[93m", "\033[96m", "\033[1m", "\033[0m"

class SubdomainTakeoverHunter:
    def __init__(self):
        # 🚀 ADD YOUR WEBHOOK HERE
        self.webhook_url = "YOUR_DISCORD_WEBHOOK_URL"
        self.domain = None
        self.all_subs_file = None
        self.vulnerables = []
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0"
        ]

    def print_banner(self):
        print(f"{RED}{BOLD}" + "="*55)
        print("    🎯 ADVANCED SUBDOMAIN TAKEOVER HUNTER v2.0 🎯")
        print("          Automated Recon & Discord Alert")
        print("="*55 + f"{RESET}")

    def run_command(self, command):
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=400)
            return result.stdout.strip() if result.stdout else ""
        except Exception as e:
            return ""

    def tool_exists(self, tool):
        return subprocess.run(f"which {tool}", shell=True, capture_output=True).returncode == 0

    def find_subdomains(self):
        print(f"{CYAN}[+] Step 1: Deep Reconnaissance...{RESET}")
        subdomains = set()
        
        # 1. Subfinder (Passive)
        print(f"    {YELLOW}→ Running Subfinder...{RESET}")
        out = self.run_command(f"subfinder -d {self.domain} -silent -all")
        subdomains.update(out.split('\n'))

        # 2. Assetfinder
        if self.tool_exists("assetfinder"):
            print(f"    {YELLOW}→ Running Assetfinder...{RESET}")
            out = self.run_command(f"assetfinder --subs-only {self.domain}")
            subdomains.update(out.split('\n'))

        # 3. DNSX (Verification & Alive Subs)
        if self.tool_exists("dnsx"):
            print(f"    {YELLOW}→ Running DNSX (Filtering dead domains)...{RESET}")
            temp_file = "raw_subs.txt"
            with open(temp_file, "w") as f:
                f.write("\n".join(filter(None, subdomains)))
            
            # This cleans the list and ensures they actually resolve
            out = self.run_command(f"dnsx -l {temp_file} -silent")
            subdomains = set(out.split('\n'))
            os.remove(temp_file)

        valid_subs = sorted([s.strip() for s in subdomains if s.strip()])
        print(f"{GREEN}[✓] Total Unique Active Subdomains: {len(valid_subs)}{RESET}")
        return valid_subs

    def verify_dangling(self, subdomain):
        """Advanced verification logic: DNS CNAME + HTTP Fingerprint"""
        # 1. Check CNAME Chain via dig
        cname_chain = self.run_command(f"dig {subdomain} CNAME +short")
        if not cname_chain:
            return None

        # 2. Known Vulnerable Service Patterns
        fingerprints = {
            'GitHub Pages': ['there isn\'t a github pages site here', '404 not found'],
            'Heroku': ['no such app', 'herokucdn.com/error-pages/no-such-app'],
            'AWS S3': ['nosuchbucket', 'the specified bucket does not exist'],
            'Azure': ['404 web site not found', 'sitename.azurewebsites.net'],
            'Shopify': ['sorry, this shop is currently unavailable'],
            'WordPress': ['do you want to register', 'wordpress.com'],
            'Netlify': ['not found - request id', 'netlify.app'],
            'Pantheon': ['404 error unknown site']
        }

        try:
            # Check HTTP
            resp = requests.get(f"http://{subdomain}", timeout=10, verify=False, allow_redirects=True, headers={'User-Agent': random.choice(self.user_agents)})
            body = resp.text.lower()
            
            for service, patterns in fingerprints.items():
                for p in patterns:
                    if p in body:
                        return f"{service} (Fingerprint Found)"
        except:
            # If HTTP fails but CNAME exists, it might still be dangling
            if "amazonaws" in cname_chain or "herokuapp" in cname_chain:
                return "Potential (Connection Timed Out)"
        
        return None

    def send_discord(self, vuln_list):
        if not self.webhook_url or "YOUR_" in self.webhook_url:
            return
            
        for v in vuln_list:
            data = {
                "embeds": [{
                    "title": "🚨 SUBDOMAIN TAKEOVER DETECTED!",
                    "color": 15158332, # Red
                    "fields": [
                        {"name": "Domain", "value": f"`{self.domain}`", "inline": True},
                        {"name": "Vulnerable Sub", "value": f"`{v}`", "inline": False},
                        {"name": "Timestamp", "value": f"{datetime.now()}"}
                    ],
                    "footer": {"text": "Cyber Protectors Bot"}
                }]
            }
            requests.post(self.webhook_url, json=data)

    def run(self):
        self.print_banner()
        self.domain = input(f"{CYAN}[?] Enter target domain (e.g. example.com): {RESET}").strip()
        if not self.domain: return

        # Get Subs
        subs = self.find_subdomains()
        if not subs: return

        # Check for Takeovers
        print(f"\n{CYAN}[+] Step 2: Analyzing CNAME Chains & Fingerprints...{RESET}")
        vulnerables = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_sub = {executor.submit(self.verify_dangling, sub): sub for sub in subs}
            for future in as_completed(future_to_sub):
                sub = future_to_sub[future]
                res = future.result()
                if res:
                    msg = f"{sub} -> {res}"
                    print(f"{RED}{BOLD}[!!!] TAKEOVER: {msg}{RESET}")
                    vulnerables.append(msg)

        # Final Report
        if vulnerables:
            print(f"\n{RED}# Found {len(vulnerables)} vulnerabilities. Sending alerts...{RESET}")
            self.send_discord(vulnerables)
            # Save to file
            with open(f"takeover_{self.domain}.txt", "w") as f:
                f.write("\n".join(vulnerables))
        else:
            print(f"\n{GREEN}[✓] No takeovers found on {self.domain}. Clean scan.{RESET}")

if __name__ == "__main__":
    try:
        hunter = SubdomainTakeoverHunter()
        hunter.run()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Aborted by user.{RESET}")
