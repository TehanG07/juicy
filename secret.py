#!/usr/bin/env python3
"""
Secret-Killer v1.0
Author: TehanG07 (cybereye)
Multi-Engine Sensitive Info Scanner for URLs (JS/JSON)
"""

import os, re, json, requests, subprocess
from urllib.parse import urljoin
from detect_secrets.core.scan import scan_file
from detect_secrets.settings import default_settings
from termcolor import colored

# ----------------------------
# Banner
# ----------------------------
print(colored("""
   ███████╗███████╗ ██████╗███████╗████████╗
   ██╔════╝██╔════╝██╔════╝██╔════╝╚══██╔══╝
   ███████╗█████╗  ██║     █████╗     ██║   
   ╚════██║██╔══╝  ██║     ██╔══╝     ██║   
   ███████║███████╗╚██████╗███████╗   ██║   
   ╚══════╝╚══════╝ ╚═════╝╚══════╝   ╚═╝   
        Secret-Killer v1.0
        Author: TehanG07 (cybereye)
""","cyan"))

# ----------------------------
# Extra Regex
# ----------------------------
EXTRA_PATTERNS = {
    "Username": re.compile(r'["\']?(?:username|user_name|usr)["\']?\s*[:=]\s*["\']([^"\']{3,50})["\']?', re.I),
    "Email": re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'),
    "DB_User": re.compile(r'["\']?(?:db[_-]?user|dbUser)["\']?\s*[:=]\s*["\']([^"\']{3,50})["\']?', re.I),
    "DB_Pass": re.compile(r'["\']?(?:db[_-]?pass|db[_-]?password|dbPass)["\']?\s*[:=]\s*["\']([^"\']{3,50})["\']?', re.I),
    "SMTP/FTP_User": re.compile(r'["\']?(?:smtp[_-]?user|ftp[_-]?user)["\']?\s*[:=]\s*["\']([^"\']+)["\']?', re.I),
    "SMTP/FTP_Pass": re.compile(r'["\']?(?:smtp[_-]?pass|ftp[_-]?pass)["\']?\s*[:=]\s*["\']([^"\']+)["\']?', re.I),
}

# ----------------------------
# Fetch content
# ----------------------------
def fetch(url):
    try: return requests.get(url, headers={"User-Agent":"Mozilla/5.0"}, timeout=10).text
    except: return ""

# ----------------------------
# Extract JS/JSON links
# ----------------------------
def extract_links(base, html):
    return list({urljoin(base, m) for m in re.findall(r'<script[^>]+src=["\'](.*?)["\']', html, re.I) if m.endswith(".js")}
             | {urljoin(base, m) for m in re.findall(r'<link[^>]+href=["\'](.*?)["\']', html, re.I) if m.endswith(".json")})

# ----------------------------
# Scanners
# ----------------------------
def detect_secrets_scan(path): return [{"engine":"detect-secrets","secret":s.secret_value} for s in scan_file(path)]
def trufflehog_scan(path):
    r=[]
    try:
        p=subprocess.Popen(["trufflehog","filesystem","--json",path],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        for l in p.stdout:
            try: j=json.loads(l.strip()); r.append({"engine":"trufflehog","secret":j.get("Raw","N/A")})
            except: continue
    except: print("[!] TruffleHog not installed.")
    return r
def regex_scan(path):
    c=open(path,"r",errors="ignore").read()
    return [{"engine":"regex","type":n,"secret":m} for n,p in EXTRA_PATTERNS.items() for m in p.findall(c)]

# ----------------------------
# Scan URL
# ----------------------------
def scan_url(url,log):
    if not url.startswith("http"): url="https://"+url
    log.write(f"\n[+] URL: {url}\n{'='*50}\n")
    print(colored(f"\n[+] Scanning {url}","magenta"))
    content=fetch(url)
    files=[("main_page",content)]+[(l,fetch(l)) for l in extract_links(url,content)]
    for name,data in files:
        tmp=f"tmp_{os.path.basename(name)}"
        with open(tmp,"w",encoding="utf-8") as f: f.write(data)
        for scan in [detect_secrets_scan,trufflehog_scan,regex_scan]:
            for r in scan(tmp):
                sec=r.get("secret") or r.get("matched") or "N/A"
                t=r.get("type") or "unknown"
                log.write(f"{t}: {sec}\n"); print(colored(f"    {t}: {sec}","white"))
        os.remove(tmp)

# ----------------------------
# Main
# ----------------------------
file_path=input("[?] Enter file path with URLs to scan: ").strip()
if not os.path.isfile(file_path): exit("[!] File not found!")
urls=[l.strip() for l in open(file_path) if l.strip()]
if not urls: exit("[!] No URLs found!")

with open("secret-killer_results.txt","w",encoding="utf-8") as log:
    for u in urls: scan_url(u,log)

print(colored("\n✅ Scan complete! Results saved in secret-killer_results.txt","green"))
