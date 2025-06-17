import os
import re
import requests
import math
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from termcolor import colored

# Author: TehanG07

def banner():
    print(colored("""
  ███████╗███████╗ ██████╗███████╗████████╗
  ██╔════╝██╔════╝██╔════╝██╔════╝╚══██╔══╝
  ███████╗█████╗  ██║     █████╗     ██║   
  ╚════██║██╔══╝  ██║     ██╔══╝     ██║   
  ███████║███████╗╚██████╗███████╗   ██║   
  ╚══════╝╚══════╝ ╚═════╝╚══════╝   ╚═╝   
    """, "cyan"))
    print(colored("[+] Super Secret & Endpoint Scanner by TehanG07 - v3.5\n", "green"))

def entropy(text):
    if not text:
        return 0
    return -sum((text.count(c) / len(text)) * math.log2(text.count(c) / len(text)) for c in set(text))

def verify_secret(name, val):
    if len(val) < 6 or val.lower() in ['true', 'false', 'null', 'none']:
        return False
    if entropy(val) > 3.5:
        return True
    return False

def find_secrets(content):
    patterns = {
        'API_KEY': r'(?i)(api[_-]?key|access[_-]?key|auth[_-]?token|x-api-key)[\'"=:\s>]{1,3}([a-z0-9A-Z\-\._]{16,})',
        'PASSWORD': r'(?i)(password|pass|pwd)[\'"=:\s>]{1,3}([a-zA-Z0-9@#\$%\^&\+=!*\-_\.,]{6,})',
        'USERNAME': r'(?i)(username|user|login)[\'"=:\s>]{1,3}([a-zA-Z0-9_\-\.]{3,50})',
        'EMAIL': r'(?<!//)(?<![a-zA-Z0-9])([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)',
        'JWT': r'(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)',
        'ENCODED': r'["\']([A-Za-z0-9+/=]{20,})["\']',
        'DB_URI': r'(?i)(mysql|mongodb|postgres|sql):\/\/[a-z0-9:_@\-\.\/]+',
        'FIREBASE': r'(?i)(firebase|google-services)[\'"=:\s>]{1,3}[a-zA-Z0-9_\-:\.]{10,}',
        'AWS_KEY': r'(?i)(aws[_-]?(access|secret)?[_-]?key)[\'"=:\s>]{1,3}[A-Za-z0-9/+=]{16,}',
        'STRIPE': r'(?i)(sk_live|pk_live|stripe[_-]?key)[\'"=:\s>]{1,3}[a-z0-9A-Z_\-]{16,}',
        'SLACK': r'(?i)(slack|bot|hook)[\'"=:\s>]{1,3}(xox[baprs]-[a-zA-Z0-9-]{10,})',
        'GITHUB_TOKEN': r'ghp_[A-Za-z0-9]{36}',
        'PRIVATE_KEY': r'-----BEGIN(.*?)PRIVATE KEY-----'
    }

    results = []
    for name, pattern in patterns.items():
        matches = re.findall(pattern, content)
        for match in matches:
            value = match[-1].strip() if isinstance(match, tuple) else match.strip()
            if name != "EMAIL" and not verify_secret(name, value):
                continue
            results.append((name, value))
    return list(set(results))

def find_endpoints(content):
    pattern = re.compile(r'(?i)(/api/[a-zA-Z0-9/_-]+|/v[0-9]+/[a-zA-Z0-9/_-]+|/auth/[a-zA-Z0-9/_-]+|/user/[a-zA-Z0-9/_-]+)')
    return list(set(pattern.findall(content)))

def fetch_content(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        res = requests.get(url, timeout=10, headers=headers)
        return res.text
    except Exception as e:
        print(colored(f"[-] Failed to fetch: {url} ({e})", "red"))
        return ""

def extract_js_json_links(base_url, html):
    soup = BeautifulSoup(html, "html.parser")
    found_links = []

    for tag in soup.find_all(["script"], src=True):
        link = urljoin(base_url, tag.get("src"))
        if link.endswith(".js"):
            found_links.append(link)

    for tag in soup.find_all("link", href=True):
        link = urljoin(base_url, tag.get("href"))
        if link.endswith(".json"):
            found_links.append(link)

    return list(set(found_links))

def color_by_type(key):
    color_map = {
        'API_KEY': 'green',
        'PASSWORD': 'red',
        'EMAIL': 'blue',
        'USERNAME': 'cyan',
        'JWT': 'yellow',
        'ENCODED': 'magenta',
        'DB_URI': 'red',
        'FIREBASE': 'blue',
        'AWS_KEY': 'green',
        'STRIPE': 'yellow',
        'SLACK': 'cyan',
        'GITHUB_TOKEN': 'blue',
        'PRIVATE_KEY': 'red',
        'ENDPOINT': 'white'
    }
    return color_map.get(key, 'white')

def scan_urls(file_path):
    if not os.path.exists(file_path):
        print(colored(f"[!] File not found: {file_path}", "red"))
        return

    with open(file_path, 'r', errors='ignore') as f:
        urls = [x.strip() for x in f.read().splitlines() if x.strip()]

    with open("scan_results.txt", "w") as log:
        for url in urls:
            if not url.startswith("http"):
                url = "https://" + url
            print(colored(f"\n[+] Scanning: {url}", "magenta"))
            log.write(f"\n[+] URL: {url}\n{'='*60}\n")

            content = fetch_content(url)
            if not content:
                continue

            all_content = [content]
            linked_files = extract_js_json_links(url, content)
            for linked in linked_files:
                linked_content = fetch_content(linked)
                if linked_content:
                    all_content.append(linked_content)

            for data in all_content:
                secrets = find_secrets(data)
                endpoints = find_endpoints(data)

                for s in secrets:
                    k, v = s
                    print(colored(f"    🔐 {k}: {v}", color_by_type(k)))
                    log.write(f"{k}: {v}\n")

                for ep in endpoints:
                    print(colored(f"    📍 ENDPOINT => {ep}", color_by_type('ENDPOINT')))
                    log.write(f"ENDPOINT => {ep}\n")

            log.write("="*60 + "\n")

def main():
    banner()
    while True:
        path = input(colored("[?] Enter file path with URLs (or 'q' to quit): ", "yellow")).strip()
        if path.lower() == 'q':
            break
        scan_urls(path)
    print(colored("\n[✓] Scanning complete! Results saved in scan_results.txt", "green"))

if __name__ == "__main__":
    main()
