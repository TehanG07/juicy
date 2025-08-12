import os
import re
import requests
import math
import base64
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

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
    print(colored("[+] Super Secret & Endpoint Scanner by TehanG07 - v5.0\n", "green"))

def entropy(text):
    if not text:
        return 0
    return -sum((text.count(c) / len(text)) * math.log2(text.count(c) / len(text)) for c in set(text))

def is_strong_password(pwd):
    length_ok = 8 <= len(pwd) <= 64
    upper = re.search(r'[A-Z]', pwd)
    lower = re.search(r'[a-z]', pwd)
    digit = re.search(r'\d', pwd)
    special = re.search(r'[@#$%^&+=!*_\-.,]', pwd)
    complexity_count = sum(bool(x) for x in [upper, lower, digit, special])
    return length_ok and complexity_count >= 3

def verify_secret(name, val):
    if name == 'PASSWORD':
        return is_strong_password(val)
    if len(val) < 6 or val.lower() in ['true', 'false', 'null', 'none']:
        return False
    if entropy(val) > 3.5:
        return True
    return False

PRIVATE_KEY_PATTERNS = [
    r"-----BEGIN RSA PRIVATE KEY-----\s+([A-Za-z0-9+/=\s]{200,})\s+-----END RSA PRIVATE KEY-----",
    r"-----BEGIN EC PRIVATE KEY-----\s+([A-Za-z0-9+/=\s]{200,})\s+-----END EC PRIVATE KEY-----",
    r"-----BEGIN DSA PRIVATE KEY-----\s+([A-Za-z0-9+/=\s]{200,})\s+-----END DSA PRIVATE KEY-----",
    r"-----BEGIN PRIVATE KEY-----\s+([A-Za-z0-9+/=\s]{200,})\s+-----END PRIVATE KEY-----",
]

compiled_private_key_patterns = [re.compile(p, re.DOTALL) for p in PRIVATE_KEY_PATTERNS]

def detect_private_keys(text):
    keys_found = []
    for pattern in compiled_private_key_patterns:
        for match in pattern.finditer(text):
            key_body = match.group(1)
            cleaned_body = "".join(key_body.split())
            if len(cleaned_body) >= 200:
                keys_found.append(match.group(0))
    return keys_found

JWT_REGEX = re.compile(r'\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{10,})\b')

def base64url_decode(input_str):
    padding = '=' * (-len(input_str) % 4)
    return base64.urlsafe_b64decode(input_str + padding)

def extract_jwts(text):
    tokens = JWT_REGEX.findall(text)
    results = []
    for token in tokens:
        try:
            header_b64, payload_b64, signature_b64 = token.split('.')
            json.loads(base64url_decode(header_b64))
            json.loads(base64url_decode(payload_b64))
            results.append(token)
        except Exception:
            continue
    return results

EMAIL_REGEX = re.compile(
    r'(?<![a-zA-Z0-9._%+-])'
    r'([a-zA-Z0-9._%+-]+@'
    r'[a-zA-Z0-9.-]+\.' 
    r'[a-zA-Z]{2,})'
)

def is_valid_email(email):
    if len(email) > 254:
        return False
    local_part, _, domain = email.rpartition('@')
    if len(local_part) > 64:
        return False
    if '..' in local_part:
        return False
    if local_part.startswith('.') or local_part.endswith('.'):
        return False
    if '..' in domain:
        return False
    domain_parts = domain.split('.')
    for part in domain_parts:
        if part.startswith('-') or part.endswith('-') or len(part) == 0:
            return False
    return True

def extract_emails(text):
    candidates = EMAIL_REGEX.findall(text)
    return [email for email in candidates if is_valid_email(email)]

def is_valid_username(username):
    if not 3 <= len(username) <= 30:
        return False
    if not re.match(r'^[a-zA-Z0-9]', username):
        return False
    if not re.match(r'.*[a-zA-Z0-9]$', username):
        return False
    if '..' in username or '--' in username or '.-' in username or '-.' in username:
        return False
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return False
    return True

API_PATTERNS = {
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Temporary Access Key": r"ASIA[0-9A-Z]{16}",
    "AWS Account ID": r"A3T[A-Z0-9]{13}",
    "AWS Gov Access Key": r"AGPA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"[0-9a-zA-Z/+]{40}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth Token": r"ya29\.[0-9A-Za-z\-_]+",
    "GitHub Personal Access Token": r"ghp_[0-9A-Za-z]{36}",
    "GitHub OAuth Token": r"gho_[0-9A-Za-z]{36}",
    "GitHub User Token": r"ghu_[0-9A-Za-z]{36}",
    "GitHub Server Token": r"ghs_[0-9A-Za-z]{36}",
    "GitHub Refresh Token": r"ghr_[0-9A-Za-z]{36}",
    "Stripe Live Key": r"sk_live_[0-9A-Za-z]{24}",
    "Stripe Test Key": r"sk_test_[0-9A-Za-z]{24}",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z\-]{10,48}",
    "SendGrid API Key": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Cloudflare API Key": r"cloudflare_[A-Za-z0-9]{37}",
    "Cloudflare Token": r"CF\.[A-Za-z0-9]{37}",
    "Shopify API Key": r"shpat_[A-Za-z0-9]{32}",
    "Square Access Token": r"sq0atp-[A-Za-z0-9\-_]{22}",
    "Square Client Secret": r"sq0csp-[A-Za-z0-9\-_]{43}",
    "DigitalOcean Token": r"DO\.[A-Za-z0-9]{30,64}",
    "Heroku API Key": r"heroku_[A-Za-z0-9]{30,64}",
}

combined_api_patterns = "|".join(f"({p})" for p in API_PATTERNS.values())
MASTER_API_REGEX = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?key|secret[_-]?key|auth[_-]?(?:token|key)|x-api-key|token|bearer|client[_-]?secret|consumer[_-]?key|private[_-]?key|app[_-]?secret|app[_-]?key)[\'\"=:\s>]{0,5}(" + combined_api_patterns + r")"
)

ENCODED_REGEX = re.compile(
    r'(?:[A-Za-z0-9+/]{20,}={0,2}|[A-Fa-f0-9]{20,}|(?:\\x[0-9A-Fa-f]{2}){4,}|(?:%[0-9A-Fa-f]{2}){4,}|(?:&(?:[a-zA-Z]{2,}|#[0-9]{2,4}|#x[0-9A-Fa-f]{2,4});){2,})'
)

def is_valid_encoded(candidate: str) -> bool:
    if '/' in candidate:
        return False
    blacklist_words = ['com', 'repos', 'zipball', 'template', 'blob', 'raw', 'github']
    tokens = re.split(r'[^a-zA-Z0-9]+', candidate.lower())
    if any(word in tokens for word in blacklist_words):
        return False
    if len(candidate) < 20:
        return False
    return True

DB_URI_REGEX = re.compile(
    r'(?i)\b(mysql|mongodb|postgresql?|mssql|oracle|redis|cassandra):\/\/(?:[a-zA-Z0-9._%+-]+(:[^@\/\s]*)?@)?(?:[a-zA-Z0-9.-]+|\[[0-9a-fA-F:.]+\])(?::\d{1,5})?(?:\/[a-zA-Z0-9_\-]+)?(?:\?[a-zA-Z0-9=&_\-]+)?\b'
)

FIREBASE_API_KEY_REGEX = re.compile(
    r'(?i)firebase[_\-]?api[_\-]?key[\'"=:\s>]{0,3}(AIzaSy[a-zA-Z0-9_\-]{35})'
)
FIREBASE_PROJECT_ID_REGEX = re.compile(
    r'(?i)(?:firebase|google-services)[\'"=:\s>]{0,3}([a-z0-9\-]{6,30})'
)
FIREBASE_DB_URL_REGEX = re.compile(
    r'https?://[a-z0-9\-]+\.firebaseio\.com|https?://[a-z0-9\-]+\.firebasedatabase\.app'
)

def extract_firebase_data(text):
    results = {
        "api_keys": [],
        "project_ids": [],
        "database_urls": []
    }
    for m in FIREBASE_API_KEY_REGEX.finditer(text):
        results["api_keys"].append(m.group(1))
    for m in FIREBASE_PROJECT_ID_REGEX.finditer(text):
        results["project_ids"].append(m.group(1))
    results["database_urls"] = FIREBASE_DB_URL_REGEX.findall(text)
    return results

# New mobile number regex (simple, covers intl and local numbers)
MOBILE_REGEX = re.compile(
    r'(?<!\w)(\+?\d{1,3}[-.\s]?(\(?\d{1,4}\)?)[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9})(?!\w)'
)

def is_valid_mobile(mobile):
    digits = re.sub(r'\D', '', mobile)
    return 7 <= len(digits) <= 15  # reasonable phone length

def extract_mobiles(text):
    candidates = MOBILE_REGEX.findall(text)
    # MOBILE_REGEX captures tuple groups, pick full match
    numbers = [match[0] for match in candidates]
    return [num for num in numbers if is_valid_mobile(num)]

def find_secrets(content, options):
    results = []

    if 1 in options:  # API Keys / Tokens
        api_matches = MASTER_API_REGEX.findall(content)
        for match in api_matches:
            key = next(k for k in match if k)
            provider = "Unknown API Key"
            for name, pattern in API_PATTERNS.items():
                if re.fullmatch(pattern, key):
                    provider = name
                    break
            if verify_secret("API_KEY", key):
                results.append((provider, key))

    if 4 in options:  # Passwords
        pwd_pattern = re.compile(r'(?i)(password|pass|pwd)[\'"=:\s>]{1,3}([^\s\'"]{8,64})')
        for m in pwd_pattern.finditer(content):
            candidate = m.group(2)
            if is_strong_password(candidate):
                results.append(('PASSWORD', candidate))

    if 6 in options:  # DB URLs
        for m in DB_URI_REGEX.finditer(content):
            results.append(('DB_URI', m.group(0)))

    if 5 in options:  # Tokens (Firebase, JWT, Private Keys)
        firebase = extract_firebase_data(content)
        for key in firebase['api_keys']:
            results.append(('FIREBASE_API_KEY', key))
        for proj in firebase['project_ids']:
            results.append(('FIREBASE_PROJECT_ID', proj))
        for url in firebase['database_urls']:
            results.append(('FIREBASE_DB_URL', url))
        private_keys = detect_private_keys(content)
        for key in private_keys:
            results.append(('PRIVATE_KEY', key))
        jwts = extract_jwts(content)
        for token in jwts:
            results.append(('JWT', token))

    if 2 in options:  # Emails
        emails = extract_emails(content)
        for email in emails:
            results.append(('EMAIL', email))

    if 3 in options:  # Usernames
        username_pattern = re.compile(r"(?i)(username|user|login)[\'\"=:\s>]{1,3}([a-zA-Z0-9_\-\.]{3,30})")
        for m in username_pattern.finditer(content):
            candidate = m.group(2)
            if is_valid_username(candidate):
                results.append(('USERNAME', candidate))

    if 8 in options:  # Encoded strings
        for m in ENCODED_REGEX.finditer(content):
            candidate = m.group(0)
            if is_valid_encoded(candidate):
                results.append(('ENCODED', candidate))

    if 7 in options:  # Mobile numbers
        mobiles = extract_mobiles(content)
        for number in mobiles:
            results.append(('MOBILE', number))

    return list(set(results))

def find_endpoints(content, base_url):
    pattern = re.compile(r'(?i)(/api/[a-zA-Z0-9/_\-]+|/v[0-9]+/[a-zA-Z0-9/_\-]+|/auth/[a-zA-Z0-9/_\-]+|/user/[a-zA-Z0-9/_\-]+)')
    raw_eps = list(set(pattern.findall(content)))
    full_eps = []
    for ep in raw_eps:
        if ep.startswith('http'):
            full_eps.append(ep)
        else:
            full_eps.append(urljoin(base_url, ep))
    return full_eps

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
        'AWS Access Key ID': 'green',
        'AWS Temporary Access Key': 'green',
        'AWS Account ID': 'green',
        'AWS Gov Access Key': 'green',
        'AWS Secret Access Key': 'green',
        'Google API Key': 'green',
        'Google OAuth Token': 'green',
        'GitHub Personal Access Token': 'blue',
        'GitHub OAuth Token': 'blue',
        'GitHub User Token': 'blue',
        'GitHub Server Token': 'blue',
        'GitHub Refresh Token': 'blue',
        'Stripe Live Key': 'yellow',
        'Stripe Test Key': 'yellow',
        'Slack Token': 'cyan',
        'SendGrid API Key': 'magenta',
        'Mailgun API Key': 'magenta',
        'Cloudflare API Key': 'green',
        'Cloudflare Token': 'green',
        'Shopify API Key': 'cyan',
        'Square Access Token': 'cyan',
        'Square Client Secret': 'cyan',
        'DigitalOcean Token': 'cyan',
        'Heroku API Key': 'cyan',
        'PASSWORD': 'red',
        'EMAIL': 'blue',
        'USERNAME': 'cyan',
        'JWT': 'yellow',
        'ENCODED': 'magenta',
        'DB_URI': 'red',
        'FIREBASE_API_KEY': 'blue',
        'FIREBASE_PROJECT_ID': 'blue',
        'FIREBASE_DB_URL': 'blue',
        'PRIVATE_KEY': 'red',
        'MOBILE': 'magenta',
        'ENDPOINT': 'white'
    }
    return color_map.get(key, 'white')

def scan_url(url, options, log):
    if not url.startswith("http"):
        url = "https://" + url

    print(colored(f"\n[+] Scanning: {url}", "magenta"))
    log.write(f"\n[+] URL: {url}\n{'='*60}\n")

    content = fetch_content(url)
    if not content:
        return

    all_content = [content]
    linked_files = extract_js_json_links(url, content)
    for file_url in linked_files:
        file_content = fetch_content(file_url)
        if file_content:
            all_content.append(file_content)

    # Find secrets
    combined_results = []
    for data in all_content:
        found = find_secrets(data, options)
        combined_results.extend(found)

    combined_results = list(set(combined_results))

    # Find endpoints (only if API scan selected)
    endpoints = []
    if 1 in options:
        for data in all_content:
            eps = find_endpoints(data, url)
            endpoints.extend(eps)
        endpoints = list(set(endpoints))

    # Print and log
    for key, val in combined_results:
        print(colored(f"    🔐 {key}: ", color_by_type(key)) + colored(val, 'white'))
        log.write(f"{key}: {val}\n")

    if endpoints:
        print(colored("\n    📡 Endpoints Found:", "white"))
        log.write("\nEndpoints Found:\n")
        for ep in endpoints:
            print(colored(f"     - {ep}", "white"))
            log.write(f"{ep}\n")

def main():
    banner()
    print("Select scan types (comma separated):")
    print("1. API Keys / Tokens")
    print("2. Emails")
    print("3. Usernames")
    print("4. Passwords")
    print("5. Tokens (Firebase, JWT, Private Keys)")
    print("6. Database URIs")
    print("7. Mobile Numbers")
    print("8. Encoded strings")

    choices = input("[?] Enter choices (e.g. 1,3,5): ").strip()
    options = set()
    for c in choices.split(','):
        c = c.strip()
        if c.isdigit():
            c_int = int(c)
            if 1 <= c_int <= 8:
                options.add(c_int)

    if not options:
        print(colored("[-] No valid scan type selected. Exiting.", "red"))
        return

    url_file = input("[?] Enter the file path with URLs to scan: ").strip()
    if not os.path.isfile(url_file):
        print(colored("[-] File not found.", "red"))
        return

    with open(url_file, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    if not urls:
        print(colored("[-] No URLs found in file.", "red"))
        return

    output_file = "scan_results.txt"
    with open(output_file, 'w', encoding='utf-8') as log:

        # Use ThreadPoolExecutor for parallel scanning, but limit concurrency
        max_workers = 5
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for url in urls:
                futures.append(executor.submit(scan_url, url, options, log))
                time.sleep(0.3)  # Delay to avoid aggressive scanning

            for future in as_completed(futures):
                pass  # Results handled inside scan_url

    print(colored(f"\nScan completed. Results saved in {output_file}", "green"))

if __name__ == "__main__":
    main()
