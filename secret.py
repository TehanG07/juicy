#!/usr/bin/env python3
"""
🔥 ULTIMATE URL SOURCE CODE ANALYZER v9.1 🔥
Extracts EVERYTHING useful from URL source code
- Improved Phone Number Extraction
- Generates ONLY TXT Report (Colored, Category-wise)
- Only shows URLs WITH findings
- Separator lines between URLs

Author: TehanG07 + Community
License: Educational & Authorized Testing Only
"""

import os
import sys
import re
import json
import math
import base64
import hashlib
import datetime
import time
import ssl
import threading
from urllib.request import urlopen, Request
from urllib.parse import urlparse, urljoin, parse_qs
from urllib.error import HTTPError, URLError
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Optional, Any
from collections import defaultdict
from html.parser import HTMLParser

# ==================== COLORS ====================
class Colors:
    """ANSI color codes for terminal AND text markers for file"""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

    # Category colors
    RED = "\033[91m"         # Credentials & Secrets, Private Keys
    GREEN = "\033[92m"       # API Endpoints, Subdomains
    YELLOW = "\033[93m"      # JWT Tokens, Interesting URLs
    BLUE = "\033[94m"        # Emails, IP Addresses
    MAGENTA = "\033[95m"     # Phone Numbers, Sensitive PII
    CYAN = "\033[96m"        # AWS, Google/Firebase, Cloud
    WHITE = "\033[97m"       # Other
    ORANGE = "\033[38;5;208m"  # Payment Keys, Messaging
    PINK = "\033[38;5;213m"    # Database Connections
    LIME = "\033[38;5;118m"    # Git Tokens
    GOLD = "\033[38;5;220m"    # Comments
    PURPLE = "\033[38;5;141m"  # Azure
    TEAL = "\033[38;5;51m"     # Interesting URLs

    # Separator & Header
    HEADER_BG = "\033[48;5;236m"
    SEP_COLOR = "\033[38;5;240m"
    URL_COLOR = "\033[38;5;39m"
    COUNT_COLOR = "\033[38;5;226m"
    ARROW = "\033[38;5;243m"
    STAR = "\033[38;5;220m"

# Category -> Color mapping
CATEGORY_COLORS = {
    "JWT Tokens": Colors.YELLOW,
    "Emails": Colors.BLUE,
    "AWS Resources": Colors.CYAN,
    "Google/Firebase": Colors.CYAN,
    "Git Tokens": Colors.LIME,
    "Payment Keys": Colors.ORANGE,
    "Messaging/Webhooks": Colors.ORANGE,
    "Database Connections": Colors.PINK,
    "Private Keys": Colors.RED,
    "IP Addresses": Colors.BLUE,
    "Phone Numbers": Colors.MAGENTA,
    "Credentials & Secrets": Colors.RED,
    "Sensitive PII": Colors.MAGENTA,
    "Interesting Comments": Colors.GOLD,
    "Azure Resources": Colors.PURPLE,
    "API Endpoints": Colors.GREEN,
    "Subdomains": Colors.GREEN,
    "Interesting URLs": Colors.TEAL,
    "Other Secrets": Colors.WHITE,
}

# Category -> Emoji mapping
CATEGORY_EMOJIS = {
    "JWT Tokens": "🔑",
    "Emails": "📧",
    "AWS Resources": "☁️",
    "Google/Firebase": "🔥",
    "Git Tokens": "🐙",
    "Payment Keys": "💳",
    "Messaging/Webhooks": "💬",
    "Database Connections": "🗄️",
    "Private Keys": "🔐",
    "IP Addresses": "🌐",
    "Phone Numbers": "📱",
    "Credentials & Secrets": "🚨",
    "Sensitive PII": "⚠️",
    "Interesting Comments": "💭",
    "Azure Resources": "☁️",
    "API Endpoints": "🔗",
    "Subdomains": "🌍",
    "Interesting URLs": "🔍",
    "Other Secrets": "🔶",
}

# ==================== CONFIGURATION ====================
class Config:
    VERSION = "9.1"
    MAX_WORKERS = 10
    FETCH_TIMEOUT = 20
    MAX_SIZE = 15 * 1024 * 1024  # 15MB
    RATE_LIMIT = 0.3
    VERBOSE = True
    FOLLOW_JS = True
    MAX_JS_PER_URL = 15
    DECODE_JWT = True
    VALIDATE_KEYS = True

# ==================== GLOBALS ====================
SEEN_URLS: Set[str] = set()
SEEN_SECRETS: Set[str] = set()
URL_FINDINGS: Dict[str, Dict[str, List]] = defaultdict(lambda: defaultdict(list))

STATS = {
    "urls_scanned": 0,
    "urls_with_findings": 0,
    "total_findings": 0,
    "js_files_scanned": 0,
    "start_time": None
}

LOCK = threading.Lock()

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# ==================== BANNER ====================
def print_banner():
    print(f"""
{Colors.ORANGE}╔═══════════════════════════════════════════════════════════════════════════════════╗{Colors.RESET}
{Colors.ORANGE}║{Colors.RESET}  {Colors.RED}{Colors.BOLD}🔥 ULTIMATE URL SOURCE CODE ANALYZER v9.1 🔥{Colors.RESET}                                     {Colors.ORANGE}║{Colors.RESET}
{Colors.ORANGE}║{Colors.RESET}  {Colors.CYAN}👨‍💻 Extracts EVERYTHING useful from URL source code{Colors.RESET}                               {Colors.ORANGE}║{Colors.RESET}
{Colors.ORANGE}║{Colors.RESET}  {Colors.MAGENTA}📱 Improved Phone Number Extraction{Colors.RESET}                                              {Colors.ORANGE}║{Colors.RESET}
{Colors.ORANGE}║{Colors.RESET}  {Colors.GREEN}📂 OUTPUT: TXT file ONLY (Colored, Category-wise){Colors.RESET}                                 {Colors.ORANGE}║{Colors.RESET}
{Colors.ORANGE}╠═══════════════════════════════════════════════════════════════════════════════════╣{Colors.RESET}
{Colors.ORANGE}║{Colors.RESET}  {Colors.YELLOW}📋 What it finds:{Colors.RESET}                                                                 {Colors.ORANGE}║{Colors.RESET}
{Colors.ORANGE}║{Colors.RESET}     {Colors.YELLOW}• JWT Tokens (decoded!){Colors.RESET}    {Colors.BLUE}• Email Addresses{Colors.RESET}      {Colors.RED}• API Keys & Secrets{Colors.RESET}        {Colors.ORANGE}║{Colors.RESET}
{Colors.ORANGE}║{Colors.RESET}     {Colors.BLUE}• Internal IPs{Colors.RESET}             {Colors.GREEN}• Subdomains{Colors.RESET}           {Colors.GREEN}• API Endpoints{Colors.RESET}             {Colors.ORANGE}║{Colors.RESET}
{Colors.ORANGE}║{Colors.RESET}     {Colors.CYAN}• S3 Buckets{Colors.RESET}               {Colors.CYAN}• Firebase URLs{Colors.RESET}        {Colors.PINK}• Database Strings{Colors.RESET}          {Colors.ORANGE}║{Colors.RESET}
{Colors.ORANGE}║{Colors.RESET}     {Colors.RED}• Credentials{Colors.RESET}              {Colors.MAGENTA}• Phone Numbers{Colors.RESET}       {Colors.RED}• Private Keys{Colors.RESET}              {Colors.ORANGE}║{Colors.RESET}
{Colors.ORANGE}║{Colors.RESET}     {Colors.GOLD}• Comments with secrets{Colors.RESET}  {Colors.ORANGE}• Social media tokens{Colors.RESET}  {Colors.CYAN}• Cloud resources{Colors.RESET}           {Colors.ORANGE}║{Colors.RESET}
{Colors.ORANGE}╠═══════════════════════════════════════════════════════════════════════════════════╣{Colors.RESET}
{Colors.ORANGE}║{Colors.RESET}  {Colors.RED}⚠️  For AUTHORIZED SECURITY TESTING ONLY{Colors.RESET}                                         {Colors.ORANGE}║{Colors.RESET}
{Colors.ORANGE}╚═══════════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
""")

# ==================== EXTRACTION PATTERNS ====================
PATTERNS = {
    "JWT Token": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_\-]+",
    "AWS Access Key": r"(?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16}",
    "AWS Secret Key": r"(?i)(?:aws)?_?(?:secret)?_?(?:access)?_?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})",
    "AWS S3 Bucket": r"(?:s3://|https?://)?([a-zA-Z0-9\-\.]+)\.s3(?:\.[a-zA-Z0-9\-]+)?\.amazonaws\.com",
    "AWS S3 Bucket Alt": r"s3\.amazonaws\.com/([a-zA-Z0-9\-\.]+)",
    "AWS ARN": r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]*:[a-zA-Z0-9\-_/:.]+",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Firebase URL": r"https?://[a-z0-9\-]+\.firebaseio\.com/?[^\s\"'<>]*",
    "Firebase Storage": r"https?://firebasestorage\.googleapis\.com/[^\s\"'<>]+",
    "GCS Bucket": r"(?:gs://|https?://storage\.googleapis\.com/)([a-zA-Z0-9\-_.]+)",
    "Firebase FCM": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "GitHub Token (ghp)": r"ghp_[A-Za-z0-9_]{36,255}",
    "GitHub Token (gho)": r"gho_[A-Za-z0-9]{36}",
    "GitHub PAT": r"github_pat_[A-Za-z0-9_]{22,255}",
    "GitHub App Token": r"(?:ghs|ghr)_[A-Za-z0-9]{36}",
    "GitLab Token": r"glpat-[A-Za-z0-9\-_]{20,}",
    "Stripe Live Secret": r"sk_live_[A-Za-z0-9]{24,}",
    "Stripe Live Publish": r"pk_live_[A-Za-z0-9]{24,}",
    "Stripe Test Secret": r"sk_test_[A-Za-z0-9]{24,}",
    "Stripe Webhook": r"whsec_[A-Za-z0-9]{32,}",
    "Slack Token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9\-]*",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}",
    "Discord Bot Token": r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}",
    "Discord Webhook": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+",
    "Twilio Account SID": r"AC[a-f0-9]{32}",
    "Twilio API Key": r"SK[a-f0-9]{32}",
    "SendGrid API Key": r"SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}",
    "Mailgun API Key": r"key-[A-Za-z0-9]{32}",
    "Mailchimp API Key": r"[a-f0-9]{32}-us[0-9]{1,2}",
    "Telegram Bot Token": r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",
    "Facebook Access Token": r"EAA[A-Za-z0-9]{50,}",
    "Facebook App Secret": r"(?i)(?:facebook|fb)_?(?:app)?_?secret['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32})",
    "Twitter Bearer": r"AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+",
    "Twitter API Key": r"(?i)twitter_?(?:api)?_?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9]{25})",
    "Shopify Token": r"shpat_[a-fA-F0-9]{32}",
    "Shopify Private": r"shppa_[a-fA-F0-9]{32}",
    "Heroku API Key": r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
    "DigitalOcean Token": r"dop_v1_[a-f0-9]{64}",
    "NPM Token": r"npm_[A-Za-z0-9]{36}",
    "Docker Hub Token": r"dckr_pat_[A-Za-z0-9\-_]{27}",
    "PayPal Braintree": r"access_token\$production\$[A-Za-z0-9]{16}\$[a-f0-9]{32}",
    "Square Access Token": r"sq0atp-[A-Za-z0-9\-_]{22}",
    "Square OAuth": r"sq0csp-[A-Za-z0-9\-_]{43}",
    "Mapbox Token": r"pk\.[a-zA-Z0-9]{60,}",
    "Mapbox Secret": r"sk\.[a-zA-Z0-9]{60,}",
    "Sentry DSN": r"https://[a-f0-9]{32}@[a-z0-9\-\.]+\.ingest\.sentry\.io/[0-9]+",
    "New Relic Key": r"NRAK-[A-Z0-9]{27}",
    "Linear API Key": r"lin_api_[A-Za-z0-9]{40}",
    "Notion Token": r"secret_[A-Za-z0-9]{43}",
    "Airtable Key": r"key[A-Za-z0-9]{14}",
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "EC Private Key": r"-----BEGIN EC PRIVATE KEY-----",
    "OpenSSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "PGP Private Key": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Generic Private Key": r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----",
    "MongoDB URI": r"mongodb(?:\+srv)?://[^\s\"'<>]+",
    "PostgreSQL URI": r"postgres(?:ql)?://[^\s\"'<>]+",
    "MySQL URI": r"mysql://[^\s\"'<>]+",
    "Redis URI": r"redis://[^\s\"'<>]+",
    "MSSQL Connection": r"(?i)(?:server|data source)=[^;]+;(?:[^;]+;)*(?:password|pwd)=[^;]+",
    "Bearer Token": r"(?i)bearer\s+[A-Za-z0-9\-_\.~\+\/]{20,}=*",
    "Basic Auth Header": r"(?i)basic\s+[A-Za-z0-9+/]{20,}=*",
    "Authorization Header": r"(?i)authorization['\"]?\s*[:=]\s*['\"]?(?:bearer|basic|token)\s+[^\s'\"]+",
    "Password in URL": r"(?i)(?:https?|ftp)://[^:]+:([^@]+)@[^/\s]+",
    "Password Field": r"(?i)(?:password|passwd|pwd|secret|token)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{6,})",
    "API Key Generic": r"(?i)(?:api[_\-]?key|apikey)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{16,})",
    "Secret Key Generic": r"(?i)(?:secret[_\-]?key|client[_\-]?secret)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{16,})",
    "Access Token Generic": r"(?i)(?:access[_\-]?token)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{16,})",
    "Email Address": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "Internal IP (10.x)": r"\b10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b",
    "Internal IP (172.x)": r"\b172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}\b",
    "Internal IP (192.168.x)": r"\b192\.168\.[0-9]{1,3}\.[0-9]{1,3}\b",
    "IPv4 Address": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "IPv6 Address": r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}",
    "API Endpoint": r"['\"]/(api|v[0-9]|rest|graphql)/[^'\"]+['\"]",
    "Internal URL": r"(?i)https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|internal|dev|stage|staging|test|admin)[:\d]*[^\s\"'<>]*",
    "Webhook URL": r"https?://[^\s\"'<>]*(?:webhook|hook|callback|notify)[^\s\"'<>]*",
    "Azure Storage": r"https?://[a-z0-9]+\.blob\.core\.windows\.net/[^\s\"'<>]+",
    "Azure Connection": r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+",
    "Phone Number": r"(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})(?: *x(\d+))?|(?:phone|mobile|tel|fax|contact)['\"]?\s*[:=]\s*['\"]?(\+?\d[\d\-\.\(\)\s]{8,}\d)",
    "SSN Pattern": r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b",
    "Credit Card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    "TODO Comment": r"(?i)(?://|/\*|#)\s*(?:todo|fixme|hack|xxx|bug).*",
    "Password Comment": r"(?i)(?://|/\*|#).*(?:password|passwd|pwd|secret|token|key|credential).*",
    "Debug Comment": r"(?i)(?://|/\*|#).*(?:debug|test|temp|remove|delete).*",
}

COMPILED_PATTERNS = {}
for name, pattern in PATTERNS.items():
    try:
        COMPILED_PATTERNS[name] = re.compile(pattern)
    except:
        pass

SUBDOMAIN_PATTERN = re.compile(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
ENDPOINT_PATTERN = re.compile(r"['\"]/((?:api|v[0-9]|rest|graphql|admin|user|auth|login|register|account|dashboard|internal|debug|test|config|setting|upload|download|file|data|export|import)[^\s\"']*)['\"]", re.I)

FALSE_POSITIVES = [
    r"example\.com", r"test\.com", r"localhost", r"127\.0\.0\.1",
    r"schema\.org", r"w3\.org", r"googleapis\.com/jsapi",
    r"jquery", r"bootstrap", r"fontawesome", r"cdnjs",
    r"^test", r"^example", r"^sample", r"^demo", r"^fake",
    r"^xxx+$", r"^000+$", r"placeholder",
]
COMPILED_FP = [re.compile(p, re.I) for p in FALSE_POSITIVES]

# ==================== HTTP UTILITIES ====================
def fetch_url(url: str) -> str:
    time.sleep(Config.RATE_LIMIT)
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "identity",
            "Connection": "keep-alive",
        }
        req = Request(url, headers=headers)
        with urlopen(req, timeout=Config.FETCH_TIMEOUT, context=SSL_CTX) as resp:
            return resp.read(Config.MAX_SIZE).decode('utf-8', 'ignore')
    except Exception as e:
        if Config.VERBOSE:
            print(f"    {Colors.RED}❌ Fetch error: {str(e)[:50]}{Colors.RESET}")
        return ""

# ==================== JWT DECODER ====================
def decode_jwt(token: str) -> Dict:
    result = {
        "valid": False,
        "header": None,
        "payload": None,
        "issues": [],
        "sensitive_data": []
    }
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return result

        header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_padded))
        result["header"] = header

        alg = header.get("alg", "").upper()
        if alg == "NONE":
            result["issues"].append("CRITICAL: Algorithm 'none' - Token can be FORGED!")
        elif alg in ["HS256", "HS384", "HS512"]:
            result["issues"].append("WARNING: HMAC algorithm - Secret key may be brute-forceable")

        payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_padded))
        result["payload"] = payload
        result["valid"] = True

        if "exp" in payload:
            exp_time = datetime.datetime.fromtimestamp(payload["exp"])
            if exp_time < datetime.datetime.now():
                result["issues"].append(f"Token EXPIRED: {exp_time}")
            else:
                result["issues"].append(f"Expires: {exp_time}")
        else:
            result["issues"].append("No expiration - Token never expires!")

        sensitive_keys = ["email", "sub", "user", "username", "user_id", "uid",
                          "admin", "role", "roles", "permissions", "scope", "scopes",
                          "aud", "iss", "name", "phone", "address"]
        for key in sensitive_keys:
            if key in payload:
                result["sensitive_data"].append({key: payload[key]})

    except Exception as e:
        result["issues"].append(f"Parse error: {str(e)}")
    return result

# ==================== VALIDATION ====================
def is_false_positive(value: str) -> bool:
    for pattern in COMPILED_FP:
        if pattern.search(value):
            return True
    if len(value) < 6:
        return True
    if len(set(value)) < 4:
        return True
    return False

# ==================== CATEGORIZATION ====================
def categorize_finding(pattern_name: str) -> str:
    name_lower = pattern_name.lower()
    if "jwt" in name_lower:
        return "JWT Tokens"
    elif "email" in name_lower:
        return "Emails"
    elif any(x in name_lower for x in ["aws", "s3", "arn"]):
        return "AWS Resources"
    elif any(x in name_lower for x in ["google", "firebase", "gcs", "fcm"]):
        return "Google/Firebase"
    elif any(x in name_lower for x in ["github", "gitlab"]):
        return "Git Tokens"
    elif any(x in name_lower for x in ["stripe", "paypal", "square", "braintree"]):
        return "Payment Keys"
    elif any(x in name_lower for x in ["slack", "discord", "telegram", "webhook"]):
        return "Messaging/Webhooks"
    elif any(x in name_lower for x in ["mongo", "postgres", "mysql", "redis", "mssql", "database"]):
        return "Database Connections"
    elif any(x in name_lower for x in ["private key", "rsa", "openssh", "pgp"]):
        return "Private Keys"
    elif any(x in name_lower for x in ["internal ip", "ipv4", "ipv6"]):
        return "IP Addresses"
    elif "phone" in name_lower:
        return "Phone Numbers"
    elif any(x in name_lower for x in ["password", "credential", "secret", "token", "api key", "access"]):
        return "Credentials & Secrets"
    elif any(x in name_lower for x in ["ssn", "credit card"]):
        return "Sensitive PII"
    elif any(x in name_lower for x in ["comment", "todo", "debug"]):
        return "Interesting Comments"
    elif any(x in name_lower for x in ["azure", "blob"]):
        return "Azure Resources"
    else:
        return "Other Secrets"

# ==================== MAIN SCANNER ====================
def extract_from_content(content: str, source_url: str) -> Dict[str, List]:
    findings = defaultdict(list)

    for pattern_name, pattern in COMPILED_PATTERNS.items():
        for match in pattern.finditer(content):
            value = match.group(0)
            if match.lastindex and match.lastindex >= 1:
                if pattern_name == "Phone Number":
                    value = match.group(0).strip()
                else:
                    value = match.group(1)

            if is_false_positive(value):
                continue

            fp = hashlib.md5(f"{pattern_name}:{value}".encode()).hexdigest()
            if fp in SEEN_SECRETS:
                continue
            SEEN_SECRETS.add(fp)

            finding = {
                "value": value[:500],
                "pattern": pattern_name,
            }

            if pattern_name == "JWT Token" and Config.DECODE_JWT:
                jwt_data = decode_jwt(value)
                if jwt_data["valid"]:
                    finding["decoded"] = jwt_data

            category = categorize_finding(pattern_name)
            findings[category].append(finding)

    for match in SUBDOMAIN_PATTERN.finditer(content):
        subdomain = match.group(0).lower()
        if not is_false_positive(subdomain) and subdomain not in SEEN_SECRETS:
            SEEN_SECRETS.add(subdomain)
            if not any(cdn in subdomain for cdn in ['googleapis', 'gstatic', 'cloudflare', 'jquery', 'bootstrap', 'cdnjs', 'unpkg', 'jsdelivr']):
                findings["Subdomains"].append({"value": subdomain})

    for match in ENDPOINT_PATTERN.finditer(content):
        endpoint = "/" + match.group(1)
        if endpoint not in SEEN_SECRETS:
            SEEN_SECRETS.add(endpoint)
            findings["API Endpoints"].append({"value": endpoint})

    interesting_urls = []
    for match in URL_PATTERN.finditer(content):
        url = match.group(0)
        if any(kw in url.lower() for kw in ['api', 'admin', 'internal', 'debug', 'test', 'dev', 'staging', 'config', 'secret', 'backup', 'token']):
            if url not in SEEN_SECRETS:
                SEEN_SECRETS.add(url)
                interesting_urls.append(url)

    if interesting_urls:
        for url in interesting_urls[:20]:
            findings["Interesting URLs"].append({"value": url})

    return dict(findings)


def scan_url(url: str) -> Dict[str, List]:
    all_findings = defaultdict(list)

    print(f"\n{Colors.CYAN}🔍 Scanning: {Colors.URL_COLOR}{url}{Colors.RESET}")

    content = fetch_url(url)
    if not content:
        print(f"    {Colors.RED}⚠️ Could not fetch content{Colors.RESET}")
        return {}

    print(f"    {Colors.GREEN}📄 Fetched {len(content):,} bytes{Colors.RESET}")

    findings = extract_from_content(content, url)
    for category, items in findings.items():
        all_findings[category].extend(items)

    if Config.FOLLOW_JS:
        js_urls = set()
        for match in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', content, re.I):
            js_url = match.group(1)
            if not js_url.startswith('http'):
                js_url = urljoin(url, js_url)
            js_urls.add(js_url)

        for match in re.finditer(r'href=["\']([^"\']+\.js[^"\']*)["\']', content, re.I):
            js_url = match.group(1)
            if not js_url.startswith('http'):
                js_url = urljoin(url, js_url)
            js_urls.add(js_url)

        js_scanned = 0
        for js_url in list(js_urls)[:Config.MAX_JS_PER_URL]:
            if js_url in SEEN_URLS:
                continue
            SEEN_URLS.add(js_url)

            js_content = fetch_url(js_url)
            if js_content:
                js_scanned += 1
                with LOCK:
                    STATS["js_files_scanned"] += 1

                js_findings = extract_from_content(js_content, js_url)
                for category, items in js_findings.items():
                    for item in items:
                        item["source"] = f"JS: {js_url.split('/')[-1][:30]}"
                    all_findings[category].extend(items)

        if js_scanned > 0:
            print(f"    {Colors.YELLOW}📜 Scanned {js_scanned} JS files{Colors.RESET}")

    return dict(all_findings)


def scan_urls_from_file(file_path: str):
    if not os.path.exists(file_path):
        print(f"{Colors.RED}❌ File not found: {file_path}{Colors.RESET}")
        return

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        urls = [line.strip() for line in f if line.strip() and line.strip().startswith('http')]

    if not urls:
        print(f"{Colors.RED}❌ No valid URLs found in file{Colors.RESET}")
        return

    print(f"\n{Colors.CYAN}📋 Found {len(urls)} URLs to scan{Colors.RESET}")
    print(f"{Colors.SEP_COLOR}{'=' * 80}{Colors.RESET}")

    STATS['start_time'] = datetime.datetime.now()

    for i, url in enumerate(urls, 1):
        print(f"\n{Colors.BOLD}[{i}/{len(urls)}]{Colors.RESET}", end="")

        if url in SEEN_URLS:
            print(f" {Colors.YELLOW}⏭️ Already scanned: {url[:50]}...{Colors.RESET}")
            continue

        SEEN_URLS.add(url)

        with LOCK:
            STATS['urls_scanned'] += 1

        findings = scan_url(url)

        if findings:
            with LOCK:
                STATS['urls_with_findings'] += 1
                URL_FINDINGS[url] = findings

            total = sum(len(v) for v in findings.values())
            STATS['total_findings'] += total

            print(f"    {Colors.GREEN}✅ Found {Colors.COUNT_COLOR}{total}{Colors.GREEN} items!{Colors.RESET}")

            for category, items in findings.items():
                if items:
                    color = CATEGORY_COLORS.get(category, Colors.WHITE)
                    emoji = CATEGORY_EMOJIS.get(category, "🔶")
                    print(f"       {color}{emoji} {category}: {len(items)}{Colors.RESET}")
                    for item in items[:3]:
                        value = item['value'][:60] + "..." if len(item['value']) > 60 else item['value']
                        source = f" {Colors.ARROW}[{item.get('source', '')}]{Colors.RESET}" if item.get('source') else ""
                        print(f"         {Colors.ARROW}→{Colors.RESET} {color}{value}{Colors.RESET}{source}")

                        if 'decoded' in item:
                            jwt = item['decoded']
                            for issue in jwt.get('issues', [])[:2]:
                                print(f"           {Colors.YELLOW}⚠ {issue}{Colors.RESET}")
                            for data in jwt.get('sensitive_data', [])[:2]:
                                print(f"           {Colors.GREEN}🔑 {data}{Colors.RESET}")

                    if len(items) > 3:
                        print(f"         {Colors.ARROW}... and {len(items) - 3} more{Colors.RESET}")
        else:
            print(f"    {Colors.SEP_COLOR}➖ No findings{Colors.RESET}")


# ==================== TXT REPORT GENERATION ====================
def strip_ansi(text: str) -> str:
    """Remove ANSI color codes for clean file writing"""
    ansi_escape = re.compile(r'\033\[[0-9;]*m')
    return ansi_escape.sub('', text)


def generate_txt_report():
    """Generate TXT report - ONLY URLs with findings, category-wise, separated"""

    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    duration = (datetime.datetime.now() - STATS['start_time']).total_seconds() if STATS['start_time'] else 0

    # Console Summary
    print(f"\n\n{Colors.SEP_COLOR}{'=' * 80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.STAR}📊 SCAN COMPLETE - SUMMARY{Colors.RESET}")
    print(f"{Colors.SEP_COLOR}{'=' * 80}{Colors.RESET}")
    print(f"   {Colors.CYAN}URLs Scanned:{Colors.RESET}         {Colors.COUNT_COLOR}{STATS['urls_scanned']}{Colors.RESET}")
    print(f"   {Colors.GREEN}URLs with Findings:{Colors.RESET}   {Colors.COUNT_COLOR}{STATS['urls_with_findings']}{Colors.RESET}")
    print(f"   {Colors.YELLOW}JS Files Scanned:{Colors.RESET}     {Colors.COUNT_COLOR}{STATS['js_files_scanned']}{Colors.RESET}")
    print(f"   {Colors.RED}Total Findings:{Colors.RESET}       {Colors.COUNT_COLOR}{STATS['total_findings']}{Colors.RESET}")
    print(f"   {Colors.MAGENTA}Scan Duration:{Colors.RESET}        {Colors.COUNT_COLOR}{duration:.2f} seconds{Colors.RESET}")
    print(f"{Colors.SEP_COLOR}{'=' * 80}{Colors.RESET}")

    if not URL_FINDINGS:
        print(f"\n{Colors.RED}❌ No findings in any URL{Colors.RESET}")
        txt_file = f"results_{timestamp}.txt"
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write("=" * 100 + "\n")
            f.write("  ULTIMATE URL SOURCE CODE ANALYZER v9.1 - RESULTS\n")
            f.write(f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Duration: {duration:.2f} seconds\n")
            f.write("=" * 100 + "\n\n")
            f.write("  No findings in any URL.\n")
        print(f"\n{Colors.CYAN}📁 Results TXT: {txt_file}{Colors.RESET}")
        return

    # Categorize all findings
    category_totals = defaultdict(int)
    for url, findings in URL_FINDINGS.items():
        for category, items in findings.items():
            category_totals[category] += len(items)

    print(f"\n{Colors.BOLD}{Colors.YELLOW}📈 FINDINGS BY CATEGORY:{Colors.RESET}")
    print(f"{Colors.SEP_COLOR}{'-' * 40}{Colors.RESET}")
    for category, count in sorted(category_totals.items(), key=lambda x: -x[1]):
        color = CATEGORY_COLORS.get(category, Colors.WHITE)
        emoji = CATEGORY_EMOJIS.get(category, "🔶")
        print(f"   {color}{emoji} {category}: {count}{Colors.RESET}")

    # ===== BUILD TXT CONTENT (with ANSI colors for terminal-like viewing) =====
    # We'll write two versions: colored (for terminals that support it) and clean

    txt_file = f"results_{timestamp}.txt"

    lines = []  # Clean lines (no ANSI)
    c_lines = []  # Colored lines (with ANSI for cat/less -R)

    sep_line = "=" * 100
    thin_sep = "-" * 100

    # Header
    lines.append(sep_line)
    lines.append("  🔥 ULTIMATE URL SOURCE CODE ANALYZER v9.1 - RESULTS REPORT")
    lines.append(f"  📅 Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  ⏱️  Duration: {duration:.2f} seconds")
    lines.append(sep_line)
    lines.append("")
    lines.append(f"  📊 SCAN STATISTICS:")
    lines.append(f"     • URLs Scanned:         {STATS['urls_scanned']}")
    lines.append(f"     • URLs with Findings:   {STATS['urls_with_findings']}")
    lines.append(f"     • JS Files Scanned:     {STATS['js_files_scanned']}")
    lines.append(f"     • Total Findings:       {STATS['total_findings']}")
    lines.append("")
    lines.append(f"  📈 CATEGORY TOTALS:")
    lines.append(thin_sep)

    for category, count in sorted(category_totals.items(), key=lambda x: -x[1]):
        emoji = CATEGORY_EMOJIS.get(category, "🔶")
        lines.append(f"     {emoji} {category}: {count}")

    lines.append("")
    lines.append(sep_line)
    lines.append("  🔗 DETAILED FINDINGS BY URL (Only URLs with data)")
    lines.append(sep_line)
    lines.append("")

    # Category sort order (most critical first)
    CATEGORY_ORDER = [
        "Credentials & Secrets",
        "Private Keys",
        "JWT Tokens",
        "AWS Resources",
        "Google/Firebase",
        "Azure Resources",
        "Database Connections",
        "Payment Keys",
        "Git Tokens",
        "Messaging/Webhooks",
        "Sensitive PII",
        "Phone Numbers",
        "Emails",
        "IP Addresses",
        "API Endpoints",
        "Subdomains",
        "Interesting URLs",
        "Interesting Comments",
        "Other Secrets",
    ]

    url_num = 0
    for url, findings in URL_FINDINGS.items():
        url_num += 1
        total = sum(len(v) for v in findings.values())

        # Separator between URLs
        if url_num > 1:
            lines.append("")
            lines.append("═" * 100)
            lines.append("")

        lines.append(f"  🌐 URL #{url_num}: {url}")
        lines.append(f"     📊 Total Findings: {total}")
        lines.append(thin_sep)

        # Sort categories by priority order
        sorted_cats = sorted(
            findings.items(),
            key=lambda x: CATEGORY_ORDER.index(x[0]) if x[0] in CATEGORY_ORDER else 999
        )

        for category, items in sorted_cats:
            if not items:
                continue

            emoji = CATEGORY_EMOJIS.get(category, "🔶")

            lines.append("")
            lines.append(f"     ┌─── {emoji} {category} ({len(items)}) ───")
            lines.append(f"     │")

            for idx, item in enumerate(items, 1):
                value = item['value']
                if len(value) > 120:
                    value = value[:120] + "..."

                source_str = ""
                if item.get('source'):
                    source_str = f"  ← [{item['source']}]"

                pattern_str = f"  ({item.get('pattern', '')})" if item.get('pattern') else ""

                lines.append(f"     │  [{idx:>3}] {value}{source_str}{pattern_str}")

                # JWT decoded details
                if 'decoded' in item:
                    jwt = item['decoded']
                    for issue in jwt.get('issues', []):
                        lines.append(f"     │        ⚠ {issue}")
                    for data in jwt.get('sensitive_data', []):
                        key = list(data.keys())[0]
                        lines.append(f"     │        🔑 {key}: {data[key]}")
                    if jwt.get('header'):
                        lines.append(f"     │        📋 Header: alg={jwt['header'].get('alg', '?')}, typ={jwt['header'].get('typ', '?')}")

            lines.append(f"     │")
            lines.append(f"     └{'─' * 60}")

    # Footer
    lines.append("")
    lines.append(sep_line)
    lines.append("  🔥 End of Report - Ultimate URL Source Code Analyzer v9.1")
    lines.append("  ⚠️  For authorized security testing only")
    lines.append(sep_line)

    # Write clean TXT
    with open(txt_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f"\n{Colors.GREEN}📁 Results TXT: {Colors.BOLD}{txt_file}{Colors.RESET}")
    print(f"{Colors.CYAN}   → Contains {STATS['total_findings']} findings from {STATS['urls_with_findings']} URLs{Colors.RESET}")

    # Also write a colored version for terminals
    colored_txt_file = f"results_{timestamp}_colored.txt"
    colored_lines = build_colored_txt(lines, URL_FINDINGS, category_totals)
    with open(colored_txt_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(colored_lines))

    print(f"{Colors.GREEN}📁 Colored TXT: {Colors.BOLD}{colored_txt_file}{Colors.RESET}")
    print(f"   {Colors.ARROW}→ View with: cat {colored_txt_file}  (or)  less -R {colored_txt_file}{Colors.RESET}")


def build_colored_txt(clean_lines, url_findings, category_totals):
    """Build a colored version of the report using ANSI codes"""

    c = []
    sep_line = f"{Colors.ORANGE}{'═' * 100}{Colors.RESET}"
    thin_sep = f"{Colors.SEP_COLOR}{'-' * 100}{Colors.RESET}"

    c.append(sep_line)
    c.append(f"  {Colors.RED}{Colors.BOLD}🔥 ULTIMATE URL SOURCE CODE ANALYZER v9.1 - RESULTS REPORT{Colors.RESET}")
    c.append(f"  {Colors.CYAN}📅 Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    duration = (datetime.datetime.now() - STATS['start_time']).total_seconds() if STATS['start_time'] else 0
    c.append(f"  {Colors.CYAN}⏱️  Duration: {duration:.2f} seconds{Colors.RESET}")
    c.append(sep_line)
    c.append("")
    c.append(f"  {Colors.BOLD}{Colors.YELLOW}📊 SCAN STATISTICS:{Colors.RESET}")
    c.append(f"     {Colors.CYAN}• URLs Scanned:{Colors.RESET}         {Colors.COUNT_COLOR}{STATS['urls_scanned']}{Colors.RESET}")
    c.append(f"     {Colors.GREEN}• URLs with Findings:{Colors.RESET}   {Colors.COUNT_COLOR}{STATS['urls_with_findings']}{Colors.RESET}")
    c.append(f"     {Colors.YELLOW}• JS Files Scanned:{Colors.RESET}     {Colors.COUNT_COLOR}{STATS['js_files_scanned']}{Colors.RESET}")
    c.append(f"     {Colors.RED}• Total Findings:{Colors.RESET}       {Colors.COUNT_COLOR}{STATS['total_findings']}{Colors.RESET}")
    c.append("")
    c.append(f"  {Colors.BOLD}{Colors.MAGENTA}📈 CATEGORY TOTALS:{Colors.RESET}")
    c.append(thin_sep)

    for category, count in sorted(category_totals.items(), key=lambda x: -x[1]):
        color = CATEGORY_COLORS.get(category, Colors.WHITE)
        emoji = CATEGORY_EMOJIS.get(category, "🔶")
        c.append(f"     {color}{emoji} {category}: {Colors.COUNT_COLOR}{count}{Colors.RESET}")

    c.append("")
    c.append(sep_line)
    c.append(f"  {Colors.BOLD}{Colors.CYAN}🔗 DETAILED FINDINGS BY URL{Colors.RESET}")
    c.append(sep_line)
    c.append("")

    CATEGORY_ORDER = [
        "Credentials & Secrets", "Private Keys", "JWT Tokens",
        "AWS Resources", "Google/Firebase", "Azure Resources",
        "Database Connections", "Payment Keys", "Git Tokens",
        "Messaging/Webhooks", "Sensitive PII", "Phone Numbers",
        "Emails", "IP Addresses", "API Endpoints", "Subdomains",
        "Interesting URLs", "Interesting Comments", "Other Secrets",
    ]

    url_num = 0
    for url, findings in url_findings.items():
        url_num += 1
        total = sum(len(v) for v in findings.values())

        if url_num > 1:
            c.append("")
            c.append(f"{Colors.ORANGE}{'═' * 100}{Colors.RESET}")
            c.append("")

        c.append(f"  {Colors.BOLD}{Colors.URL_COLOR}🌐 URL #{url_num}: {url}{Colors.RESET}")
        c.append(f"     {Colors.COUNT_COLOR}📊 Total Findings: {total}{Colors.RESET}")
        c.append(thin_sep)

        sorted_cats = sorted(
            findings.items(),
            key=lambda x: CATEGORY_ORDER.index(x[0]) if x[0] in CATEGORY_ORDER else 999
        )

        for category, items in sorted_cats:
            if not items:
                continue

            color = CATEGORY_COLORS.get(category, Colors.WHITE)
            emoji = CATEGORY_EMOJIS.get(category, "🔶")

            c.append("")
            c.append(f"     {color}┌─── {emoji} {category} ({len(items)}) ───{Colors.RESET}")
            c.append(f"     {color}│{Colors.RESET}")

            for idx, item in enumerate(items, 1):
                value = item['value']
                if len(value) > 120:
                    value = value[:120] + "..."

                source_str = ""
                if item.get('source'):
                    source_str = f"  {Colors.ARROW}← [{item['source']}]{Colors.RESET}"

                pattern_str = ""
                if item.get('pattern'):
                    pattern_str = f"  {Colors.SEP_COLOR}({item['pattern']}){Colors.RESET}"

                c.append(f"     {color}│{Colors.RESET}  {Colors.BOLD}[{idx:>3}]{Colors.RESET} {color}{value}{Colors.RESET}{source_str}{pattern_str}")

                if 'decoded' in item:
                    jwt = item['decoded']
                    for issue in jwt.get('issues', []):
                        c.append(f"     {color}│{Colors.RESET}        {Colors.YELLOW}⚠ {issue}{Colors.RESET}")
                    for data in jwt.get('sensitive_data', []):
                        key = list(data.keys())[0]
                        c.append(f"     {color}│{Colors.RESET}        {Colors.GREEN}🔑 {key}: {data[key]}{Colors.RESET}")
                    if jwt.get('header'):
                        c.append(f"     {color}│{Colors.RESET}        {Colors.CYAN}📋 Header: alg={jwt['header'].get('alg', '?')}, typ={jwt['header'].get('typ', '?')}{Colors.RESET}")

            c.append(f"     {color}│{Colors.RESET}")
            c.append(f"     {color}└{'─' * 60}{Colors.RESET}")

    c.append("")
    c.append(sep_line)
    c.append(f"  {Colors.BOLD}{Colors.RED}🔥 End of Report - Ultimate URL Source Code Analyzer v9.1{Colors.RESET}")
    c.append(f"  {Colors.YELLOW}⚠️  For authorized security testing only{Colors.RESET}")
    c.append(sep_line)

    return c


# ==================== MAIN ====================
def main():
    print_banner()

    print(f"{Colors.CYAN}📂 Enter the path to your file containing URLs:{Colors.RESET}")
    print(f"   {Colors.SEP_COLOR}(One URL per line){Colors.RESET}")
    print()

    file_path = input(f"{Colors.GREEN}👉 File path: {Colors.RESET}").strip().strip('"').strip("'")

    if not file_path:
        print(f"{Colors.RED}❌ No file path provided{Colors.RESET}")
        return

    if not os.path.exists(file_path):
        print(f"{Colors.RED}❌ File not found: {file_path}{Colors.RESET}")
        return

    # Options
    print(f"\n{Colors.YELLOW}⚙️ Configuration options:{Colors.RESET}")

    js_option = input(f"{Colors.CYAN}📜 Also scan linked JS files? [Y/n]: {Colors.RESET}").strip().lower()
    Config.FOLLOW_JS = js_option != 'n'

    print(f"\n{Colors.GREEN}✅ Configuration:{Colors.RESET}")
    print(f"   {Colors.CYAN}• File:{Colors.RESET} {file_path}")
    print(f"   {Colors.CYAN}• Scan JS files:{Colors.RESET} {'Yes' if Config.FOLLOW_JS else 'No'}")
    print(f"   {Colors.CYAN}• Decode JWT tokens:{Colors.RESET} Yes")
    print(f"   {Colors.CYAN}• Output:{Colors.RESET} {Colors.BOLD}TXT ONLY{Colors.RESET} (results.txt)")

    print(f"\n{Colors.SEP_COLOR}{'=' * 80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.GREEN}🚀 Starting scan...{Colors.RESET}")
    print(f"{Colors.SEP_COLOR}{'=' * 80}{Colors.RESET}")

    # Scan
    scan_urls_from_file(file_path)

    # Generate TXT report only
    generate_txt_report()

    print(f"\n{Colors.SEP_COLOR}{'=' * 80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.GREEN}✅ SCAN COMPLETE!{Colors.RESET}")
    print(f"{Colors.SEP_COLOR}{'=' * 80}{Colors.RESET}")

    if URL_FINDINGS:
        print(f"\n{Colors.STAR}🎯 Found data in {Colors.COUNT_COLOR}{len(URL_FINDINGS)}{Colors.RESET}{Colors.STAR} URLs!{Colors.RESET}")
        print(f"   {Colors.CYAN}Check the generated TXT files in current directory.{Colors.RESET}")
        print(f"   {Colors.GREEN}• results_***.txt{Colors.RESET}         → Clean text report")
        print(f"   {Colors.GREEN}• results_***_colored.txt{Colors.RESET} → Colored (view with: cat filename.txt)")
    else:
        print(f"\n{Colors.RED}❌ No significant findings.{Colors.RESET}")


if __name__ == "__main__":
    main()
