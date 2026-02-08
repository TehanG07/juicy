#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║          ULTIMATE CORS MISCONFIGURATION SCANNER v3.0         ║
║                                                               ║
║              Covers 30+ CORS Attack Scenarios                ║
║        Multi-threaded | Auto-Report | Smart Detection        ║
║           For Authorized Security Testing Only               ║
╚═══════════════════════════════════════════════════════════════╝

Usage:
  python3 cors_scanner.py -u https://target.com
  python3 cors_scanner.py -l urls.txt -t 20 -o report.txt
  python3 cors_scanner.py -u https://target.com --auth "Bearer token123"
  python3 cors_scanner.py -l urls.txt --cookie "session=abc" --delay 1
  python3 cors_scanner.py -u https://target.com -H "X-Custom: value"
"""

import requests
import sys
import os
import time
import signal
import argparse
import random
import string
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from collections import defaultdict
import urllib3

# ══════════════════════════════════════════
# SSL Warnings Disable (Testing Purpose)
# ══════════════════════════════════════════
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ══════════════════════════════════════════
# Terminal Colors
# ══════════════════════════════════════════
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


# ══════════════════════════════════════════
# Thread-Safe Globals
# ══════════════════════════════════════════
print_lock = threading.Lock()
stats_lock = threading.Lock()


def safe_print(message):
    with print_lock:
        print(message)


def banner():
    print(f"""{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║       CORS MISCONFIGURATION SCANNER v3.0              ║
║       30+ Attack Scenarios | Smart Detection          ║
║       Authorized Security Testing Only                ║
║                                                       ║
╠═══════════════════════════════════════════════════════╣
║  Features:                                            ║
║  • Auto-detect Origin header presence                 ║
║  • Response-header-based vulnerability analysis       ║
║  • 30+ Origin Bypass Techniques                       ║
║  • Preflight Analysis                                 ║
║  • Credential Leak Detection                          ║
║  • Cache Poisoning via CORS                           ║
║  • WebSocket CORS Testing                             ║
║  • Method-based CORS Bypass                           ║
║  • Custom Headers Support                             ║
║  • TXT Report (Vulnerables Only)                      ║
╚═══════════════════════════════════════════════════════╝
{Colors.END}""")


# ══════════════════════════════════════════
# SEVERITY LEVELS
# ══════════════════════════════════════════
class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ══════════════════════════════════════════
# SCAN STATISTICS
# ══════════════════════════════════════════
class ScanStats:
    def __init__(self):
        self.total_urls = 0
        self.total_tests = 0
        self.total_vulns = 0
        self.critical = 0
        self.high = 0
        self.medium = 0
        self.low = 0
        self.info = 0
        self.errors = 0
        self.timeouts = 0
        self.start_time = None
        self.end_time = None

    def add_vuln(self, severity):
        with stats_lock:
            self.total_vulns += 1
            if severity == Severity.CRITICAL:
                self.critical += 1
            elif severity == Severity.HIGH:
                self.high += 1
            elif severity == Severity.MEDIUM:
                self.medium += 1
            elif severity == Severity.LOW:
                self.low += 1
            elif severity == Severity.INFO:
                self.info += 1


# ══════════════════════════════════════════════════════════════
# RESPONSE HEADER ANALYZER
# ══════════════════════════════════════════════════════════════
class ResponseAnalyzer:
    """
    Analyzes CORS response headers and determines
    vulnerability based on ACTUAL header values.
    """

    # Headers we care about
    CORS_HEADERS = [
        'Access-Control-Allow-Origin',
        'Access-Control-Allow-Credentials',
        'Access-Control-Allow-Methods',
        'Access-Control-Allow-Headers',
        'Access-Control-Expose-Headers',
        'Access-Control-Max-Age',
        'Vary',
    ]

    DANGEROUS_METHODS = ['PUT', 'DELETE', 'PATCH']

    SENSITIVE_HEADERS = [
        'authorization', 'cookie', 'set-cookie',
        'x-csrf-token', 'x-auth-token', 'x-api-key',
    ]

    @staticmethod
    def extract_cors_headers(response):
        """Extract all CORS-related headers from response"""
        headers = {}
        for h in ResponseAnalyzer.CORS_HEADERS:
            val = response.headers.get(h, '')
            headers[h] = val
        return headers

    @staticmethod
    def has_any_cors_headers(response):
        """Check if response has ANY CORS headers"""
        for h in ResponseAnalyzer.CORS_HEADERS:
            if response.headers.get(h):
                return True
        return False

    @staticmethod
    def analyze_vulnerability(origin_sent, cors_headers, test_info):
        """
        Core logic: Analyze response headers to determine
        if CORS misconfiguration exists.

        Returns dict with vulnerability details or None
        """
        acao = cors_headers.get('Access-Control-Allow-Origin', '')
        acac = cors_headers.get('Access-Control-Allow-Credentials', '')
        acam = cors_headers.get('Access-Control-Allow-Methods', '')
        acah = cors_headers.get('Access-Control-Allow-Headers', '')
        aceh = cors_headers.get('Access-Control-Expose-Headers', '')
        acma = cors_headers.get('Access-Control-Max-Age', '')
        vary = cors_headers.get('Vary', '')

        vuln_details = {
            'vulnerable': False,
            'vuln_type': '',
            'severity': test_info.get('severity', Severity.INFO),
            'credentials_allowed': False,
            'wildcard': False,
            'vary_origin_missing': False,
            'dangerous_methods': False,
            'dangerous_methods_list': [],
            'sensitive_headers_exposed': False,
            'sensitive_headers_list': [],
            'response_analysis': [],
        }

        # No ACAO header = no CORS = not vulnerable to CORS attacks
        if not acao:
            return None

        is_reflected = False
        is_wildcard = False
        is_null_allowed = False

        # ─── CHECK 1: Origin Reflection ───
        # Server echoes back our evil origin exactly
        if acao == origin_sent and origin_sent not in ('', '*'):
            is_reflected = True
            vuln_details['vuln_type'] = 'Origin Reflected'
            vuln_details['response_analysis'].append(
                f"ACAO header reflects sent origin '{origin_sent}' verbatim"
            )

        # ─── CHECK 2: Wildcard ───
        if acao == '*':
            is_wildcard = True
            vuln_details['wildcard'] = True
            vuln_details['response_analysis'].append(
                "ACAO is wildcard (*) - allows any origin"
            )

        # ─── CHECK 3: Null Origin ───
        if acao.lower() == 'null' and origin_sent.lower() == 'null':
            is_null_allowed = True
            vuln_details['vuln_type'] = 'Null Origin Allowed'
            vuln_details['response_analysis'].append(
                "ACAO allows 'null' origin - exploitable via "
                "sandboxed iframe, data: URI, file: protocol"
            )

        # If none of these match, it's not vulnerable
        if not (is_reflected or is_wildcard or is_null_allowed):
            return None

        # ─── CHECK 4: Credentials ───
        if acac.lower() == 'true':
            vuln_details['credentials_allowed'] = True
            vuln_details['response_analysis'].append(
                "Access-Control-Allow-Credentials: true → "
                "cookies/auth headers sent cross-origin"
            )

            # Wildcard + Credentials = browser blocks BUT
            # it's still a severe misconfiguration indicator
            if is_wildcard:
                vuln_details['severity'] = Severity.CRITICAL
                vuln_details['vuln_type'] = 'Wildcard + Credentials'
                vuln_details['response_analysis'].append(
                    "CRITICAL: Wildcard(*) + Credentials(true) - "
                    "browser blocks this combo but indicates "
                    "severely broken CORS implementation"
                )
            elif is_reflected:
                # Reflection + Credentials = CRITICAL
                vuln_details['severity'] = Severity.CRITICAL
                vuln_details['response_analysis'].append(
                    "CRITICAL: Origin reflected WITH credentials - "
                    "attacker can steal authenticated user data"
                )
            elif is_null_allowed:
                vuln_details['severity'] = Severity.CRITICAL
                vuln_details['response_analysis'].append(
                    "CRITICAL: Null origin + Credentials - "
                    "sandboxed iframe can steal authenticated data"
                )
        else:
            # No credentials but still reflected/wildcard
            if is_reflected:
                vuln_details['response_analysis'].append(
                    "Origin reflected but no credentials flag - "
                    "attacker can read non-authenticated responses"
                )
            if is_wildcard:
                vuln_details['vuln_type'] = 'Wildcard Origin'
                vuln_details['response_analysis'].append(
                    "Wildcard allows any origin to read response "
                    "(without cookies)"
                )

        # ─── CHECK 5: Vary Header ───
        if 'origin' not in vary.lower():
            vuln_details['vary_origin_missing'] = True
            vuln_details['response_analysis'].append(
                "Vary header missing 'Origin' → "
                "response may be cached by CDN/proxy "
                "with attacker's ACAO, poisoning cache for all users"
            )

        # ─── CHECK 6: Dangerous Methods ───
        if acam:
            found_dangerous = []
            for method in ResponseAnalyzer.DANGEROUS_METHODS:
                if method in acam.upper():
                    found_dangerous.append(method)
            if found_dangerous:
                vuln_details['dangerous_methods'] = True
                vuln_details['dangerous_methods_list'] = found_dangerous
                vuln_details['response_analysis'].append(
                    f"Dangerous methods allowed: {', '.join(found_dangerous)} "
                    f"→ attacker can modify/delete data cross-origin"
                )

        # ─── CHECK 7: Sensitive Headers Exposed ───
        if aceh:
            found_sensitive = []
            for sh in ResponseAnalyzer.SENSITIVE_HEADERS:
                if sh in aceh.lower():
                    found_sensitive.append(sh)
            if found_sensitive:
                vuln_details['sensitive_headers_exposed'] = True
                vuln_details['sensitive_headers_list'] = found_sensitive
                vuln_details['response_analysis'].append(
                    f"Sensitive headers exposed: {', '.join(found_sensitive)} "
                    f"→ attacker JS can read these headers cross-origin"
                )

        vuln_details['vulnerable'] = True
        return vuln_details


# ══════════════════════════════════════════════════════════════
# MAIN SCANNER CLASS
# ══════════════════════════════════════════════════════════════
class UltimateCORSScanner:
    def __init__(self, config):
        self.timeout = config.get('timeout', 10)
        self.threads = config.get('threads', 10)
        self.verbose = config.get('verbose', False)
        self.delay = config.get('delay', 0)
        self.auth_header = config.get('auth', None)
        self.cookie = config.get('cookie', None)
        self.proxy = config.get('proxy', None)
        self.follow_redirects = config.get('follow_redirects', True)
        self.max_redirects = config.get('max_redirects', 5)
        self.test_methods = config.get('test_methods', True)
        self.test_websocket = config.get('test_websocket', True)
        self.test_cache = config.get('test_cache', True)
        self.custom_headers = config.get('custom_headers', {})
        self.output_file = config.get('output_file', None)

        self.results = []
        self.stats = ScanStats()
        self.analyzer = ResponseAnalyzer()

        # Session setup
        self.session = requests.Session()
        self.session.verify = False
        self.session.max_redirects = self.max_redirects

        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36',
        ]

        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,'
                      'application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
        })

        if self.auth_header:
            self.session.headers['Authorization'] = self.auth_header
        if self.cookie:
            self.session.headers['Cookie'] = self.cookie
        if self.custom_headers:
            self.session.headers.update(self.custom_headers)
        if self.proxy:
            self.session.proxies = {
                'http': self.proxy,
                'https': self.proxy,
            }

    # ══════════════════════════════════════════
    # Custom Headers Parser
    # ══════════════════════════════════════════
    @staticmethod
    def parse_custom_headers(header_list):
        headers = {}
        if not header_list:
            return headers
        for h in header_list:
            if ':' in h:
                key, value = h.split(':', 1)
                headers[key.strip()] = value.strip()
            else:
                safe_print(
                    f"{Colors.YELLOW}[WARNING] Invalid header "
                    f"format (use 'Name: Value'): {h}{Colors.END}"
                )
        return headers

    # ══════════════════════════════════════════
    # BASELINE REQUEST - Check if Origin exists
    # ══════════════════════════════════════════
    def baseline_check(self, target_url):
        """
        Make a request WITHOUT Origin header to see
        if the server already includes CORS headers.

        Returns:
            dict with:
              - 'has_cors': bool
              - 'cors_headers': dict of CORS headers
              - 'status_code': int
              - 'response': Response object
              - 'baseline_acao': str (ACAO value without Origin)
        """
        try:
            # Remove Origin if somehow present
            headers = dict(self.session.headers)
            headers.pop('Origin', None)

            response = requests.get(
                target_url,
                headers=headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=self.follow_redirects,
                proxies=self.session.proxies if self.proxy else None,
            )

            cors_headers = self.analyzer.extract_cors_headers(response)
            has_cors = self.analyzer.has_any_cors_headers(response)

            return {
                'has_cors': has_cors,
                'cors_headers': cors_headers,
                'status_code': response.status_code,
                'response': response,
                'baseline_acao': cors_headers.get(
                    'Access-Control-Allow-Origin', ''
                ),
            }

        except Exception as e:
            if self.verbose:
                safe_print(
                    f"  {Colors.YELLOW}[BASELINE ERROR] "
                    f"{str(e)}{Colors.END}"
                )
            return None

    # ══════════════════════════════════════════
    # 30+ Evil Origin Generators
    # ══════════════════════════════════════════
    def generate_all_origins(self, target_url):
        parsed = urlparse(target_url)
        target_domain = parsed.hostname or ''
        target_scheme = parsed.scheme or 'https'
        target_port = parsed.port

        domain_parts = target_domain.split('.')
        if len(domain_parts) >= 2:
            base_domain = '.'.join(domain_parts[-2:])
        else:
            base_domain = target_domain

        tld = domain_parts[-1] if domain_parts else 'com'
        domain_name = domain_parts[-2] if len(domain_parts) >= 2 else target_domain

        origins = []

        # ═══ CATEGORY 1: BASIC REFLECTION ═══
        origins.append({
            'origin': 'https://evil.com',
            'test_name': 'Arbitrary Origin Reflection',
            'category': 'Basic Reflection',
            'severity': Severity.CRITICAL,
            'description': (
                'Server reflects ANY arbitrary origin. '
                'Attacker can read responses from any domain.'
            ),
            'impact': (
                'Complete CORS bypass - attacker can steal '
                'user data, tokens, PII from any origin'
            ),
            'remediation': (
                'Implement strict origin whitelist. '
                'Never reflect the Origin header blindly.'
            ),
        })

        origins.append({
            'origin': 'https://attacker-controlled.com',
            'test_name': 'Arbitrary Origin Confirmation',
            'category': 'Basic Reflection',
            'severity': Severity.CRITICAL,
            'description': 'Second confirmation of arbitrary origin reflection',
            'impact': 'Same as arbitrary origin reflection',
            'remediation': 'Implement strict origin whitelist',
        })

        origins.append({
            'origin': 'http://evil.com',
            'test_name': 'HTTP Origin Reflection',
            'category': 'Basic Reflection',
            'severity': Severity.CRITICAL,
            'description': 'Server reflects HTTP origin - no HTTPS required',
            'impact': 'MitM attacker can intercept and steal data',
            'remediation': 'Only allow HTTPS origins in whitelist',
        })

        # ═══ CATEGORY 2: NULL ORIGIN ═══
        origins.append({
            'origin': 'null',
            'test_name': 'Null Origin Allowed',
            'category': 'Null Origin',
            'severity': Severity.HIGH,
            'description': (
                'Server allows null origin. Exploitable via '
                'sandboxed iframes, redirects, and local files'
            ),
            'impact': (
                'Attacker uses sandboxed iframe to send '
                'requests with null origin and steal data'
            ),
            'remediation': 'Never allow null origin',
        })

        origins.append({
            'origin': 'Null',
            'test_name': 'Null Origin Case Variation (Title)',
            'category': 'Null Origin',
            'severity': Severity.HIGH,
            'description': 'Case-insensitive null origin check bypass',
            'impact': 'Same as null origin',
            'remediation': 'Case-insensitive null rejection',
        })

        origins.append({
            'origin': 'NULL',
            'test_name': 'Null Origin Case Variation (Upper)',
            'category': 'Null Origin',
            'severity': Severity.HIGH,
            'description': 'Uppercase NULL origin check bypass',
            'impact': 'Same as null origin',
            'remediation': 'Case-insensitive null rejection',
        })

        # ═══ CATEGORY 3: PREFIX MATCHING BYPASS ═══
        origins.append({
            'origin': f'https://{target_domain}.evil.com',
            'test_name': 'Prefix Match Bypass',
            'category': 'Regex Bypass',
            'severity': Severity.HIGH,
            'description': (
                f'Server uses prefix matching. '
                f'{target_domain}.evil.com accepted'
            ),
            'impact': 'Attacker registers domain containing target name',
            'remediation': 'Use exact match or proper regex with anchors',
        })

        origins.append({
            'origin': f'https://{target_domain}.attacker.com',
            'test_name': 'Prefix Match Bypass (Variant)',
            'category': 'Regex Bypass',
            'severity': Severity.HIGH,
            'description': 'Another prefix matching bypass variant',
            'impact': 'Same as prefix match bypass',
            'remediation': 'Use exact domain matching',
        })

        # ═══ CATEGORY 4: SUFFIX MATCHING BYPASS ═══
        origins.append({
            'origin': f'https://evil-{target_domain}',
            'test_name': 'Suffix Match Bypass (Hyphen)',
            'category': 'Regex Bypass',
            'severity': Severity.HIGH,
            'description': f'Suffix matching: evil-{target_domain}',
            'impact': 'Attacker registers evil-target.com domain',
            'remediation': 'Match exact domain, not suffix/substring',
        })

        origins.append({
            'origin': f'https://evil{target_domain}',
            'test_name': 'Suffix Match Bypass (No Separator)',
            'category': 'Regex Bypass',
            'severity': Severity.HIGH,
            'description': f'No separator suffix: evil{target_domain}',
            'impact': 'Domain registration based bypass',
            'remediation': 'Exact domain matching with dots',
        })

        origins.append({
            'origin': f'https://not{base_domain}',
            'test_name': 'Suffix Match Bypass (Base Domain)',
            'category': 'Regex Bypass',
            'severity': Severity.HIGH,
            'description': f'Base domain suffix: not{base_domain}',
            'impact': 'Domain registration bypass',
            'remediation': 'Strict whitelist matching',
        })

        # ═══ CATEGORY 5: SUBDOMAIN TRUST ═══
        origins.append({
            'origin': f'https://evil.{target_domain}',
            'test_name': 'Subdomain Trust - evil.target',
            'category': 'Subdomain Trust',
            'severity': Severity.MEDIUM,
            'description': (
                f'Server trusts any subdomain of {target_domain}'
            ),
            'impact': 'Subdomain takeover + CORS bypass',
            'remediation': 'Whitelist specific subdomains only',
        })

        origins.append({
            'origin': f'https://test.evil.{target_domain}',
            'test_name': 'Nested Subdomain Trust',
            'category': 'Subdomain Trust',
            'severity': Severity.MEDIUM,
            'description': 'Server trusts deeply nested subdomains',
            'impact': 'Subdomain takeover exploitation',
            'remediation': 'Limit subdomain depth in whitelist',
        })

        origins.append({
            'origin': f'https://evil.{base_domain}',
            'test_name': 'Subdomain Trust - Base Domain',
            'category': 'Subdomain Trust',
            'severity': Severity.MEDIUM,
            'description': f'Trusts subdomains of {base_domain}',
            'impact': 'Subdomain based bypass',
            'remediation': 'Explicit subdomain whitelist',
        })

        random_sub = ''.join(random.choices(string.ascii_lowercase, k=8))
        origins.append({
            'origin': f'https://{random_sub}.{target_domain}',
            'test_name': 'Random Subdomain Trust',
            'category': 'Subdomain Trust',
            'severity': Severity.MEDIUM,
            'description': f'Random subdomain {random_sub}.{target_domain}',
            'impact': 'Wildcard subdomain CORS bypass',
            'remediation': 'No wildcard subdomain in CORS',
        })

        # ═══ CATEGORY 6: PROTOCOL BYPASS ═══
        if target_scheme == 'https':
            origins.append({
                'origin': f'http://{target_domain}',
                'test_name': 'HTTP Origin on HTTPS Site',
                'category': 'Protocol Bypass',
                'severity': Severity.MEDIUM,
                'description': 'HTTPS site accepts HTTP origin',
                'impact': 'Network attacker can downgrade and exploit',
                'remediation': 'Only accept HTTPS origins',
            })

            origins.append({
                'origin': f'http://evil.{target_domain}',
                'test_name': 'HTTP Subdomain on HTTPS',
                'category': 'Protocol Bypass',
                'severity': Severity.MEDIUM,
                'description': 'HTTP subdomain trusted on HTTPS site',
                'impact': 'MitM + subdomain exploitation',
                'remediation': 'HTTPS-only origins',
            })

        # ═══ CATEGORY 7: SPECIAL CHARACTER ═══
        origins.append({
            'origin': f'https://{target_domain}`.evil.com',
            'test_name': 'Backtick Character Bypass',
            'category': 'Special Character',
            'severity': Severity.HIGH,
            'description': 'Backtick confuses URL parsers',
            'impact': 'Parser differential exploitation',
            'remediation': 'Reject origins with special characters',
        })

        origins.append({
            'origin': f'https://{target_domain}%60.evil.com',
            'test_name': 'URL-Encoded Backtick Bypass',
            'category': 'Special Character',
            'severity': Severity.HIGH,
            'description': 'URL-encoded backtick parser bypass',
            'impact': 'Parser differential',
            'remediation': 'Decode and validate origins',
        })

        origins.append({
            'origin': f'https://{target_domain}%00.evil.com',
            'test_name': 'Null Byte Injection',
            'category': 'Special Character',
            'severity': Severity.HIGH,
            'description': 'Null byte truncation bypass',
            'impact': 'String truncation bypass',
            'remediation': 'Reject null bytes in origin',
        })

        origins.append({
            'origin': f'https://{target_domain}%09.evil.com',
            'test_name': 'Tab Character Bypass',
            'category': 'Special Character',
            'severity': Severity.MEDIUM,
            'description': 'Tab character parser confusion',
            'impact': 'Parser bypass',
            'remediation': 'Strip whitespace characters',
        })

        origins.append({
            'origin': f'https://{target_domain}_.evil.com',
            'test_name': 'Underscore Bypass',
            'category': 'Special Character',
            'severity': Severity.MEDIUM,
            'description': 'Underscore in domain parser confusion',
            'impact': 'Some parsers handle underscore differently',
            'remediation': 'Strict domain character validation',
        })

        origins.append({
            'origin': f'https://{target_domain}!.evil.com',
            'test_name': 'Exclamation Mark Bypass',
            'category': 'Special Character',
            'severity': Severity.MEDIUM,
            'description': 'Exclamation ! in origin',
            'impact': 'Parser confusion',
            'remediation': 'Allow only alphanumeric and dots/hyphens',
        })

        origins.append({
            'origin': f'https://{target_domain}|.evil.com',
            'test_name': 'Pipe Character Bypass',
            'category': 'Special Character',
            'severity': Severity.MEDIUM,
            'description': 'Pipe | character in origin',
            'impact': 'Parser confusion',
            'remediation': 'Strict character whitelist',
        })

        origins.append({
            'origin': f'https://{target_domain}{{.evil.com',
            'test_name': 'Curly Brace Bypass',
            'category': 'Special Character',
            'severity': Severity.MEDIUM,
            'description': 'Curly brace { in origin',
            'impact': 'Parser confusion',
            'remediation': 'Strict validation',
        })

        origins.append({
            'origin': f'https://{target_domain}%E2%80%8B.evil.com',
            'test_name': 'Zero Width Space Bypass',
            'category': 'Special Character',
            'severity': Severity.HIGH,
            'description': 'Zero-width space invisible character',
            'impact': 'Visual bypass of origin validation',
            'remediation': 'Strip unicode whitespace characters',
        })

        origins.append({
            'origin': f'https://evil.com%0d%0aX-Injected: header',
            'test_name': 'CRLF Injection in Origin',
            'category': 'Header Injection',
            'severity': Severity.HIGH,
            'description': 'CRLF injection in Origin header',
            'impact': 'HTTP header injection via CORS',
            'remediation': 'Reject origins with CR/LF characters',
        })

        # ═══ CATEGORY 8: PORT BYPASS ═══
        origins.append({
            'origin': f'https://{target_domain}:8080',
            'test_name': 'Different Port Origin',
            'category': 'Port Bypass',
            'severity': Severity.LOW,
            'description': 'Origin with different port accepted',
            'impact': 'Cross-port resource access',
            'remediation': 'Include port in origin validation',
        })

        origins.append({
            'origin': f'https://{target_domain}:1337',
            'test_name': 'Random Port Origin',
            'category': 'Port Bypass',
            'severity': Severity.LOW,
            'description': 'Random port 1337 accepted',
            'impact': 'Any local service can access',
            'remediation': 'Validate exact port',
        })

        if target_scheme == 'https' and not target_port:
            origins.append({
                'origin': f'https://{target_domain}:443',
                'test_name': 'Explicit Default Port',
                'category': 'Port Bypass',
                'severity': Severity.INFO,
                'description': 'Explicit port 443 on HTTPS',
                'impact': 'Inconsistent origin matching',
                'remediation': 'Normalize ports in validation',
            })

        # ═══ CATEGORY 9: PATH TRICKS ═══
        origins.append({
            'origin': f'https://evil.com/{target_domain}',
            'test_name': 'Origin with Path Containing Target',
            'category': 'Path Tricks',
            'severity': Severity.MEDIUM,
            'description': 'Target domain in path of evil origin',
            'impact': 'Regex bypass via path injection',
            'remediation': 'Parse origin properly, check host only',
        })

        origins.append({
            'origin': f'https://{target_domain}@evil.com',
            'test_name': 'Userinfo @ Bypass',
            'category': 'Path Tricks',
            'severity': Severity.HIGH,
            'description': (
                f'Using @ sign: {target_domain}@evil.com'
            ),
            'impact': 'URL parser confusion',
            'remediation': 'Reject origins containing @ symbol',
        })

        origins.append({
            'origin': f'https://evil.com#{target_domain}',
            'test_name': 'Fragment Origin Bypass',
            'category': 'Path Tricks',
            'severity': Severity.MEDIUM,
            'description': 'Origin with fragment containing target',
            'impact': 'Regex bypass via fragment',
            'remediation': 'Strip fragments before validation',
        })

        # ═══ CATEGORY 10: DOMAIN CONFUSION ═══
        origins.append({
            'origin': f'https://{domain_name}.evil.{tld}',
            'test_name': 'Domain Confusion - Same Name',
            'category': 'Domain Confusion',
            'severity': Severity.MEDIUM,
            'description': f'Domain {domain_name}.evil.{tld} confusion',
            'impact': 'Substring matching bypass',
            'remediation': 'Full domain comparison',
        })

        origins.append({
            'origin': f'https://evil.com..{target_domain}',
            'test_name': 'Double Dot Bypass',
            'category': 'Domain Confusion',
            'severity': Severity.MEDIUM,
            'description': 'Double dot (..) in domain',
            'impact': 'Parser confusion',
            'remediation': 'Reject domains with consecutive dots',
        })

        # ═══ CATEGORY 11: INTERNAL ORIGINS ═══
        origins.append({
            'origin': 'http://localhost',
            'test_name': 'Localhost Origin',
            'category': 'Internal Origins',
            'severity': Severity.MEDIUM,
            'description': 'Localhost origin accepted',
            'impact': 'Local application exploitation',
            'remediation': 'Remove localhost from allowed origins',
        })

        origins.append({
            'origin': 'http://127.0.0.1',
            'test_name': '127.0.0.1 Origin',
            'category': 'Internal Origins',
            'severity': Severity.MEDIUM,
            'description': 'IP-based localhost origin accepted',
            'impact': 'Local exploitation',
            'remediation': 'Remove IP-based origins',
        })

        origins.append({
            'origin': 'http://192.168.1.1',
            'test_name': 'Internal IP Origin (192.168.x.x)',
            'category': 'Internal Origins',
            'severity': Severity.LOW,
            'description': 'Internal network IP origin accepted',
            'impact': 'Internal network exploitation',
            'remediation': 'No internal IPs in CORS',
        })

        origins.append({
            'origin': 'http://10.0.0.1',
            'test_name': 'Internal IP Origin (10.x.x.x)',
            'category': 'Internal Origins',
            'severity': Severity.LOW,
            'description': 'Private IP range origin accepted',
            'impact': 'Internal network access',
            'remediation': 'Block private IP origins',
        })

        origins.append({
            'origin': 'file://',
            'test_name': 'File Protocol Origin',
            'category': 'Internal Origins',
            'severity': Severity.MEDIUM,
            'description': 'file:// protocol origin accepted',
            'impact': 'Malicious local HTML can steal data',
            'remediation': 'Reject file:// origins',
        })

        # ═══ CATEGORY 12: ADVANCED ═══
        long_sub = 'a' * 200
        origins.append({
            'origin': f'https://{long_sub}.evil.com',
            'test_name': 'Very Long Origin (Buffer Test)',
            'category': 'Advanced',
            'severity': Severity.LOW,
            'description': 'Very long origin string for buffer test',
            'impact': 'Buffer-based bypass',
            'remediation': 'Limit origin length',
        })

        origins.append({
            'origin': '',
            'test_name': 'Empty Origin Header',
            'category': 'Advanced',
            'severity': Severity.LOW,
            'description': 'Empty string as origin',
            'impact': 'Edge case handling',
            'remediation': 'Reject empty origins',
        })

        origins.append({
            'origin': f'https://evil.com {target_domain}',
            'test_name': 'Space in Origin',
            'category': 'Advanced',
            'severity': Severity.MEDIUM,
            'description': 'Space-separated origin to confuse parsers',
            'impact': 'Parser confusion',
            'remediation': 'Reject origins with spaces',
        })

        origins.append({
            'origin': f'https://evil.com, https://{target_domain}',
            'test_name': 'Multiple Origins (Comma)',
            'category': 'Advanced',
            'severity': Severity.MEDIUM,
            'description': 'Comma-separated origins bypass',
            'impact': 'Multi-value header parsing bypass',
            'remediation': 'Parse origin as single value',
        })

        origins.append({
            'origin': 'data:text/html,<h1>test</h1>',
            'test_name': 'Data Protocol Origin',
            'category': 'Advanced',
            'severity': Severity.MEDIUM,
            'description': 'data: protocol origin',
            'impact': 'Protocol-based bypass',
            'remediation': 'Only allow http/https protocols',
        })

        origins.append({
            'origin': 'javascript://evil.com',
            'test_name': 'JavaScript Protocol Origin',
            'category': 'Advanced',
            'severity': Severity.MEDIUM,
            'description': 'javascript: protocol in origin',
            'impact': 'Protocol confusion',
            'remediation': 'Strict protocol whitelist',
        })

        return origins

    # ══════════════════════════════════════════
    # CORE: Test Single Origin with Smart Analysis
    # ══════════════════════════════════════════
    def test_single_origin(self, target_url, origin_data, baseline_info):
        """
        Smart testing logic:
        1. If baseline has NO CORS headers → Add Origin, check if CORS appears
        2. If baseline HAS CORS headers → Test with evil origin, analyze response
        3. Analyze based on ACTUAL response headers
        """
        origin = origin_data['origin']

        try:
            headers = {'Origin': origin}

            response = self.session.get(
                target_url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
            )

            cors_headers = self.analyzer.extract_cors_headers(response)
            has_cors_now = self.analyzer.has_any_cors_headers(response)

            # Build result
            result = {
                'url': target_url,
                'test_name': origin_data['test_name'],
                'category': origin_data['category'],
                'origin_sent': origin,
                'acao_header': cors_headers.get(
                    'Access-Control-Allow-Origin', ''
                ),
                'acac_header': cors_headers.get(
                    'Access-Control-Allow-Credentials', ''
                ),
                'acam_header': cors_headers.get(
                    'Access-Control-Allow-Methods', ''
                ),
                'acah_header': cors_headers.get(
                    'Access-Control-Allow-Headers', ''
                ),
                'acma_header': cors_headers.get(
                    'Access-Control-Max-Age', ''
                ),
                'aceh_header': cors_headers.get(
                    'Access-Control-Expose-Headers', ''
                ),
                'vary_header': cors_headers.get('Vary', ''),
                'severity': origin_data['severity'],
                'description': origin_data['description'],
                'impact': origin_data.get('impact', ''),
                'remediation': origin_data.get('remediation', ''),
                'vulnerable': False,
                'vuln_type': '',
                'status_code': response.status_code,
                'credentials_allowed': False,
                'wildcard': False,
                'vary_origin_missing': False,
                'dangerous_methods': False,
                'dangerous_methods_list': [],
                'sensitive_headers_exposed': False,
                'sensitive_headers_list': [],
                'response_analysis': [],
                'timestamp': datetime.now().isoformat(),
                'response_size': len(response.content),
                'all_cors_headers': cors_headers,
                'baseline_had_cors': baseline_info.get('has_cors', False),
                'origin_triggered_cors': False,
            }

            # ─── SMART DETECTION LOGIC ───

            # Case A: Baseline had NO CORS → Our Origin triggered CORS headers
            if not baseline_info.get('has_cors', False) and has_cors_now:
                result['origin_triggered_cors'] = True
                result['response_analysis'].append(
                    "⚡ No CORS headers in baseline (no Origin), "
                    "but CORS headers appeared after adding Origin header. "
                    "Server is dynamically generating CORS based on Origin."
                )

            # Case B: Baseline had CORS → Compare
            if baseline_info.get('has_cors', False):
                baseline_acao = baseline_info.get('baseline_acao', '')
                current_acao = cors_headers.get(
                    'Access-Control-Allow-Origin', ''
                )
                if baseline_acao != current_acao:
                    result['response_analysis'].append(
                        f"ACAO changed from baseline '{baseline_acao}' "
                        f"to '{current_acao}' after sending Origin: {origin}"
                    )

            # ─── Run vulnerability analysis on response headers ───
            vuln_details = self.analyzer.analyze_vulnerability(
                origin, cors_headers, origin_data
            )

            if vuln_details and vuln_details['vulnerable']:
                result['vulnerable'] = True
                result['vuln_type'] = vuln_details['vuln_type']
                result['severity'] = vuln_details['severity']
                result['credentials_allowed'] = vuln_details['credentials_allowed']
                result['wildcard'] = vuln_details['wildcard']
                result['vary_origin_missing'] = vuln_details['vary_origin_missing']
                result['dangerous_methods'] = vuln_details['dangerous_methods']
                result['dangerous_methods_list'] = vuln_details['dangerous_methods_list']
                result['sensitive_headers_exposed'] = vuln_details['sensitive_headers_exposed']
                result['sensitive_headers_list'] = vuln_details['sensitive_headers_list']
                result['response_analysis'].extend(
                    vuln_details['response_analysis']
                )

            return result

        except requests.exceptions.ConnectTimeout:
            with stats_lock:
                self.stats.timeouts += 1
            return None
        except requests.exceptions.ConnectionError:
            with stats_lock:
                self.stats.errors += 1
            return None
        except requests.exceptions.TooManyRedirects:
            with stats_lock:
                self.stats.errors += 1
            return None
        except Exception as e:
            with stats_lock:
                self.stats.errors += 1
            if self.verbose:
                safe_print(
                    f"  {Colors.YELLOW}[ERROR] {target_url}: "
                    f"{str(e)}{Colors.END}"
                )
            return None

    # ══════════════════════════════════════════
    # PREFLIGHT (OPTIONS) TESTING
    # ══════════════════════════════════════════
    def test_preflight(self, target_url):
        results = []

        preflight_tests = [
            {'method': 'PUT', 'headers': 'X-Custom-Header',
             'name': 'PUT Method Preflight'},
            {'method': 'DELETE', 'headers': 'X-Custom-Header',
             'name': 'DELETE Method Preflight'},
            {'method': 'PATCH', 'headers': 'Content-Type',
             'name': 'PATCH Method Preflight'},
            {'method': 'GET', 'headers': 'Authorization',
             'name': 'Authorization Header Preflight'},
            {'method': 'POST', 'headers': 'X-CSRF-Token, Content-Type',
             'name': 'CSRF Token Preflight'},
        ]

        evil_origins = ['https://evil.com', 'null']

        for test in preflight_tests:
            for evil_origin in evil_origins:
                try:
                    headers = {
                        'Origin': evil_origin,
                        'Access-Control-Request-Method': test['method'],
                        'Access-Control-Request-Headers': test['headers'],
                    }

                    response = self.session.options(
                        target_url,
                        headers=headers,
                        timeout=self.timeout,
                    )

                    cors_headers = self.analyzer.extract_cors_headers(response)
                    acao = cors_headers.get('Access-Control-Allow-Origin', '')
                    acam = cors_headers.get('Access-Control-Allow-Methods', '')
                    acah = cors_headers.get('Access-Control-Allow-Headers', '')
                    acac = cors_headers.get('Access-Control-Allow-Credentials', '')

                    # Analyze
                    is_vuln = False
                    analysis = []

                    if acao == evil_origin or acao == '*':
                        is_vuln = True
                        analysis.append(
                            f"Preflight ACAO: '{acao}' matches/wildcards for "
                            f"evil origin '{evil_origin}'"
                        )
                    if acao.lower() == 'null' and evil_origin == 'null':
                        is_vuln = True
                        analysis.append(
                            "Preflight allows null origin"
                        )

                    if acam:
                        analysis.append(f"Allowed Methods: {acam}")
                    if acah:
                        analysis.append(f"Allowed Headers: {acah}")
                    if acac.lower() == 'true':
                        analysis.append(
                            "Credentials allowed in preflight!"
                        )

                    if is_vuln:
                        severity = Severity.CRITICAL if acac.lower() == 'true' \
                            else Severity.HIGH

                        result = {
                            'url': target_url,
                            'test_name': (
                                f'Preflight: {test["name"]} ({evil_origin})'
                            ),
                            'category': 'Preflight Bypass',
                            'origin_sent': evil_origin,
                            'acao_header': acao,
                            'acac_header': acac,
                            'acam_header': acam,
                            'acah_header': acah,
                            'acma_header': '',
                            'aceh_header': '',
                            'vary_header': '',
                            'severity': severity,
                            'description': (
                                f'Preflight for {test["method"]} '
                                f'with {test["headers"]} allows evil origin'
                            ),
                            'impact': (
                                f'Attacker can make {test["method"]} '
                                f'requests cross-origin'
                            ),
                            'remediation': (
                                'Restrict preflight to whitelisted origins'
                            ),
                            'vulnerable': True,
                            'vuln_type': 'Preflight Bypass',
                            'status_code': response.status_code,
                            'credentials_allowed': acac.lower() == 'true',
                            'wildcard': acao == '*',
                            'vary_origin_missing': False,
                            'dangerous_methods': True,
                            'dangerous_methods_list': [test['method']],
                            'sensitive_headers_exposed': False,
                            'sensitive_headers_list': [],
                            'response_analysis': analysis,
                            'timestamp': datetime.now().isoformat(),
                            'response_size': len(response.content),
                            'all_cors_headers': cors_headers,
                            'baseline_had_cors': False,
                            'origin_triggered_cors': True,
                        }
                        results.append(result)

                except Exception:
                    pass

        return results

    # ══════════════════════════════════════════
    # HTTP METHOD VARIATION TESTING
    # ══════════════════════════════════════════
    def test_method_variations(self, target_url):
        results = []
        methods_to_test = ['POST', 'PUT', 'PATCH', 'DELETE', 'HEAD']

        for method in methods_to_test:
            try:
                headers = {'Origin': 'https://evil.com'}

                response = self.session.request(
                    method, target_url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects,
                )

                cors_headers = self.analyzer.extract_cors_headers(response)
                acao = cors_headers.get('Access-Control-Allow-Origin', '')
                acac = cors_headers.get('Access-Control-Allow-Credentials', '')

                analysis = []
                is_vuln = False

                if acao == 'https://evil.com':
                    is_vuln = True
                    analysis.append(
                        f"ACAO reflects evil origin for {method} method"
                    )
                elif acao == '*' and acac.lower() == 'true':
                    is_vuln = True
                    analysis.append(
                        f"Wildcard + Credentials on {method} method"
                    )

                if acac.lower() == 'true':
                    analysis.append("Credentials allowed")

                if is_vuln:
                    result = {
                        'url': target_url,
                        'test_name': f'Method Variation: {method}',
                        'category': 'Method Bypass',
                        'origin_sent': 'https://evil.com',
                        'acao_header': acao,
                        'acac_header': acac,
                        'acam_header': '',
                        'acah_header': '',
                        'acma_header': '',
                        'aceh_header': '',
                        'vary_header': cors_headers.get('Vary', ''),
                        'severity': Severity.HIGH,
                        'description': (
                            f'{method} method allows evil origin'
                        ),
                        'impact': f'Cross-origin {method} requests possible',
                        'remediation': 'Apply CORS policy to all HTTP methods',
                        'vulnerable': True,
                        'vuln_type': 'Method-specific CORS Bypass',
                        'status_code': response.status_code,
                        'credentials_allowed': acac.lower() == 'true',
                        'wildcard': acao == '*',
                        'vary_origin_missing': 'origin' not in
                            cors_headers.get('Vary', '').lower(),
                        'dangerous_methods': True,
                        'dangerous_methods_list': [method],
                        'sensitive_headers_exposed': False,
                        'sensitive_headers_list': [],
                        'response_analysis': analysis,
                        'timestamp': datetime.now().isoformat(),
                        'response_size': len(response.content),
                        'all_cors_headers': cors_headers,
                        'baseline_had_cors': False,
                        'origin_triggered_cors': True,
                    }
                    results.append(result)

            except Exception:
                pass

        return results

    # ══════════════════════════════════════════
    # CACHE POISONING VIA CORS
    # ══════════════════════════════════════════
    def test_cache_poisoning(self, target_url):
        results = []
        try:
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(
                target_url, headers=headers, timeout=self.timeout,
            )

            cors_headers = self.analyzer.extract_cors_headers(response)
            acao = cors_headers.get('Access-Control-Allow-Origin', '')
            vary = cors_headers.get('Vary', '')
            cache_control = response.headers.get('Cache-Control', '')

            analysis = []

            is_cacheable = True
            no_cache_indicators = [
                'no-store', 'no-cache', 'private', 'max-age=0'
            ]
            for indicator in no_cache_indicators:
                if indicator in cache_control.lower():
                    is_cacheable = False
                    break

            if acao == 'https://evil.com':
                analysis.append(f"ACAO reflects evil origin: {acao}")

                if 'origin' not in vary.lower():
                    analysis.append(
                        f"Vary header is '{vary}' - missing 'Origin'"
                    )
                else:
                    analysis.append(
                        "Vary header includes Origin (good)"
                    )

                if is_cacheable:
                    analysis.append(
                        f"Cache-Control: '{cache_control}' - response IS cacheable"
                    )
                else:
                    analysis.append(
                        f"Cache-Control: '{cache_control}' - response NOT cacheable"
                    )

                if 'origin' not in vary.lower() and is_cacheable:
                    result = {
                        'url': target_url,
                        'test_name': 'CORS Cache Poisoning',
                        'category': 'Cache Poisoning',
                        'origin_sent': 'https://evil.com',
                        'acao_header': acao,
                        'acac_header': cors_headers.get(
                            'Access-Control-Allow-Credentials', ''
                        ),
                        'acam_header': '',
                        'acah_header': '',
                        'acma_header': '',
                        'aceh_header': '',
                        'vary_header': vary,
                        'severity': Severity.HIGH,
                        'description': (
                            'CORS response is cacheable but missing '
                            'Vary: Origin header'
                        ),
                        'impact': (
                            'CDN/proxy cache stores response with '
                            'evil ACAO → all users get poisoned'
                        ),
                        'remediation': (
                            'Add Vary: Origin header OR set '
                            'Cache-Control: no-store'
                        ),
                        'vulnerable': True,
                        'vuln_type': 'Cache Poisoning',
                        'status_code': response.status_code,
                        'credentials_allowed': False,
                        'wildcard': False,
                        'vary_origin_missing': True,
                        'dangerous_methods': False,
                        'dangerous_methods_list': [],
                        'sensitive_headers_exposed': False,
                        'sensitive_headers_list': [],
                        'response_analysis': analysis,
                        'timestamp': datetime.now().isoformat(),
                        'response_size': len(response.content),
                        'all_cors_headers': cors_headers,
                        'baseline_had_cors': False,
                        'origin_triggered_cors': True,
                        'cache_control': cache_control,
                    }
                    results.append(result)

        except Exception:
            pass

        return results

    # ══════════════════════════════════════════
    # WEBSOCKET CORS CHECK
    # ══════════════════════════════════════════
    def test_websocket_cors(self, target_url):
        results = []
        parsed = urlparse(target_url)

        ws_paths = [
            parsed.path or '/',
            '/ws',
            '/websocket',
            '/socket.io/',
        ]

        for path in ws_paths:
            try:
                http_url = f"{parsed.scheme}://{parsed.netloc}{path}"

                headers = {
                    'Origin': 'https://evil.com',
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': '13',
                }

                response = self.session.get(
                    http_url, headers=headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                )

                cors_headers = self.analyzer.extract_cors_headers(response)
                acao = cors_headers.get('Access-Control-Allow-Origin', '')

                analysis = []
                analysis.append(f"Status Code: {response.status_code}")
                analysis.append(f"ACAO: '{acao}'")

                if response.status_code in (101, 200):
                    if acao == 'https://evil.com' or acao == '*':
                        analysis.append(
                            "WebSocket handshake accepts evil origin!"
                        )

                        result = {
                            'url': http_url,
                            'test_name': f'WebSocket CORS Bypass ({path})',
                            'category': 'WebSocket',
                            'origin_sent': 'https://evil.com',
                            'acao_header': acao,
                            'acac_header': '',
                            'acam_header': '',
                            'acah_header': '',
                            'acma_header': '',
                            'aceh_header': '',
                            'vary_header': '',
                            'severity': Severity.HIGH,
                            'description': (
                                'WebSocket endpoint allows cross-origin'
                            ),
                            'impact': (
                                'Attacker can establish WebSocket and '
                                'steal real-time data'
                            ),
                            'remediation': (
                                'Validate Origin in WebSocket handshake'
                            ),
                            'vulnerable': True,
                            'vuln_type': 'WebSocket CORS',
                            'status_code': response.status_code,
                            'credentials_allowed': False,
                            'wildcard': acao == '*',
                            'vary_origin_missing': False,
                            'dangerous_methods': False,
                            'dangerous_methods_list': [],
                            'sensitive_headers_exposed': False,
                            'sensitive_headers_list': [],
                            'response_analysis': analysis,
                            'timestamp': datetime.now().isoformat(),
                            'response_size': len(response.content),
                            'all_cors_headers': cors_headers,
                            'baseline_had_cors': False,
                            'origin_triggered_cors': True,
                        }
                        results.append(result)

            except Exception:
                pass

        return results

    # ══════════════════════════════════════════
    # CONTENT TYPE VARIATION TEST
    # ══════════════════════════════════════════
    def test_content_type_bypass(self, target_url):
        results = []

        content_types = [
            'text/plain',
            'application/x-www-form-urlencoded',
            'multipart/form-data',
            'application/json',
            'application/xml',
            'text/xml',
        ]

        for ct in content_types:
            try:
                headers = {
                    'Origin': 'https://evil.com',
                    'Content-Type': ct,
                }

                response = self.session.post(
                    target_url, headers=headers,
                    data='test=1', timeout=self.timeout,
                )

                cors_headers = self.analyzer.extract_cors_headers(response)
                acao = cors_headers.get('Access-Control-Allow-Origin', '')
                acac = cors_headers.get('Access-Control-Allow-Credentials', '')

                analysis = []
                analysis.append(f"Content-Type sent: {ct}")
                analysis.append(f"ACAO received: '{acao}'")

                if acao == 'https://evil.com':
                    analysis.append(
                        f"Evil origin reflected for POST with CT: {ct}"
                    )
                    if acac.lower() == 'true':
                        analysis.append("Credentials allowed!")

                    # Simple requests (text/plain, form-urlencoded,
                    # multipart/form-data) skip preflight
                    simple_types = [
                        'text/plain',
                        'application/x-www-form-urlencoded',
                        'multipart/form-data',
                    ]
                    if ct in simple_types:
                        analysis.append(
                            f"⚡ '{ct}' is a simple request type - "
                            f"NO preflight required! Browser sends "
                            f"directly."
                        )

                    result = {
                        'url': target_url,
                        'test_name': f'Content-Type Bypass: {ct}',
                        'category': 'Content-Type Bypass',
                        'origin_sent': 'https://evil.com',
                        'acao_header': acao,
                        'acac_header': acac,
                        'acam_header': '',
                        'acah_header': '',
                        'acma_header': '',
                        'aceh_header': '',
                        'vary_header': cors_headers.get('Vary', ''),
                        'severity': Severity.HIGH,
                        'description': (
                            f'POST with Content-Type: {ct} allows evil origin'
                        ),
                        'impact': 'Cross-origin POST without preflight',
                        'remediation': 'Apply CORS to all content types',
                        'vulnerable': True,
                        'vuln_type': 'Content-Type CORS Bypass',
                        'status_code': response.status_code,
                        'credentials_allowed': acac.lower() == 'true',
                        'wildcard': False,
                        'vary_origin_missing': False,
                        'dangerous_methods': False,
                        'dangerous_methods_list': [],
                        'sensitive_headers_exposed': False,
                        'sensitive_headers_list': [],
                        'response_analysis': analysis,
                        'timestamp': datetime.now().isoformat(),
                        'response_size': len(response.content),
                        'all_cors_headers': cors_headers,
                        'baseline_had_cors': False,
                        'origin_triggered_cors': True,
                    }
                    results.append(result)

            except Exception:
                pass

        return results

    # ══════════════════════════════════════════
    # MAIN SCAN FUNCTION FOR SINGLE URL
    # ══════════════════════════════════════════
    def scan_url(self, target_url):
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        target_url = target_url.rstrip('/')

        safe_print(
            f"\n{Colors.BLUE}{Colors.BOLD}"
            f"{'═' * 60}{Colors.END}"
        )
        safe_print(
            f"{Colors.BLUE}[*] Scanning: {target_url}{Colors.END}"
        )
        safe_print(
            f"{Colors.BLUE}{'═' * 60}{Colors.END}"
        )

        url_results = []
        found_vuln = False

        # ─── Phase 0: Connectivity + Baseline Check ───
        safe_print(
            f"\n  {Colors.CYAN}[Phase 0] "
            f"Connectivity & Baseline Check...{Colors.END}"
        )

        baseline_info = self.baseline_check(target_url)

        if baseline_info is None:
            safe_print(
                f"  {Colors.RED}[✗] Target unreachable{Colors.END}"
            )
            return url_results

        safe_print(
            f"  {Colors.GREEN}[✓] Target alive "
            f"(Status: {baseline_info['status_code']}){Colors.END}"
        )

        if baseline_info['has_cors']:
            safe_print(
                f"  {Colors.YELLOW}[!] Baseline has CORS headers "
                f"(without Origin){Colors.END}"
            )
            safe_print(
                f"  {Colors.WHITE}    └── ACAO: "
                f"'{baseline_info['baseline_acao']}'{Colors.END}"
            )
            for h, v in baseline_info['cors_headers'].items():
                if v and h != 'Access-Control-Allow-Origin':
                    safe_print(
                        f"  {Colors.WHITE}    └── {h}: "
                        f"'{v}'{Colors.END}"
                    )
        else:
            safe_print(
                f"  {Colors.GREEN}[i] No CORS headers in baseline "
                f"(will add Origin and test){Colors.END}"
            )

        # ─── Phase 1: Origin Reflection Tests ───
        evil_origins = self.generate_all_origins(target_url)

        safe_print(
            f"\n  {Colors.CYAN}[Phase 1/6] "
            f"Origin Reflection Tests ({len(evil_origins)} tests)..."
            f"{Colors.END}"
        )

        for origin_data in evil_origins:
            if self.delay > 0:
                time.sleep(self.delay)

            with stats_lock:
                self.stats.total_tests += 1

            result = self.test_single_origin(
                target_url, origin_data, baseline_info
            )

            if result and result['vulnerable']:
                found_vuln = True
                url_results.append(result)
                self.print_vulnerability(result)
                self.stats.add_vuln(result['severity'])
            elif result and self.verbose:
                safe_print(
                    f"    {Colors.GREEN}[SAFE] "
                    f"{origin_data['test_name']}{Colors.END}"
                )

        # ─── Phase 2: Preflight Tests ───
        safe_print(
            f"\n  {Colors.CYAN}[Phase 2/6] "
            f"Preflight (OPTIONS) Tests...{Colors.END}"
        )

        preflight_results = self.test_preflight(target_url)
        for result in preflight_results:
            found_vuln = True
            url_results.append(result)
            self.print_vulnerability(result)
            self.stats.add_vuln(result['severity'])

        # ─── Phase 3: Method Variation Tests ───
        if self.test_methods:
            safe_print(
                f"\n  {Colors.CYAN}[Phase 3/6] "
                f"HTTP Method Variation Tests...{Colors.END}"
            )
            method_results = self.test_method_variations(target_url)
            for result in method_results:
                found_vuln = True
                url_results.append(result)
                self.print_vulnerability(result)
                self.stats.add_vuln(result['severity'])

        # ─── Phase 4: Cache Poisoning Tests ───
        if self.test_cache:
            safe_print(
                f"\n  {Colors.CYAN}[Phase 4/6] "
                f"Cache Poisoning Tests...{Colors.END}"
            )
            cache_results = self.test_cache_poisoning(target_url)
            for result in cache_results:
                found_vuln = True
                url_results.append(result)
                self.print_vulnerability(result)
                self.stats.add_vuln(result['severity'])

        # ─── Phase 5: WebSocket Tests ───
        if self.test_websocket:
            safe_print(
                f"\n  {Colors.CYAN}[Phase 5/6] "
                f"WebSocket CORS Tests...{Colors.END}"
            )
            ws_results = self.test_websocket_cors(target_url)
            for result in ws_results:
                found_vuln = True
                url_results.append(result)
                self.print_vulnerability(result)
                self.stats.add_vuln(result['severity'])

        # ─── Phase 6: Content-Type Tests ───
        safe_print(
            f"\n  {Colors.CYAN}[Phase 6/6] "
            f"Content-Type Bypass Tests...{Colors.END}"
        )
        ct_results = self.test_content_type_bypass(target_url)
        for result in ct_results:
            found_vuln = True
            url_results.append(result)
            self.print_vulnerability(result)
            self.stats.add_vuln(result['severity'])

        # ─── URL Summary ───
        if not found_vuln:
            safe_print(
                f"\n  {Colors.GREEN}{Colors.BOLD}"
                f"[✓] No CORS misconfiguration found{Colors.END}"
            )
        else:
            safe_print(
                f"\n  {Colors.RED}{Colors.BOLD}"
                f"[!] {len(url_results)} vulnerabilities "
                f"found!{Colors.END}"
            )

        self.results.extend(url_results)
        return url_results

    # ══════════════════════════════════════════
    # BULK SCANNING FROM FILE
    # ══════════════════════════════════════════
    def scan_from_file(self, filepath):
        if not os.path.exists(filepath):
            safe_print(
                f"{Colors.RED}[ERROR] File not found: "
                f"{filepath}{Colors.END}"
            )
            sys.exit(1)

        with open(filepath, 'r') as f:
            urls = [
                line.strip() for line in f
                if line.strip() and not line.startswith('#')
            ]

        seen = set()
        unique_urls = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        urls = unique_urls

        self.stats.total_urls = len(urls)

        safe_print(f"{Colors.CYAN}[*] Loaded {len(urls)} unique URLs{Colors.END}")
        safe_print(f"{Colors.CYAN}[*] Using {self.threads} threads{Colors.END}")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {
                executor.submit(self.scan_url, url): url
                for url in urls
            }

            completed = 0
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                completed += 1
                try:
                    future.result()
                except Exception as e:
                    safe_print(
                        f"{Colors.RED}[ERROR] {url}: "
                        f"{str(e)}{Colors.END}"
                    )

                if completed % 5 == 0:
                    safe_print(
                        f"\n{Colors.CYAN}[Progress] "
                        f"{completed}/{len(urls)} URLs "
                        f"scanned{Colors.END}"
                    )

    # ══════════════════════════════════════════
    # VULNERABILITY PRINTER (Terminal)
    # ══════════════════════════════════════════
    def print_vulnerability(self, result):
        severity = result['severity']

        color_map = {
            Severity.CRITICAL: Colors.RED + Colors.BOLD,
            Severity.HIGH: Colors.RED,
            Severity.MEDIUM: Colors.YELLOW,
            Severity.LOW: Colors.CYAN,
            Severity.INFO: Colors.WHITE,
        }
        icon_map = {
            Severity.CRITICAL: '🔴',
            Severity.HIGH: '🟠',
            Severity.MEDIUM: '🟡',
            Severity.LOW: '🔵',
            Severity.INFO: '⚪',
        }

        color = color_map.get(severity, Colors.WHITE)
        icon = icon_map.get(severity, '⚪')

        safe_print(
            f"\n    {color}{icon} [{severity}] "
            f"{result['test_name']}{Colors.END}"
        )
        safe_print(
            f"    {Colors.WHITE}├── Category: "
            f"{result['category']}{Colors.END}"
        )
        safe_print(
            f"    {Colors.WHITE}├── URL: "
            f"{result['url']}{Colors.END}"
        )
        safe_print(
            f"    {Colors.WHITE}├── Origin Sent: "
            f"{result['origin_sent']}{Colors.END}"
        )

        # ─── Show ALL response CORS headers ───
        safe_print(
            f"    {Colors.WHITE}├── Response Headers:{Colors.END}"
        )

        cors_h = result.get('all_cors_headers', {})
        if cors_h:
            for h, v in cors_h.items():
                if v:
                    indicator = ''
                    if h == 'Access-Control-Allow-Origin':
                        if v == result.get('origin_sent', ''):
                            indicator = f' {Colors.RED}← REFLECTED!{Colors.END}'
                        elif v == '*':
                            indicator = f' {Colors.RED}← WILDCARD!{Colors.END}'
                        elif v.lower() == 'null':
                            indicator = f' {Colors.RED}← NULL!{Colors.END}'
                    elif h == 'Access-Control-Allow-Credentials':
                        if v.lower() == 'true':
                            indicator = f' {Colors.RED}← DANGEROUS!{Colors.END}'
                    elif h == 'Vary':
                        if 'origin' not in v.lower():
                            indicator = f' {Colors.YELLOW}← Missing Origin!{Colors.END}'

                    safe_print(
                        f"    {Colors.WHITE}│   ├── {h}: "
                        f"{v}{indicator}{Colors.END}"
                    )
        else:
            safe_print(
                f"    {Colors.WHITE}│   ├── ACAO: "
                f"{result['acao_header']}{Colors.END}"
            )
            if result.get('acac_header'):
                safe_print(
                    f"    {Colors.WHITE}│   ├── ACAC: "
                    f"{result['acac_header']}{Colors.END}"
                )

        # ─── Show baseline info ───
        if result.get('origin_triggered_cors'):
            safe_print(
                f"    {Colors.MAGENTA}├── ⚡ Origin TRIGGERED CORS "
                f"(no CORS in baseline){Colors.END}"
            )

        # ─── Credential warning ───
        if result.get('credentials_allowed'):
            safe_print(
                f"    {Colors.RED}├── ⚠ CREDENTIALS: "
                f"ALLOWED - cookies/auth sent cross-origin!{Colors.END}"
            )

        # ─── Vary warning ───
        if result.get('vary_origin_missing'):
            safe_print(
                f"    {Colors.YELLOW}├── ⚠ Vary: Origin "
                f"MISSING (Cache Poisoning Risk){Colors.END}"
            )

        # ─── Dangerous methods ───
        if result.get('dangerous_methods'):
            methods = result.get('dangerous_methods_list', [])
            safe_print(
                f"    {Colors.RED}├── ⚠ Dangerous Methods: "
                f"{', '.join(methods)}{Colors.END}"
            )

        # ─── Sensitive headers ───
        if result.get('sensitive_headers_exposed'):
            hdrs = result.get('sensitive_headers_list', [])
            safe_print(
                f"    {Colors.RED}├── ⚠ Sensitive Headers Exposed: "
                f"{', '.join(hdrs)}{Colors.END}"
            )

        # ─── Response Analysis (WHY it's vulnerable) ───
        analysis = result.get('response_analysis', [])
        if analysis:
            safe_print(
                f"    {Colors.MAGENTA}├── Response Analysis:{Colors.END}"
            )
            for i, line in enumerate(analysis):
                prefix = '│   ├──' if i < len(analysis) - 1 else '│   └──'
                safe_print(
                    f"    {Colors.MAGENTA}{prefix} {line}{Colors.END}"
                )

        safe_print(
            f"    {Colors.WHITE}├── Status: "
            f"{result['status_code']}{Colors.END}"
        )
        safe_print(
            f"    {Colors.WHITE}├── Impact: "
            f"{result.get('impact', 'N/A')}{Colors.END}"
        )
        safe_print(
            f"    {Colors.WHITE}└── Fix: "
            f"{result.get('remediation', 'N/A')}{Colors.END}"
        )

    # ══════════════════════════════════════════
    # TXT REPORT - ONLY VULNERABLES
    # ══════════════════════════════════════════
    def generate_txt_report(self, filename=None):
        if not self.results:
            safe_print(
                f"\n{Colors.GREEN}[*] No vulnerabilities "
                f"found - no report generated{Colors.END}"
            )
            return

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        if filename is None:
            filename = f"cors_report_{timestamp}.txt"
        if not filename.endswith('.txt'):
            filename += '.txt'

        # Group by URL
        url_groups = defaultdict(list)
        for r in self.results:
            if r.get('vulnerable'):
                url_groups[r['url']].append(r)

        if not url_groups:
            safe_print(
                f"\n{Colors.GREEN}[*] No vulnerable findings{Colors.END}"
            )
            return

        with open(filename, 'w') as f:
            f.write("=" * 73 + "\n")
            f.write(
                "  ULTIMATE CORS SCANNER v3.0 - VULNERABILITY REPORT\n"
            )
            f.write(
                f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            f.write(
                f"  Total Findings: "
                f"{sum(len(v) for v in url_groups.values())}\n"
            )
            f.write(f"  Vulnerable URLs: {len(url_groups)}\n")
            f.write("=" * 73 + "\n")

            url_count = 0
            for url, findings in url_groups.items():
                url_count += 1
                if url_count > 1:
                    f.write("\n" + "=" * 73 + "\n\n")

                f.write(f"TARGET: {url}\n")
                f.write(f"FINDINGS: {len(findings)}\n")
                f.write("-" * 73 + "\n")

                for i, r in enumerate(findings, 1):
                    f.write(f"\n  [{i}] {r['test_name']}\n")
                    f.write(f"      Severity      : {r['severity']}\n")
                    f.write(f"      Category      : {r['category']}\n")
                    f.write(f"      Vuln Type     : {r.get('vuln_type', 'N/A')}\n")
                    f.write(f"      Origin Sent   : {r['origin_sent']}\n")

                    # All CORS response headers
                    f.write(f"      Response CORS Headers:\n")
                    cors_h = r.get('all_cors_headers', {})
                    if cors_h:
                        for h, v in cors_h.items():
                            if v:
                                marker = ''
                                if h == 'Access-Control-Allow-Origin':
                                    if v == r.get('origin_sent', ''):
                                        marker = ' ← REFLECTED!'
                                    elif v == '*':
                                        marker = ' ← WILDCARD!'
                                    elif v.lower() == 'null':
                                        marker = ' ← NULL!'
                                elif h == 'Access-Control-Allow-Credentials':
                                    if v.lower() == 'true':
                                        marker = ' ← DANGEROUS!'
                                elif h == 'Vary':
                                    if 'origin' not in v.lower():
                                        marker = ' ← Missing Origin!'
                                f.write(f"        {h}: {v}{marker}\n")
                    else:
                        f.write(f"        ACAO: {r['acao_header']}\n")
                        if r.get('acac_header'):
                            f.write(f"        ACAC: {r['acac_header']}\n")

                    if r.get('origin_triggered_cors'):
                        f.write(
                            f"      ⚡ Origin TRIGGERED CORS "
                            f"(no CORS in baseline)\n"
                        )

                    if r.get('credentials_allowed'):
                        f.write(f"      ⚠ Credentials  : ALLOWED\n")
                    if r.get('wildcard'):
                        f.write(f"      ⚠ Wildcard     : YES (*)\n")
                    if r.get('vary_origin_missing'):
                        f.write(
                            f"      ⚠ Vary: Origin : MISSING "
                            f"(Cache Poisoning)\n"
                        )
                    if r.get('dangerous_methods'):
                        methods = r.get('dangerous_methods_list', [])
                        f.write(
                            f"      ⚠ Methods      : "
                            f"{', '.join(methods)}\n"
                        )
                    if r.get('sensitive_headers_exposed'):
                        hdrs = r.get('sensitive_headers_list', [])
                        f.write(
                            f"      ⚠ Exposed Hdrs : "
                            f"{', '.join(hdrs)}\n"
                        )

                    # Response analysis
                    analysis = r.get('response_analysis', [])
                    if analysis:
                        f.write(f"      Response Analysis:\n")
                        for line in analysis:
                            f.write(f"        • {line}\n")

                    f.write(f"      Status Code   : {r['status_code']}\n")
                    f.write(f"      Description   : {r['description']}\n")
                    f.write(f"      Impact        : {r.get('impact', 'N/A')}\n")
                    f.write(
                        f"      Remediation   : "
                        f"{r.get('remediation', 'N/A')}\n"
                    )

            f.write("\n" + "=" * 73 + "\n")
            f.write("  END OF REPORT\n")
            f.write("=" * 73 + "\n")

        safe_print(
            f"{Colors.GREEN}[✓] TXT Report: {filename}{Colors.END}"
        )

    # ══════════════════════════════════════════
    # FINAL SUMMARY
    # ══════════════════════════════════════════
    def print_summary(self):
        safe_print(f"\n{'═' * 60}")
        safe_print(
            f"{Colors.BOLD}{Colors.CYAN}"
            f"              SCAN SUMMARY"
            f"{Colors.END}"
        )
        safe_print(f"{'═' * 60}")

        duration = "N/A"
        if self.stats.start_time and self.stats.end_time:
            duration = str(self.stats.end_time - self.stats.start_time)

        safe_print(f"  Duration: {duration}")
        safe_print(f"  URLs Scanned: {self.stats.total_urls or 1}")
        safe_print(f"  Total Tests: {self.stats.total_tests}")
        safe_print(f"  Errors: {self.stats.errors}")
        safe_print(f"  Timeouts: {self.stats.timeouts}")

        safe_print(f"\n  {'─' * 40}")
        safe_print(f"  VULNERABILITIES FOUND:")
        safe_print(f"  {'─' * 40}")

        safe_print(
            f"  {Colors.RED}🔴 Critical: "
            f"{self.stats.critical}{Colors.END}"
        )
        safe_print(
            f"  {Colors.RED}🟠 High: "
            f"{self.stats.high}{Colors.END}"
        )
        safe_print(
            f"  {Colors.YELLOW}🟡 Medium: "
            f"{self.stats.medium}{Colors.END}"
        )
        safe_print(
            f"  {Colors.CYAN}🔵 Low: "
            f"{self.stats.low}{Colors.END}"
        )
        safe_print(
            f"  {Colors.WHITE}⚪ Info: "
            f"{self.stats.info}{Colors.END}"
        )
        safe_print(f"  {'─' * 40}")
        safe_print(
            f"  {Colors.BOLD}TOTAL: "
            f"{self.stats.total_vulns}{Colors.END}"
        )

        if self.results:
            vuln_urls = set(r['url'] for r in self.results)
            safe_print(
                f"\n  {Colors.RED}{Colors.BOLD}"
                f"Vulnerable URLs ({len(vuln_urls)}):"
                f"{Colors.END}"
            )
            sev_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            for url in vuln_urls:
                url_vulns = [r for r in self.results if r['url'] == url]
                max_sev = 'INFO'
                for r in url_vulns:
                    if sev_order.index(r['severity']) < sev_order.index(max_sev):
                        max_sev = r['severity']
                safe_print(
                    f"    • [{max_sev}] {url} ({len(url_vulns)} findings)"
                )

            categories = defaultdict(int)
            for r in self.results:
                categories[r['category']] += 1
            safe_print(
                f"\n  {Colors.CYAN}Findings by Category:{Colors.END}"
            )
            for cat, count in sorted(
                categories.items(), key=lambda x: x[1], reverse=True
            ):
                safe_print(f"    • {cat}: {count}")

        safe_print(f"{'═' * 60}\n")


# ══════════════════════════════════════════════════════
# MAIN FUNCTION
# ══════════════════════════════════════════════════════
def main():
    banner()

    parser = argparse.ArgumentParser(
        description='Ultimate CORS Misconfiguration Scanner v3.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EXAMPLES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Basic scan:
    python3 cors_scanner.py -u https://example.com

  With output:
    python3 cors_scanner.py -u https://example.com -o report.txt

  URL list:
    python3 cors_scanner.py -l urls.txt -t 20 -o results.txt

  Custom headers:
    python3 cors_scanner.py -u https://api.target.com \\
      -H "X-Api-Key: secret123" -H "X-Custom: value"

  Authentication:
    python3 cors_scanner.py -u https://api.target.com \\
      --auth "Bearer eyJhbG..."

  Through proxy:
    python3 cors_scanner.py -u https://target.com \\
      --proxy http://127.0.0.1:8080
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    )

    # Target Options
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('-u', '--url', help='Single URL to scan')
    target.add_argument('-l', '--list', help='File with URLs')

    # Scan Options
    parser.add_argument(
        '-t', '--threads', type=int, default=10,
        help='Thread count (default: 10)'
    )
    parser.add_argument(
        '--timeout', type=int, default=10,
        help='Request timeout seconds (default: 10)'
    )
    parser.add_argument(
        '--delay', type=float, default=0,
        help='Delay between tests (default: 0)'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Show all results including safe'
    )

    # Authentication
    parser.add_argument(
        '--auth', help='Authorization header value'
    )
    parser.add_argument(
        '--cookie', help='Cookie header value'
    )

    # Custom Headers
    parser.add_argument(
        '-H', '--header', action='append', dest='headers',
        help='Custom header (e.g., -H "X-Api-Key: value")'
    )

    # Proxy
    parser.add_argument(
        '--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)'
    )

    # Output
    parser.add_argument(
        '-o', '--output', help='Output TXT filename'
    )

    # Skip Options
    parser.add_argument(
        '--skip-methods', action='store_true',
        help='Skip HTTP method variation tests'
    )
    parser.add_argument(
        '--skip-websocket', action='store_true',
        help='Skip WebSocket CORS tests'
    )
    parser.add_argument(
        '--skip-cache', action='store_true',
        help='Skip cache poisoning tests'
    )

    # Redirect Options
    parser.add_argument(
        '--no-redirect', action='store_true',
        help='Do not follow redirects'
    )
    parser.add_argument(
        '--max-redirects', type=int, default=5,
        help='Max redirects (default: 5)'
    )

    args = parser.parse_args()

    custom_headers = UltimateCORSScanner.parse_custom_headers(args.headers)

    config = {
        'timeout': args.timeout,
        'threads': args.threads,
        'verbose': args.verbose,
        'delay': args.delay,
        'auth': args.auth,
        'cookie': args.cookie,
        'proxy': args.proxy,
        'follow_redirects': not args.no_redirect,
        'max_redirects': args.max_redirects,
        'test_methods': not args.skip_methods,
        'test_websocket': not args.skip_websocket,
        'test_cache': not args.skip_cache,
        'custom_headers': custom_headers,
        'output_file': args.output,
    }

    scanner = UltimateCORSScanner(config)

    # Print Config
    safe_print(f"{Colors.CYAN}[Configuration]{Colors.END}")
    safe_print(f"  Threads: {config['threads']}")
    safe_print(f"  Timeout: {config['timeout']}s")
    safe_print(f"  Delay: {config['delay']}s")
    safe_print(f"  Auth: {'Set' if config['auth'] else 'None'}")
    safe_print(f"  Cookie: {'Set' if config['cookie'] else 'None'}")
    safe_print(f"  Proxy: {config['proxy'] or 'None'}")

    if custom_headers:
        safe_print(f"  Custom Headers: {len(custom_headers)}")
        for k, v in custom_headers.items():
            safe_print(f"    • {k}: {v}")
    else:
        safe_print(f"  Custom Headers: None")

    safe_print(
        f"  Method Tests: "
        f"{'Yes' if config['test_methods'] else 'Skipped'}"
    )
    safe_print(
        f"  WebSocket Tests: "
        f"{'Yes' if config['test_websocket'] else 'Skipped'}"
    )
    safe_print(
        f"  Cache Tests: "
        f"{'Yes' if config['test_cache'] else 'Skipped'}"
    )
    safe_print(f"  Output: {args.output or 'Terminal only'}")

    # Start Scanning
    scanner.stats.start_time = datetime.now()

    def signal_handler(sig, frame):
        safe_print(
            f"\n{Colors.YELLOW}[!] Scan interrupted{Colors.END}"
        )
        scanner.stats.end_time = datetime.now()
        scanner.print_summary()
        if args.output:
            scanner.generate_txt_report(filename=args.output)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    if args.url:
        scanner.stats.total_urls = 1
        scanner.scan_url(args.url)
    elif args.list:
        scanner.scan_from_file(args.list)

    scanner.stats.end_time = datetime.now()

    # Summary
    scanner.print_summary()

    # Report
    if args.output:
        safe_print(
            f"{Colors.CYAN}[*] Generating TXT report...{Colors.END}"
        )
        scanner.generate_txt_report(filename=args.output)

    safe_print(
        f"\n{Colors.GREEN}{Colors.BOLD}"
        f"[✓] Scan complete!{Colors.END}"
    )


if __name__ == '__main__':
    main()
