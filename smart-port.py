#!/usr/bin/env python3
"""
🔥 SMART PORT SCANNER v5.0 🔥
Pure Python - No External Tools Required

Default: Domain dalo → Full automatic scan
  Step 1: Subdomain Discovery (crt.sh + DNS brute + archives)
  Step 2: Port Scanning (68+ interesting ports)
  Step 3: HTTP Service Probing (title + tech detect)
  Step 4: Banner Grabbing & Fingerprinting
  Step 5: High-Value Target Detection & TXT Report

License: Educational & Authorized Testing Only
"""

import os
import sys
import re
import ssl
import json
import time
import socket
import hashlib
import datetime
import threading
import argparse
from urllib.request import urlopen, Request
from urllib.parse import urlparse, urljoin
from urllib.error import HTTPError, URLError
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Optional, Tuple, Any
from collections import defaultdict

# ==================== COLORS ====================
class C:
    RESET     = "\033[0m"
    BOLD      = "\033[1m"
    DIM       = "\033[2m"
    RED       = "\033[91m"
    GREEN     = "\033[92m"
    YELLOW    = "\033[93m"
    BLUE      = "\033[94m"
    MAGENTA   = "\033[95m"
    CYAN      = "\033[96m"
    WHITE     = "\033[97m"
    ORANGE    = "\033[38;5;208m"
    PINK      = "\033[38;5;213m"
    LIME      = "\033[38;5;118m"
    GOLD      = "\033[38;5;220m"
    PURPLE    = "\033[38;5;141m"
    TEAL      = "\033[38;5;51m"
    GRAY      = "\033[38;5;240m"
    LGRAY     = "\033[38;5;250m"
    BG_RED    = "\033[41m"

# ==================== DEFAULT CONFIGURATION ====================
class Config:
    VERSION          = "5.0"
    MAX_THREADS      = 100       # Default threads
    PORT_TIMEOUT     = 3         # Default port scan timeout
    HTTP_TIMEOUT     = 10        # Default HTTP probe timeout
    BANNER_TIMEOUT   = 5         # Banner grab timeout
    SUB_THREADS      = 20        # Subdomain resolution threads
    RATE_LIMIT       = 0         # No delay by default

    # DEFAULT: All 68+ interesting uncommon ports
    INTERESTING_PORTS = [
        81, 300, 443, 591, 593, 832, 981, 1010, 1311,
        2082, 2087, 2095, 2096, 2480,
        3000, 3128, 3306, 3333, 3389,
        4243, 4567, 4711, 4712, 4993,
        5000, 5104, 5108, 5432, 5800, 5900, 5984,
        6379, 6543,
        7000, 7396, 7474,
        8000, 8001, 8008, 8014, 8042, 8069, 8080, 8081,
        8088, 8090, 8091, 8118, 8123, 8172, 8222, 8243,
        8280, 8281, 8333, 8443, 8500, 8834, 8880, 8888, 8983,
        9000, 9043, 9060, 9080, 9090, 9091, 9200, 9300,
        9443, 9800, 9981, 9999,
        10000, 10250, 10255, 11211,
        12443, 15672, 16080,
        18091, 18092,
        20720, 27017, 28017
    ]

    # Built-in subdomain wordlist
    SUBDOMAIN_WORDLIST = [
        "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "dns",
        "webmail", "admin", "portal", "api", "dev", "staging", "stage",
        "test", "testing", "qa", "uat", "beta", "demo", "app",
        "m", "mobile", "cdn", "static", "assets", "media", "img",
        "images", "video", "docs", "doc", "help", "support", "forum",
        "blog", "shop", "store", "secure", "vpn", "remote", "gateway",
        "proxy", "cache", "web", "www1", "www2", "web1", "web2",
        "server", "server1", "server2", "db", "database", "mysql",
        "postgres", "mongo", "redis", "elastic", "elasticsearch",
        "kibana", "grafana", "jenkins", "ci", "cd", "git", "gitlab",
        "github", "bitbucket", "jira", "confluence", "wiki",
        "monitor", "monitoring", "nagios", "zabbix", "prometheus",
        "status", "health", "ping", "dashboard", "panel", "cpanel",
        "whm", "plesk", "webmin", "phpmyadmin", "adminer",
        "cloud", "aws", "azure", "gcp", "docker", "k8s", "kubernetes",
        "node", "node1", "node2", "worker", "master", "backup",
        "bak", "old", "new", "temp", "tmp", "log", "logs",
        "internal", "intranet", "extranet", "private", "public",
        "auth", "login", "sso", "oauth", "ldap", "ad",
        "mx", "mx1", "mx2", "relay", "exchange",
        "chat", "im", "irc", "slack", "teams",
        "api1", "api2", "api-v1", "api-v2", "rest", "graphql",
        "ws", "websocket", "socket", "wss",
        "s3", "storage", "files", "download", "upload",
        "analytics", "tracking", "pixel", "ads",
        "pay", "payment", "billing", "invoice",
        "crm", "erp", "hr", "finance",
        "sandbox", "preview", "canary", "edge",
        "consul", "vault", "nomad", "terraform",
        "rabbitmq", "kafka", "activemq", "solr",
        "tomcat", "apache", "nginx", "iis",
        "office", "outlook", "autodiscover", "lyncdiscover",
        "sip", "meet", "conference", "call",
        "ns", "ns3", "ns4", "dns1", "dns2",
    ]

    # High-value service keywords
    HIGH_VALUE_KEYWORDS = [
        "elasticsearch", "elastic", "kibana", "grafana", "jenkins",
        "docker", "kubernetes", "k8s", "redis", "mongodb", "mongo",
        "prometheus", "consul", "vault", "etcd", "couchdb", "couchbase",
        "rabbitmq", "kafka", "activemq", "solr", "hadoop", "spark",
        "phpmyadmin", "adminer", "pgadmin", "webmin", "cpanel",
        "tomcat", "jboss", "wildfly", "glassfish", "websphere",
        "jupyter", "notebook", "zeppelin", "airflow", "mlflow",
        "sonarqube", "nexus", "artifactory", "harbor",
        "gitea", "gogs", "gitlab", "drone", "argo",
        "traefik", "envoy", "haproxy", "nginx status",
        "memcached", "cassandra", "influxdb", "clickhouse",
        "minio", "portainer", "rancher", "longhorn",
        "keycloak", "dex", "hydra", "oauth",
        "nagios", "zabbix", "icinga", "sensu",
        "splunk", "graylog", "logstash", "fluentd",
        "debug", "phpinfo", "server-status", "server-info",
        "actuator", "health", "metrics", "swagger", "api-docs",
    ]

    # Service fingerprint signatures
    SERVICE_SIGNATURES = {
        "Elasticsearch": [b'"cluster_name"', b'"tagline" : "You Know, for Search"'],
        "Kibana": [b'kibana', b'kbn-name', b'kbn-xsrf'],
        "Grafana": [b'grafana', b'Grafana'],
        "Jenkins": [b'jenkins', b'Jenkins', b'X-Jenkins'],
        "Docker API": [b'docker', b'/v1.', b'ApiVersion'],
        "Kubernetes": [b'kubernetes', b'/api/v1'],
        "Redis": [b'REDIS', b'redis_version'],
        "MongoDB": [b'MongoDB', b'ismaster'],
        "Prometheus": [b'prometheus', b'go_gc_duration'],
        "Consul": [b'consul', b'Consul'],
        "CouchDB": [b'couchdb', b'"couchdb":"Welcome"'],
        "RabbitMQ": [b'rabbitmq', b'RabbitMQ'],
        "Tomcat": [b'tomcat', b'Apache Tomcat'],
        "phpMyAdmin": [b'phpmyadmin', b'phpMyAdmin'],
        "GitLab": [b'gitlab', b'GitLab'],
        "Jupyter": [b'jupyter', b'Jupyter'],
        "Swagger": [b'swagger', b'api-docs'],
        "Spring Actuator": [b'actuator', b'"status":"UP"'],
        "Portainer": [b'portainer', b'Portainer'],
        "MinIO": [b'minio', b'MinIO'],
        "Vault": [b'vault', b'Vault'],
        "SonarQube": [b'sonarqube', b'SonarQube'],
        "Solr": [b'solr', b'Solr'],
        "Webmin": [b'webmin', b'Webmin'],
        "cPanel": [b'cpanel', b'cPanel'],
    }


# ==================== GLOBAL STATE ====================
class State:
    discovered_subdomains: Set[str]     = set()
    resolved_hosts: Dict[str, str]      = {}     # subdomain -> IP
    open_ports: Dict[str, List[int]]    = defaultdict(list)
    http_services: List[Dict]           = []
    high_value_targets: List[Dict]      = []
    lock                                = threading.Lock()
    total_ports_scanned                 = 0
    total_open_ports                    = 0
    start_time                          = None

ST = State()

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


# ==================== BANNER ====================
def print_banner():
    print(f"""
{C.ORANGE}╔══════════════════════════════════════════════════════════════════════════════╗{C.RESET}
{C.ORANGE}║{C.RESET}  {C.RED}{C.BOLD}🔥 SMART PORT SCANNER v5.0 🔥{C.RESET}                                            {C.ORANGE}║{C.RESET}
{C.ORANGE}║{C.RESET}  {C.CYAN}Pure Python • No External Tools • Full Automatic Default{C.RESET}                 {C.ORANGE}║{C.RESET}
{C.ORANGE}╠══════════════════════════════════════════════════════════════════════════════╣{C.RESET}
{C.ORANGE}║{C.RESET}  {C.YELLOW}📋 Default Pipeline (just give domain):{C.RESET}                                   {C.ORANGE}║{C.RESET}
{C.ORANGE}║{C.RESET}     {C.GREEN}Step 1:{C.RESET} Subdomain Discovery (DNS + crt.sh + archives)              {C.ORANGE}║{C.RESET}
{C.ORANGE}║{C.RESET}     {C.GREEN}Step 2:{C.RESET} Port Scan ({C.GOLD}{len(Config.INTERESTING_PORTS)}{C.RESET} interesting ports, {C.GOLD}{Config.MAX_THREADS}{C.RESET} threads)          {C.ORANGE}║{C.RESET}
{C.ORANGE}║{C.RESET}     {C.GREEN}Step 3:{C.RESET} HTTP Service Probing (title + tech + headers)              {C.ORANGE}║{C.RESET}
{C.ORANGE}║{C.RESET}     {C.GREEN}Step 4:{C.RESET} High-Value Target Detection (50+ services)                 {C.ORANGE}║{C.RESET}
{C.ORANGE}║{C.RESET}     {C.GREEN}Step 5:{C.RESET} TXT Report Generation (clean + colored)                    {C.ORANGE}║{C.RESET}
{C.ORANGE}╠══════════════════════════════════════════════════════════════════════════════╣{C.RESET}
{C.ORANGE}║{C.RESET}  {C.LIME}📂 Output: TXT files only (no JSON/HTML){C.RESET}                                 {C.ORANGE}║{C.RESET}
{C.ORANGE}║{C.RESET}  {C.RED}⚠️  For AUTHORIZED SECURITY TESTING ONLY{C.RESET}                                  {C.ORANGE}║{C.RESET}
{C.ORANGE}╚══════════════════════════════════════════════════════════════════════════════╝{C.RESET}
""")


def print_step(num: int, title: str):
    print(f"\n{C.ORANGE}{'━' * 80}{C.RESET}")
    print(f"  {C.BOLD}{C.GREEN}▶ STEP {num}:{C.RESET} {C.BOLD}{C.CYAN}{title}{C.RESET}")
    print(f"{C.ORANGE}{'━' * 80}{C.RESET}")


def print_progress(current: int, total: int, prefix: str = ""):
    bar_len = 40
    filled  = int(bar_len * current / max(total, 1))
    bar     = f"{C.GREEN}{'█' * filled}{C.GRAY}{'░' * (bar_len - filled)}{C.RESET}"
    pct     = current / max(total, 1) * 100
    sys.stdout.write(f"\r  {prefix} [{bar}] {C.YELLOW}{pct:5.1f}%{C.RESET} ({current}/{total})  ")
    sys.stdout.flush()
    if current >= total:
        print()


# ==================== STEP 1: SUBDOMAIN DISCOVERY ====================
def dns_resolve(hostname: str) -> Optional[str]:
    try:
        return socket.gethostbyname(hostname)
    except:
        return None


def subdomain_bruteforce(domain: str) -> Set[str]:
    found = set()
    total = len(Config.SUBDOMAIN_WORDLIST)
    print(f"  {C.CYAN}🔤 DNS Brute-force ({total} words)...{C.RESET}")

    completed = 0
    lock = threading.Lock()

    def check(word):
        nonlocal completed
        sub = f"{word}.{domain}"
        ip  = dns_resolve(sub)
        if ip:
            with lock:
                found.add(sub)
                ST.resolved_hosts[sub] = ip
        with lock:
            completed += 1
            if completed % 20 == 0 or completed == total:
                print_progress(completed, total, "  Brute-force")

    with ThreadPoolExecutor(max_workers=Config.SUB_THREADS) as ex:
        futures = [ex.submit(check, w) for w in Config.SUBDOMAIN_WORDLIST]
        for f in as_completed(futures):
            try: f.result()
            except: pass

    print(f"  {C.GREEN}  ✅ Found {len(found)} via DNS brute-force{C.RESET}")
    return found


def crtsh_enum(domain: str) -> Set[str]:
    found = set()
    print(f"  {C.CYAN}🔐 Querying crt.sh...{C.RESET}")
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = Request(url, headers={"User-Agent": "Mozilla/5.0 Chrome/120.0.0.0"})
        with urlopen(req, timeout=15, context=SSL_CTX) as resp:
            data = json.loads(resp.read().decode('utf-8', 'ignore'))
            for entry in data:
                for sub in entry.get("name_value", "").split("\n"):
                    sub = sub.strip().lower()
                    if (sub.endswith(f".{domain}") or sub == domain) and "*" not in sub:
                        found.add(sub)
        print(f"  {C.GREEN}  ✅ Found {len(found)} via crt.sh{C.RESET}")
    except Exception as e:
        print(f"  {C.YELLOW}  ⚠️ crt.sh error: {str(e)[:60]}{C.RESET}")
    return found


def web_archive_enum(domain: str) -> Set[str]:
    found = set()
    print(f"  {C.CYAN}📚 Querying Web Archive...{C.RESET}")
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey&limit=500"
        req = Request(url, headers={"User-Agent": "Mozilla/5.0 Chrome/120.0.0.0"})
        with urlopen(req, timeout=20, context=SSL_CTX) as resp:
            for line in resp.read().decode('utf-8', 'ignore').split('\n'):
                line = line.strip()
                if line:
                    try:
                        host = urlparse(line).hostname
                        if host and (host.endswith(f".{domain}") or host == domain):
                            found.add(host)
                    except: pass
        print(f"  {C.GREEN}  ✅ Found {len(found)} via Web Archive{C.RESET}")
    except Exception as e:
        print(f"  {C.YELLOW}  ⚠️ Web Archive error: {str(e)[:60]}{C.RESET}")
    return found


def hackertarget_enum(domain: str) -> Set[str]:
    found = set()
    print(f"  {C.CYAN}🎯 Querying HackerTarget...{C.RESET}")
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        req = Request(url, headers={"User-Agent": "Mozilla/5.0 Chrome/120.0.0.0"})
        with urlopen(req, timeout=15, context=SSL_CTX) as resp:
            for line in resp.read().decode('utf-8', 'ignore').split('\n'):
                if ',' in line:
                    sub = line.split(',')[0].strip().lower()
                    if sub.endswith(f".{domain}") or sub == domain:
                        found.add(sub)
        print(f"  {C.GREEN}  ✅ Found {len(found)} via HackerTarget{C.RESET}")
    except Exception as e:
        print(f"  {C.YELLOW}  ⚠️ HackerTarget error: {str(e)[:60]}{C.RESET}")
    return found


def discover_subdomains(domain: str) -> Set[str]:
    all_subs = {domain}

    for name, func in [
        ("DNS Brute-force", subdomain_bruteforce),
        ("crt.sh",          crtsh_enum),
        ("Web Archive",     web_archive_enum),
        ("HackerTarget",    hackertarget_enum),
    ]:
        try:
            all_subs.update(func(domain))
        except Exception as e:
            print(f"  {C.RED}  ❌ {name} failed: {e}{C.RESET}")

    # Resolve all
    print(f"\n  {C.CYAN}🔍 Resolving {len(all_subs)} unique subdomains...{C.RESET}")

    def resolve_one(sub):
        if sub not in ST.resolved_hosts:
            ip = dns_resolve(sub)
            if ip:
                with ST.lock:
                    ST.resolved_hosts[sub] = ip

    with ThreadPoolExecutor(max_workers=Config.SUB_THREADS) as ex:
        list(ex.map(resolve_one, all_subs))

    live = {s for s in all_subs if s in ST.resolved_hosts}
    print(f"  {C.GREEN}  ✅ {len(live)} live subdomains resolved{C.RESET}")
    return live


# ==================== STEP 2: PORT SCANNING ====================
def scan_port(host: str, port: int, ip: str = None) -> Tuple[bool, Optional[str]]:
    target = ip or host
    banner = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(Config.PORT_TIMEOUT)
        result = sock.connect_ex((target, port))
        if result == 0:
            try:
                sock.settimeout(Config.BANNER_TIMEOUT)
                if port in [80,443,8080,8443,8000,8888,3000,9090,8081,8088,9200,5984,15672]:
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                else:
                    sock.sendall(b"\r\n")
                banner = sock.recv(1024).decode('utf-8', 'ignore').strip()[:200]
            except: pass
            sock.close()
            return True, banner
        sock.close()
    except: pass
    return False, None


def scan_all_ports(subdomains: Set[str], ports: List[int]):
    total_tasks = len(subdomains) * len(ports)
    completed = 0
    lock = threading.Lock()

    print(f"  {C.CYAN}📡 Scanning {len(subdomains)} hosts × {len(ports)} ports = {C.GOLD}{total_tasks:,}{C.CYAN} checks{C.RESET}")
    print(f"  {C.CYAN}⚡ Threads: {C.GOLD}{Config.MAX_THREADS}{C.RESET}")
    print()

    def scan_host(host):
        nonlocal completed
        ip = ST.resolved_hosts.get(host)
        for port in ports:
            is_open, banner = scan_port(host, port, ip)
            if is_open:
                with ST.lock:
                    ST.open_ports[host].append(port)
                    ST.total_open_ports += 1
                    pc = C.RED if port in [3306,5432,6379,27017,9200,2375,11211] else C.GREEN
                    bn = f" {C.GRAY}│ {banner[:50]}{C.RESET}" if banner else ""
                    print(f"\r  {C.GREEN}🟢 OPEN{C.RESET} {C.CYAN}{host}{C.RESET}:{pc}{port}{C.RESET}{bn}" + " " * 20)
            with lock:
                completed += 1
                if completed % 200 == 0 or completed == total_tasks:
                    print_progress(completed, total_tasks, "  Scanning")

    with ThreadPoolExecutor(max_workers=Config.MAX_THREADS) as ex:
        futures = [ex.submit(scan_host, h) for h in subdomains]
        for f in as_completed(futures):
            try: f.result()
            except: pass

    print(f"\n  {C.GREEN}✅ Port scan complete: {C.GOLD}{ST.total_open_ports}{C.GREEN} open ports found{C.RESET}")


# ==================== STEP 3: HTTP SERVICE PROBING ====================
def probe_http(host: str, port: int) -> Optional[Dict]:
    result = {
        "host": host, "port": port, "url": "", "status_code": None,
        "title": "", "server": "", "headers": {}, "technologies": [],
        "is_https": False, "content_length": 0,
    }

    schemes = ["https","http"] if port in [443,8443,9443,12443] else ["http","https"]

    for scheme in schemes:
        url = f"{scheme}://{host}:{port}"
        result["url"] = url
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "Accept": "text/html,*/*;q=0.8",
                "Connection": "close",
            }
            req = Request(url, headers=headers)
            with urlopen(req, timeout=Config.HTTP_TIMEOUT, context=SSL_CTX) as resp:
                body = resp.read(50000).decode('utf-8', 'ignore')
                result["status_code"]    = resp.status
                result["is_https"]       = scheme == "https"
                result["content_length"] = len(body)
                result["url"]            = resp.url

                for key in resp.headers:
                    result["headers"][key.lower()] = resp.headers[key]
                result["server"] = resp.headers.get("Server", "")

                title_m = re.search(r'<title[^>]*>([^<]+)</title>', body, re.I)
                if title_m:
                    result["title"] = title_m.group(1).strip()[:100]

                result["technologies"] = detect_tech(body, result["headers"], result["server"])
                return result

        except HTTPError as e:
            result["status_code"] = e.code
            try:
                body = e.read(50000).decode('utf-8', 'ignore')
                title_m = re.search(r'<title[^>]*>([^<]+)</title>', body, re.I)
                if title_m:
                    result["title"] = title_m.group(1).strip()[:100]
                result["technologies"] = detect_tech(body, {}, "")
            except: pass
            return result
        except:
            continue

    return None


def detect_tech(body: str, headers: Dict, server: str) -> List[str]:
    techs = []
    bl = body.lower()
    sl = server.lower()

    for kw, name in [("nginx","Nginx"),("apache","Apache"),("iis","IIS"),
                      ("tomcat","Tomcat"),("gunicorn","Gunicorn"),("express","Express.js"),
                      ("cloudflare","Cloudflare")]:
        if kw in sl: techs.append(name)

    pw = headers.get("x-powered-by", "").lower()
    for kw, name in [("php","PHP"),("asp.net","ASP.NET"),("express","Express.js"),("next.js","Next.js")]:
        if kw in pw: techs.append(name)

    tech_map = {
        "WordPress": ["wp-content","wp-includes","wordpress"],
        "React": ["react","reactdom","_react"],
        "Angular": ["ng-app","angular"],
        "Vue.js": ["vue.js","vuejs"],
        "jQuery": ["jquery"],
        "Laravel": ["laravel"],
        "Django": ["django","csrfmiddlewaretoken"],
        "Flask": ["flask"],
        "Spring": ["spring","actuator"],
        "Elasticsearch": ['"cluster_name"',"you know, for search"],
        "Kibana": ["kibana","kbn-name"],
        "Grafana": ["grafana"],
        "Jenkins": ["jenkins","hudson"],
        "GitLab": ["gitlab"],
        "Prometheus": ["prometheus"],
        "phpMyAdmin": ["phpmyadmin"],
        "Swagger": ["swagger","api-docs"],
        "Docker": ["docker"],
        "K8s Dashboard": ["kubernetes-dashboard"],
        "Portainer": ["portainer"],
        "RabbitMQ": ["rabbitmq"],
        "MinIO": ["minio"],
        "Consul": ["consul"],
        "Vault": ["vault"],
        "Jupyter": ["jupyter","notebook"],
        "Drupal": ["drupal"],
        "Joomla": ["joomla"],
        "Ruby on Rails": ["rails"],
        "SonarQube": ["sonarqube"],
        "Solr": ["solr"],
        "Webmin": ["webmin"],
        "cPanel": ["cpanel"],
    }

    for tech, keywords in tech_map.items():
        if tech not in techs:
            for kw in keywords:
                if kw in bl:
                    techs.append(tech)
                    break

    return list(set(techs))


def probe_all_http():
    tasks = [(h, p) for h, ports in ST.open_ports.items() for p in ports]

    if not tasks:
        print(f"  {C.YELLOW}⚠️ No open ports to probe{C.RESET}")
        return

    print(f"  {C.CYAN}🌐 Probing {C.GOLD}{len(tasks)}{C.CYAN} HTTP services...{C.RESET}\n")

    completed = 0
    lock = threading.Lock()

    def probe_one(host, port):
        nonlocal completed
        result = probe_http(host, port)
        if result and result.get("status_code"):
            with ST.lock:
                ST.http_services.append(result)
                status = result["status_code"]
                if 200 <= status < 300:   sc = f"{C.GREEN}{status}{C.RESET}"
                elif 300 <= status < 400: sc = f"{C.YELLOW}{status}{C.RESET}"
                elif 400 <= status < 500: sc = f"{C.ORANGE}{status}{C.RESET}"
                else:                     sc = f"{C.RED}{status}{C.RESET}"
                tech = f" {C.MAGENTA}[{', '.join(result['technologies'][:3])}]{C.RESET}" if result['technologies'] else ""
                ttl  = f" {C.GOLD}「{result['title'][:35]}」{C.RESET}" if result['title'] else ""
                print(f"\r  {sc} {C.CYAN}{result['url']}{C.RESET}{ttl}{tech}" + " " * 10)
        with lock:
            completed += 1
            if completed % 5 == 0 or completed == len(tasks):
                print_progress(completed, len(tasks), "  Probing")

    with ThreadPoolExecutor(max_workers=min(20, Config.MAX_THREADS)) as ex:
        futures = [ex.submit(probe_one, h, p) for h, p in tasks]
        for f in as_completed(futures):
            try: f.result()
            except: pass

    print(f"\n  {C.GREEN}✅ Found {C.GOLD}{len(ST.http_services)}{C.GREEN} HTTP services{C.RESET}")


# ==================== STEP 4: HIGH-VALUE DETECTION ====================
HIGH_VALUE_PORTS = {
    9200: "Elasticsearch", 9300: "ES-Transport", 5601: "Kibana",
    3000: "Grafana/Dev", 8500: "Consul", 15672: "RabbitMQ-Mgmt",
    5984: "CouchDB", 27017: "MongoDB", 6379: "Redis",
    11211: "Memcached", 2375: "Docker API", 2376: "Docker TLS",
    10250: "Kubelet", 10255: "Kubelet-RO", 8834: "Nessus",
    9000: "SonarQube/Portainer", 4243: "Docker", 8888: "Jupyter",
    9090: "Prometheus", 10000: "Webmin",
}

def detect_high_value():
    for svc in ST.http_services:
        is_hv   = False
        reasons = []

        title_l = (svc.get("title") or "").lower()
        for kw in Config.HIGH_VALUE_KEYWORDS:
            if kw in title_l:
                is_hv = True
                reasons.append(f"Title contains '{kw}'")
                break

        for tech in svc.get("technologies", []):
            for kw in Config.HIGH_VALUE_KEYWORDS:
                if kw in tech.lower():
                    is_hv = True
                    reasons.append(f"Technology: {tech}")
                    break

        server_l = (svc.get("server") or "").lower()
        for kw in Config.HIGH_VALUE_KEYWORDS:
            if kw in server_l:
                is_hv = True
                reasons.append(f"Server: {svc['server']}")
                break

        port = svc.get("port", 0)
        if port in HIGH_VALUE_PORTS:
            is_hv = True
            reasons.append(f"High-value port {port} ({HIGH_VALUE_PORTS[port]})")

        if is_hv:
            svc["high_value_reasons"] = reasons
            ST.high_value_targets.append(svc)

    if ST.high_value_targets:
        print(f"\n  {C.RED}{C.BOLD}🚨 HIGH-VALUE TARGETS FOUND: {len(ST.high_value_targets)}{C.RESET}")
        for t in ST.high_value_targets:
            print(f"     {C.RED}🎯 {t['url']}{C.RESET}")
            if t.get("title"):
                print(f"        {C.GOLD}Title: {t['title']}{C.RESET}")
            for r in t.get("high_value_reasons", []):
                print(f"        {C.YELLOW}⚠ {r}{C.RESET}")
    else:
        print(f"  {C.GREEN}✅ No high-value targets detected{C.RESET}")


# ==================== PORT NAME LOOKUP ====================
SERVICE_NAMES = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",81:"HTTP-Alt",
    110:"POP3",143:"IMAP",300:"ThinLinc",443:"HTTPS",445:"SMB",
    591:"FileMaker",593:"HTTP-RPC",832:"NetBios",981:"cPanel-SSL",
    993:"IMAPS",995:"POP3S",1010:"ThinLinc",1311:"Dell-OMSA",
    2082:"cPanel",2087:"WHM",2095:"Webmail",2096:"Webmail-SSL",
    2375:"Docker-API",2376:"Docker-TLS",2480:"OrientDB",
    3000:"Grafana/Dev",3128:"Squid",3306:"MySQL",3333:"Dec-Notes",3389:"RDP",
    4243:"Docker",4567:"Sinatra",4711:"McAfee",4712:"McAfee",4993:"Horizon",
    5000:"Flask/Registry",5104:"ISC",5108:"VPOP",5432:"PostgreSQL",
    5800:"VNC-HTTP",5900:"VNC",5984:"CouchDB",
    6379:"Redis",6543:"Pyramid",
    7000:"Cassandra",7396:"Desktop-Central",7474:"Neo4j",
    8000:"HTTP-Alt",8001:"HTTP-Alt",8008:"HTTP-Alt",8014:"HTTP-Alt",
    8042:"YARN",8069:"Odoo",8080:"HTTP-Proxy",8081:"HTTP-Alt",
    8088:"HTTP-Alt",8090:"HTTP-Alt",8091:"Couchbase",8118:"Privoxy",
    8123:"Polipo/HA",8172:"IIS-Mgmt",8222:"HTTP-Alt",8243:"HTTPS-Alt",
    8280:"HTTP-Alt",8281:"HTTP-Alt",8333:"Bitcoin",
    8443:"HTTPS-Alt",8500:"Consul",8834:"Nessus",8880:"HTTP-Alt",
    8888:"Jupyter",8983:"Solr",
    9000:"SonarQube",9043:"WebSphere",9060:"WebSphere",9080:"HTTP-Alt",
    9090:"Prometheus",9091:"HTTP-Alt",9200:"Elasticsearch",9300:"ES-Transport",
    9443:"HTTPS-Alt",9800:"WebCT",9981:"TVheadend",9999:"HTTP-Alt",
    10000:"Webmin",10250:"Kubelet",10255:"Kubelet-RO",11211:"Memcached",
    12443:"HTTPS-Alt",15672:"RabbitMQ",16080:"HTTP-Alt",
    18091:"Couchbase",18092:"Couchbase",
    20720:"HTTP-Alt",27017:"MongoDB",28017:"MongoDB-HTTP",
}

def svc_name(port: int) -> str:
    return SERVICE_NAMES.get(port, f"Port-{port}")


# ==================== STEP 5: TXT REPORT ====================
def generate_report(domain: str):
    ts       = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    duration = time.time() - ST.start_time if ST.start_time else 0
    now_str  = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # ═══════ CLEAN TXT ═══════
    sep  = "=" * 100
    thin = "-" * 100
    L = []

    L.append(sep)
    L.append("  🔥 SMART PORT SCANNER v5.0 - SCAN REPORT")
    L.append(f"  📅 Date:     {now_str}")
    L.append(f"  🎯 Target:   {domain}")
    L.append(f"  ⏱️  Duration: {duration:.2f} seconds")
    L.append(sep)
    L.append("")
    L.append("  📊 SCAN STATISTICS")
    L.append(thin)
    L.append(f"     • Subdomains Discovered:   {len(ST.discovered_subdomains)}")
    L.append(f"     • Subdomains Resolved:     {len(ST.resolved_hosts)}")
    L.append(f"     • Ports Scanned:           {ST.total_ports_scanned:,}")
    L.append(f"     • Open Ports Found:        {ST.total_open_ports}")
    L.append(f"     • HTTP Services Found:     {len(ST.http_services)}")
    L.append(f"     • High-Value Targets:      {len(ST.high_value_targets)}")
    L.append("")

    # ── Subdomains ──
    L.append(sep)
    L.append("  🌍 DISCOVERED SUBDOMAINS")
    L.append(sep)
    L.append("")
    if ST.resolved_hosts:
        for sub in sorted(ST.resolved_hosts):
            L.append(f"     🟢 {sub:<50} → {ST.resolved_hosts[sub]}")
    else:
        L.append("     (none)")
    L.append("")

    # ── Open Ports ──
    L.append(sep)
    L.append("  🔓 OPEN PORTS BY HOST")
    L.append(sep)
    L.append("")

    if ST.open_ports:
        hnum = 0
        for host in sorted(ST.open_ports):
            ports = sorted(ST.open_ports[host])
            hnum += 1
            if hnum > 1:
                L.append("")
                L.append("  " + "═" * 96)
                L.append("")
            ip = ST.resolved_hosts.get(host, "?")
            L.append(f"  🌐 Host: {host} ({ip})")
            L.append(f"     Open Ports: {len(ports)}")
            L.append("  " + thin)
            for p in ports:
                L.append(f"     🔓 :{p:<6}  │  {svc_name(p)}")
    else:
        L.append("     (none)")
    L.append("")

    # ── HTTP Services ──
    L.append(sep)
    L.append("  🌐 HTTP SERVICES DETECTED")
    L.append(sep)
    L.append("")

    if ST.http_services:
        snum = 0
        for svc in sorted(ST.http_services, key=lambda x: x['url']):
            snum += 1
            if snum > 1:
                L.append("")
                L.append("  " + "═" * 96)
                L.append("")
            L.append(f"  [{snum}] {svc['url']}")
            L.append(f"      Status:       {svc.get('status_code','?')}")
            if svc.get("title"):
                L.append(f"      Title:        {svc['title']}")
            if svc.get("server"):
                L.append(f"      Server:       {svc['server']}")
            if svc.get("technologies"):
                L.append(f"      Technologies: {', '.join(svc['technologies'])}")
            if svc.get("is_https"):
                L.append(f"      HTTPS:        Yes")

            for hdr in ["x-powered-by","x-aspnet-version","access-control-allow-origin","x-generator"]:
                val = svc.get("headers",{}).get(hdr)
                if val: L.append(f"      {hdr}: {val}")
    else:
        L.append("     (none)")
    L.append("")

    # ── High-Value ──
    L.append(sep)
    if ST.high_value_targets:
        L.append("  🚨🚨🚨 HIGH-VALUE TARGETS 🚨🚨🚨")
    else:
        L.append("  ✅ HIGH-VALUE TARGETS: None Found")
    L.append(sep)
    L.append("")

    if ST.high_value_targets:
        for i, t in enumerate(ST.high_value_targets, 1):
            L.append(f"  🎯 [{i}] {t['url']}")
            if t.get("title"):  L.append(f"        Title:  {t['title']}")
            if t.get("server"): L.append(f"        Server: {t['server']}")
            if t.get("technologies"):
                L.append(f"        Tech:   {', '.join(t['technologies'])}")
            for r in t.get("high_value_reasons", []):
                L.append(f"        ⚠ REASON: {r}")
            L.append("")
    else:
        L.append("     (none)")
    L.append("")

    # ── Quick Reference Table ──
    L.append(sep)
    L.append("  📋 QUICK REFERENCE TABLE")
    L.append(sep)
    L.append("")
    L.append(f"  {'HOST':<45} {'PORT':<8} {'SERVICE':<20} {'STATUS':<8} {'TITLE'}")
    L.append("  " + thin)

    for svc in sorted(ST.http_services, key=lambda x: (x['host'], x['port'])):
        L.append(f"  {svc['host'][:44]:<45} {str(svc['port']):<8} {svc_name(svc['port'])[:19]:<20} {str(svc.get('status_code','?')):<8} {(svc.get('title') or '')[:40]}")

    for host, ports in sorted(ST.open_ports.items()):
        http_ports = {s['port'] for s in ST.http_services if s['host'] == host}
        for p in sorted(ports):
            if p not in http_ports:
                L.append(f"  {host[:44]:<45} {str(p):<8} {svc_name(p)[:19]:<20} {'N/A':<8} (non-HTTP)")

    L.append("")
    L.append(sep)
    L.append("  🔥 End of Report - Smart Port Scanner v5.0")
    L.append("  ⚠️  For authorized security testing only")
    L.append(sep)

    # Write clean
    clean_file = f"portscan_{domain}_{ts}.txt"
    with open(clean_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(L))

    # ═══════ COLORED TXT ═══════
    CL = build_colored(domain, duration, now_str)
    color_file = f"portscan_{domain}_{ts}_colored.txt"
    with open(color_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(CL))

    # ═══════ RAW DATA FILES ═══════
    sub_file = f"subdomains_{domain}_{ts}.txt"
    with open(sub_file, 'w') as f:
        for sub in sorted(ST.resolved_hosts):
            f.write(f"{sub}\n")

    port_file = f"open_ports_{domain}_{ts}.txt"
    with open(port_file, 'w') as f:
        for host, ports in sorted(ST.open_ports.items()):
            for p in sorted(ports):
                f.write(f"{host}:{p}\n")

    http_file = f"http_services_{domain}_{ts}.txt"
    with open(http_file, 'w') as f:
        for svc in ST.http_services:
            tech = ', '.join(svc.get('technologies', []))
            f.write(f"{svc['url']} [{svc.get('status_code','?')}] [{svc.get('title','')}] [{tech}]\n")

    hv_file = ""
    if ST.high_value_targets:
        hv_file = f"high_value_{domain}_{ts}.txt"
        with open(hv_file, 'w') as f:
            for t in ST.high_value_targets:
                f.write(f"{t['url']} | {t.get('title','')} | {', '.join(t.get('high_value_reasons',[]))}\n")

    print(f"\n  {C.GREEN}📁 Reports saved:{C.RESET}")
    print(f"     {C.CYAN}📄 {clean_file}{C.RESET}          (Clean report)")
    print(f"     {C.CYAN}🎨 {color_file}{C.RESET}  (Colored → cat filename)")
    print(f"     {C.CYAN}🌍 {sub_file}{C.RESET}          (Subdomains)")
    print(f"     {C.CYAN}🔓 {port_file}{C.RESET}         (Open ports)")
    print(f"     {C.CYAN}🌐 {http_file}{C.RESET}       (HTTP services)")
    if hv_file:
        print(f"     {C.RED}🚨 {hv_file}{C.RESET}       (HIGH-VALUE!)")


def build_colored(domain, duration, now_str):
    s = f"{C.ORANGE}{'═' * 100}{C.RESET}"
    t = f"{C.GRAY}{'-' * 100}{C.RESET}"
    cl = []

    cl.append(s)
    cl.append(f"  {C.RED}{C.BOLD}🔥 SMART PORT SCANNER v5.0 - SCAN REPORT{C.RESET}")
    cl.append(f"  {C.CYAN}📅 {now_str}  🎯 {C.BOLD}{domain}{C.RESET}  {C.CYAN}⏱️ {duration:.2f}s{C.RESET}")
    cl.append(s)
    cl.append("")
    cl.append(f"  {C.BOLD}{C.YELLOW}📊 STATISTICS{C.RESET}")
    cl.append(t)
    cl.append(f"     {C.GREEN}Subdomains:{C.RESET} {C.GOLD}{len(ST.resolved_hosts)}{C.RESET}  │  {C.LIME}Open Ports:{C.RESET} {C.GOLD}{ST.total_open_ports}{C.RESET}  │  {C.BLUE}HTTP:{C.RESET} {C.GOLD}{len(ST.http_services)}{C.RESET}  │  {C.RED}High-Value:{C.RESET} {C.GOLD}{len(ST.high_value_targets)}{C.RESET}")
    cl.append("")

    # Subdomains
    cl.append(s)
    cl.append(f"  {C.BOLD}{C.GREEN}🌍 SUBDOMAINS{C.RESET}")
    cl.append(s)
    for sub in sorted(ST.resolved_hosts):
        cl.append(f"     {C.GREEN}🟢{C.RESET} {C.CYAN}{sub:<50}{C.RESET} → {C.YELLOW}{ST.resolved_hosts[sub]}{C.RESET}")
    cl.append("")

    # Open Ports
    cl.append(s)
    cl.append(f"  {C.BOLD}{C.LIME}🔓 OPEN PORTS{C.RESET}")
    cl.append(s)

    hnum = 0
    for host in sorted(ST.open_ports):
        ports = sorted(ST.open_ports[host])
        hnum += 1
        if hnum > 1:
            cl.append(f"\n  {C.ORANGE}{'═' * 96}{C.RESET}\n")
        cl.append(f"  {C.BOLD}{C.CYAN}🌐 {host} ({ST.resolved_hosts.get(host,'?')}){C.RESET}  —  {C.GOLD}{len(ports)} ports{C.RESET}")
        cl.append(t)
        for p in ports:
            pc = C.RED if p in [3306,5432,6379,27017,11211,9200,2375] else (C.GREEN if p in [80,443,8080,8443] else C.YELLOW)
            cl.append(f"     {pc}🔓 :{p:<6}{C.RESET}  │  {C.LGRAY}{svc_name(p)}{C.RESET}")
    cl.append("")

    # HTTP Services
    cl.append(s)
    cl.append(f"  {C.BOLD}{C.BLUE}🌐 HTTP SERVICES{C.RESET}")
    cl.append(s)

    snum = 0
    for svc in sorted(ST.http_services, key=lambda x: x['url']):
        snum += 1
        if snum > 1:
            cl.append(f"\n  {C.ORANGE}{'═' * 96}{C.RESET}\n")
        st = svc.get("status_code", "?")
        if isinstance(st, int):
            if   200 <= st < 300: sc = f"{C.GREEN}{st}{C.RESET}"
            elif 300 <= st < 400: sc = f"{C.YELLOW}{st}{C.RESET}"
            elif 400 <= st < 500: sc = f"{C.ORANGE}{st}{C.RESET}"
            else:                 sc = f"{C.RED}{st}{C.RESET}"
        else: sc = str(st)

        cl.append(f"  {C.BOLD}[{snum}]{C.RESET} {C.CYAN}{svc['url']}{C.RESET}")
        cl.append(f"      {C.LGRAY}Status:{C.RESET} {sc}")
        if svc.get("title"):
            cl.append(f"      {C.LGRAY}Title:{C.RESET}  {C.GOLD}{svc['title']}{C.RESET}")
        if svc.get("server"):
            cl.append(f"      {C.LGRAY}Server:{C.RESET} {C.PURPLE}{svc['server']}{C.RESET}")
        if svc.get("technologies"):
            cl.append(f"      {C.LGRAY}Tech:{C.RESET}   {C.MAGENTA}{', '.join(svc['technologies'])}{C.RESET}")
    cl.append("")

    # High-Value
    cl.append(s)
    if ST.high_value_targets:
        cl.append(f"  {C.BOLD}{C.RED}{C.BG_RED} 🚨 HIGH-VALUE TARGETS 🚨 {C.RESET}")
    else:
        cl.append(f"  {C.BOLD}{C.GREEN}✅ No High-Value Targets{C.RESET}")
    cl.append(s)

    for i, tgt in enumerate(ST.high_value_targets, 1):
        cl.append(f"\n  {C.RED}{C.BOLD}🎯 [{i}] {tgt['url']}{C.RESET}")
        if tgt.get("title"):
            cl.append(f"        {C.GOLD}Title: {tgt['title']}{C.RESET}")
        if tgt.get("technologies"):
            cl.append(f"        {C.MAGENTA}Tech:  {', '.join(tgt['technologies'])}{C.RESET}")
        for r in tgt.get("high_value_reasons", []):
            cl.append(f"        {C.YELLOW}⚠ {r}{C.RESET}")
    cl.append("")

    cl.append(s)
    cl.append(f"  {C.RED}{C.BOLD}🔥 End - Smart Port Scanner v5.0{C.RESET}")
    cl.append(f"  {C.YELLOW}⚠️  Authorized testing only{C.RESET}")
    cl.append(s)
    return cl


# ==================== MAIN ====================
def main():
    print_banner()

    # ─── Parse args ───
    parser = argparse.ArgumentParser(
        description="🔥 Smart Port Scanner v5.0",
        epilog="Default: Just give domain → everything runs automatically"
    )
    parser.add_argument("-d", "--domain",       help="Target domain")
    parser.add_argument("--host-file",          help="File with hosts (one per line)")
    parser.add_argument("-t", "--threads",       type=int, default=100)
    parser.add_argument("--timeout",            type=int, default=3)
    parser.add_argument("--http-timeout",       type=int, default=10)
    parser.add_argument("--common-ports",       action="store_true")
    parser.add_argument("--ports",              help="Custom ports (comma-separated)")
    parser.add_argument("--skip-subdomain",     action="store_true")
    parser.add_argument("--skip-http",          action="store_true")

    args = parser.parse_args()

    # ─── Interactive if no domain ───
    if not args.domain and not args.host_file:
        print(f"  {C.CYAN}Enter target domain:{C.RESET}")
        args.domain = input(f"  {C.GREEN}👉 Domain: {C.RESET}").strip()
        if not args.domain:
            print(f"  {C.RED}❌ No domain given. Exiting.{C.RESET}")
            return
        # NO extra questions → all defaults run automatically

    # Apply config
    Config.MAX_THREADS  = args.threads
    Config.PORT_TIMEOUT = args.timeout
    Config.HTTP_TIMEOUT = args.http_timeout

    # Ports
    ports = list(Config.INTERESTING_PORTS)
    if args.common_ports:
        ports = list(set(ports + [21,22,23,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443]))
    if args.ports:
        custom = [int(p.strip()) for p in args.ports.split(',') if p.strip().isdigit()]
        ports = list(set(ports + custom))
    ports.sort()

    domain = args.domain

    # Show config
    print(f"\n  {C.GREEN}✅ Default Configuration:{C.RESET}")
    print(f"     {C.CYAN}Target:{C.RESET}      {C.BOLD}{domain}{C.RESET}")
    print(f"     {C.CYAN}Threads:{C.RESET}     {Config.MAX_THREADS}")
    print(f"     {C.CYAN}Port Timeout:{C.RESET} {Config.PORT_TIMEOUT}s")
    print(f"     {C.CYAN}HTTP Timeout:{C.RESET} {Config.HTTP_TIMEOUT}s")
    print(f"     {C.CYAN}Ports:{C.RESET}       {len(ports)} interesting ports")
    print(f"     {C.CYAN}Output:{C.RESET}      {C.BOLD}TXT Only{C.RESET}")
    print(f"\n  {C.YELLOW}🚀 All 5 steps will run automatically...{C.RESET}")

    ST.start_time = time.time()

    # ═══════ STEP 1 ═══════
    print_step(1, "SUBDOMAIN DISCOVERY")

    if args.host_file:
        print(f"  {C.CYAN}📂 Loading: {args.host_file}{C.RESET}")
        try:
            with open(args.host_file) as f:
                hosts = [l.strip() for l in f if l.strip()]
            for h in hosts:
                ip = dns_resolve(h)
                if ip:
                    ST.resolved_hosts[h] = ip
                    ST.discovered_subdomains.add(h)
            print(f"  {C.GREEN}✅ Loaded {len(ST.resolved_hosts)} hosts{C.RESET}")
        except Exception as e:
            print(f"  {C.RED}❌ {e}{C.RESET}")
            return

    elif args.skip_subdomain:
        ip = dns_resolve(domain)
        if ip:
            ST.resolved_hosts[domain] = ip
            ST.discovered_subdomains.add(domain)
            print(f"  {C.GREEN}✅ {domain} → {ip}{C.RESET}")
        else:
            print(f"  {C.RED}❌ Cannot resolve {domain}{C.RESET}")
            return
    else:
        ST.discovered_subdomains = discover_subdomains(domain)

    if not ST.resolved_hosts:
        print(f"  {C.RED}❌ No hosts found. Exiting.{C.RESET}")
        return

    print(f"\n  {C.GREEN}{C.BOLD}🟢 {len(ST.resolved_hosts)} live hosts ready{C.RESET}")

    # ═══════ STEP 2 ═══════
    print_step(2, f"PORT SCANNING ({len(ports)} ports)")
    scan_all_ports(set(ST.resolved_hosts.keys()), ports)

    if not ST.open_ports:
        print(f"\n  {C.YELLOW}⚠️ No open ports found{C.RESET}")
        print_step(5, "REPORT GENERATION")
        generate_report(domain)
        print_final()
        return

    # ═══════ STEP 3 ═══════
    if not args.skip_http:
        print_step(3, "HTTP SERVICE PROBING")
        probe_all_http()

    # ═══════ STEP 4 ═══════
    print_step(4, "HIGH-VALUE TARGET DETECTION")
    detect_high_value()

    # ═══════ STEP 5 ═══════
    print_step(5, "REPORT GENERATION")
    generate_report(domain)

    print_final()


def print_final():
    duration = time.time() - ST.start_time if ST.start_time else 0

    print(f"\n{C.ORANGE}{'━' * 80}{C.RESET}")
    print(f"  {C.BOLD}{C.GREEN}✅ SCAN COMPLETE!{C.RESET}")
    print(f"{C.ORANGE}{'━' * 80}{C.RESET}")
    print(f"  {C.CYAN}⏱️  Duration:{C.RESET}     {duration:.2f}s")
    print(f"  {C.GREEN}🌍 Subdomains:{C.RESET}   {len(ST.resolved_hosts)}")
    print(f"  {C.LIME}🔓 Open Ports:{C.RESET}   {ST.total_open_ports}")
    print(f"  {C.BLUE}🌐 HTTP Services:{C.RESET} {len(ST.http_services)}")

    if ST.high_value_targets:
        print(f"  {C.RED}{C.BOLD}🚨 HIGH-VALUE:{C.RESET}   {C.RED}{len(ST.high_value_targets)}{C.RESET}")
        for t in ST.high_value_targets:
            print(f"     {C.RED}🎯 {t['url']}{C.RESET}")
    else:
        print(f"  {C.GREEN}✅ High-Value:{C.RESET}   None")

    print(f"\n  {C.YELLOW}⚠️  Authorized testing only{C.RESET}\n")


if __name__ == "__main__":
    main()
