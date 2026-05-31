#!/usr/bin/env python3

import subprocess
import sys
import os
import json
import re
import urllib.request
import urllib.error
from datetime import datetime

# ─────────────────────────────────────────────
#  ANSI Colors
# ─────────────────────────────────────────────
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

# ─────────────────────────────────────────────
#  Banner
# ─────────────────────────────────────────────
def print_banner():
    banner = f"""
{CYAN}{BOLD}
  ████████╗███████╗██╗  ██╗ █████╗ ███╗   ██╗ ██████╗  ██████╗ ███████╗
  ╚══██╔══╝██╔════╝██║  ██║██╔══██╗████╗  ██║██╔════╝ ██╔═████╗╚════██║
     ██║   █████╗  ███████║███████║██╔██╗ ██║██║  ███╗██║██╔██║    ██╔╝
     ██║   ██╔══╝  ██╔══██║██╔══██║██║╚██╗██║██║   ██║████╔╝██║   ██╔╝ 
     ██║   ███████╗██║  ██║██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝   ██║  
     ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝   ╚═╝  
{RESET}
{MAGENTA}{BOLD}
  ███████╗██╗   ██╗██████╗ ████████╗ █████╗ ██╗  ██╗███████╗ ██████╗ ██╗  ██╗
  ██╔════╝██║   ██║██╔══██╗╚══██╔══╝██╔══██╗██║ ██╔╝██╔════╝██╔═████╗╚██╗██╔╝
  ███████╗██║   ██║██████╔╝   ██║   ███████║█████╔╝ █████╗  ██║██╔██║ ╚███╔╝ 
  ╚════██║██║   ██║██╔══██╗   ██║   ██╔══██║██╔═██╗ ██╔══╝  ████╔╝██║ ██╔██╗ 
  ███████║╚██████╔╝██████╔╝   ██║   ██║  ██║██║  ██╗███████╗╚██████╔╝██╔╝ ██╗
  ╚══════╝ ╚═════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
{RESET}
{YELLOW}{'─'*78}
{BOLD}  Subdomain Takeover Detection Tool
{RESET}{YELLOW}  Owner  : {CYAN}{BOLD}TehanG07{RESET}
{YELLOW}  Purpose: Detect dangling DNS records vulnerable to subdomain takeover
{YELLOW}  Source  : github.com/edoverflow/can-i-take-over-xyz
{YELLOW}{'─'*78}{RESET}
"""
    print(banner)

# ─────────────────────────────────────────────
#  Fetch fingerprint database from GitHub
# ─────────────────────────────────────────────
FINGERPRINTS_URL = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"

def fetch_fingerprints():
    print(f"{CYAN}[*]{RESET} Fetching fingerprint database from EdOverflow/can-i-take-over-xyz ...")
    try:
        req = urllib.request.Request(FINGERPRINTS_URL, headers={"User-Agent": "SubTakeoverScanner/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        print(f"{GREEN}[+]{RESET} Loaded {BOLD}{len(data)}{RESET} service fingerprints.\n")
        return data
    except Exception as e:
        print(f"{YELLOW}[!]{RESET} Could not fetch fingerprints: {e}")
        print(f"{YELLOW}[!]{RESET} Continuing with CNAME-only detection (no fingerprint matching).\n")
        return []

# ─────────────────────────────────────────────
#  Check dependencies
# ─────────────────────────────────────────────
def check_tool(name):
    result = subprocess.run(["which", name], capture_output=True, text=True)
    return result.returncode == 0

def check_dependencies():
    missing = []
    for tool in ["subfinder", "httpx", "nslookup", "curl"]:
        if not check_tool(tool):
            missing.append(tool)
    if missing:
        print(f"{RED}[!]{RESET} Missing tools: {', '.join(missing)}")
        print(f"{YELLOW}    Install guides:{RESET}")
        if "subfinder" in missing:
            print(f"      subfinder : go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        if "httpx" in missing:
            print(f"      httpx     : go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
        sys.exit(1)
    print(f"{GREEN}[+]{RESET} All dependencies found.\n")

# ─────────────────────────────────────────────
#  Step 1: Subdomain enumeration
# ─────────────────────────────────────────────
def enumerate_subdomains(domain):
    print(f"{CYAN}[*]{RESET} {BOLD}Step 1:{RESET} Enumerating subdomains for {BOLD}{domain}{RESET} using subfinder ...")
    cmd = ["subfinder", "-d", domain, "-silent"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    subs = [s.strip() for s in result.stdout.splitlines() if s.strip()]
    with open("sub.txt", "w") as f:
        f.write("\n".join(subs))
    print(f"{GREEN}[+]{RESET} Found {BOLD}{len(subs)}{RESET} subdomains → saved to {BOLD}sub.txt{RESET}\n")
    return subs

# ─────────────────────────────────────────────
#  Step 2: Find dead subdomains via httpx
# ─────────────────────────────────────────────
def find_dead_subdomains():
    print(f"{CYAN}[*]{RESET} {BOLD}Step 2:{RESET} Probing subdomains for HTTP 404 responses using httpx ...")
    if not os.path.exists("sub.txt") or os.path.getsize("sub.txt") == 0:
        print(f"{YELLOW}[!]{RESET} sub.txt is empty. No subdomains to probe.\n")
        return []

    cmd = ["httpx", "-l", "sub.txt", "-mc", "404", "-silent"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    dead = [s.strip() for s in result.stdout.splitlines() if s.strip()]

    # Strip http:// or https:// for nslookup
    dead_clean = []
    for d in dead:
        d = re.sub(r'^https?://', '', d).rstrip('/')
        dead_clean.append(d)

    with open("dead.txt", "w") as f:
        f.write("\n".join(dead_clean))

    print(f"{GREEN}[+]{RESET} Found {BOLD}{len(dead_clean)}{RESET} dead subdomains (404) → saved to {BOLD}dead.txt{RESET}\n")
    return dead_clean

# ─────────────────────────────────────────────
#  Step 3: nslookup CNAME check
# ─────────────────────────────────────────────
def extract_cname(subdomain):
    """Run nslookup and extract CNAME/canonical name if present."""
    result = subprocess.run(["nslookup", subdomain], capture_output=True, text=True)
    output = result.stdout + result.stderr
    cnames = []
    for line in output.splitlines():
        line_lower = line.lower()
        if "canonical name" in line_lower or ("cname" in line_lower and "=" in line):
            # Parse canonical name
            if "=" in line:
                cname = line.split("=")[-1].strip().rstrip(".")
                cnames.append(cname)
            elif "canonical name" in line_lower:
                parts = line.split("=") if "=" in line else line.split(":")
                if len(parts) > 1:
                    cname = parts[-1].strip().rstrip(".")
                    cnames.append(cname)
    return cnames, output

# ─────────────────────────────────────────────
#  Step 4: Fingerprint matching
# ─────────────────────────────────────────────
def match_fingerprint(subdomain, cnames, fingerprints):
    """Try to match CNAME against known vulnerable service fingerprints."""
    matches = []
    for fp in fingerprints:
        service   = fp.get("service", "Unknown")
        cname_pat = fp.get("cname", [])
        fingerprt = fp.get("fingerprint", "")
        vulnerable = fp.get("vulnerable", False)
        status    = fp.get("status", "")

        if isinstance(cname_pat, str):
            cname_pat = [cname_pat]

        # Check if any CNAME matches a known service pattern
        for cn in cnames:
            for pat in cname_pat:
                if pat and pat.lower() in cn.lower():
                    matches.append({
                        "service": service,
                        "cname": cn,
                        "pattern": pat,
                        "fingerprint": fingerprt,
                        "vulnerable": vulnerable,
                        "status": status
                    })
    return matches

def curl_fingerprint_check(subdomain, fingerprint_string):
    """Use curl to fetch the subdomain and check if fingerprint string is present."""
    if not fingerprint_string:
        return False, ""
    try:
        result = subprocess.run(
            ["curl", "-sk", "--max-time", "8", "-L", f"http://{subdomain}"],
            capture_output=True, text=True
        )
        body = result.stdout
        if fingerprint_string.lower() in body.lower():
            return True, body[:300]
        return False, body[:300]
    except Exception:
        return False, ""

# ─────────────────────────────────────────────
#  Main scan logic
# ─────────────────────────────────────────────
def scan(dead_subdomains, fingerprints):
    print(f"{CYAN}[*]{RESET} {BOLD}Step 3:{RESET} Running nslookup + fingerprint checks on {len(dead_subdomains)} dead subdomains ...\n")
    print(f"{'─'*78}")

    vulnerable_results = []
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    for sub in dead_subdomains:
        print(f"{DIM}  [~] Checking: {sub}{RESET}", end=" ... ", flush=True)

        cnames, raw_nslookup = extract_cname(sub)

        if not cnames:
            print(f"{DIM}no CNAME{RESET}")
            continue

        print(f"\n{YELLOW}  [CNAME]{RESET} {sub} → {', '.join(cnames)}")

        # Match fingerprints
        matches = match_fingerprint(sub, cnames, fingerprints) if fingerprints else []

        if not matches:
            # Still has CNAME but no known fingerprint — worth noting
            entry = {
                "subdomain": sub,
                "cnames": cnames,
                "service": "Unknown",
                "fingerprint_matched": False,
                "vulnerable": "Unknown",
                "note": "CNAME detected but no fingerprint match"
            }
            vulnerable_results.append(entry)
            print(f"{YELLOW}  [?] CNAME found but no service fingerprint matched. May still be vulnerable.{RESET}")
            continue

        for m in matches:
            # Curl check for fingerprint string on the page
            fp_matched, curl_body = curl_fingerprint_check(sub, m["fingerprint"])

            vuln_flag = m["vulnerable"] and fp_matched

            entry = {
                "subdomain": sub,
                "cnames": cnames,
                "service": m["service"],
                "cname_pattern": m["pattern"],
                "fingerprint": m["fingerprint"],
                "fingerprint_matched": fp_matched,
                "vulnerable": vuln_flag,
                "status": m["status"]
            }
            vulnerable_results.append(entry)

            if vuln_flag:
                print(f"\n{RED}{BOLD}  ╔══════════════════════════════════════════════════════════╗")
                print(f"  ║  ⚠  VULNERABLE: {sub:<42}║")
                print(f"  ║  Service  : {m['service']:<46}║")
                print(f"  ║  CNAME    : {cnames[0][:46]:<46}║")
                print(f"  ║  FP Match : {'YES':<46}║")
                print(f"  ║  Status   : {m['status'][:46]:<46}║")
                print(f"  ╚══════════════════════════════════════════════════════════╝{RESET}\n")
            elif m["vulnerable"] and not fp_matched:
                print(f"{YELLOW}  [~] Possible ({m['service']}): CNAME matches but fingerprint NOT found on page.{RESET}")
            else:
                print(f"{GREEN}  [✓] {m['service']}: CNAME matched but service marked NOT vulnerable.{RESET}")

    print(f"\n{'─'*78}")
    return vulnerable_results, timestamp

# ─────────────────────────────────────────────
#  Save results
# ─────────────────────────────────────────────
def save_results(results, timestamp):
    confirmed    = [r for r in results if r.get("vulnerable") is True]
    possible     = [r for r in results if r.get("vulnerable") == "Unknown"]
    not_vuln_fp  = [r for r in results if r.get("vulnerable") is False and r.get("fingerprint_matched") is False]

    outfile = f"vulnerable_{timestamp}.txt"
    with open(outfile, "w") as f:
        f.write(f"SubTakeover Scan Results — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("Owner: TehanG07\n")
        f.write("="*70 + "\n\n")

        f.write(f"CONFIRMED VULNERABLE ({len(confirmed)})\n")
        f.write("-"*50 + "\n")
        for r in confirmed:
            f.write(f"[VULNERABLE] {r['subdomain']}\n")
            f.write(f"  Service     : {r['service']}\n")
            f.write(f"  CNAME       : {', '.join(r['cnames'])}\n")
            f.write(f"  FP Matched  : Yes\n")
            f.write(f"  Status      : {r.get('status','')}\n\n")

        f.write(f"\nPOSSIBLE (CNAME found, no fingerprint match) ({len(possible)})\n")
        f.write("-"*50 + "\n")
        for r in possible:
            f.write(f"[POSSIBLE] {r['subdomain']}\n")
            f.write(f"  CNAME  : {', '.join(r['cnames'])}\n\n")

        f.write(f"\nCNAME MATCH BUT FINGERPRINT NOT ON PAGE ({len(not_vuln_fp)})\n")
        f.write("-"*50 + "\n")
        for r in not_vuln_fp:
            f.write(f"[FP-MISS] {r['subdomain']}\n")
            f.write(f"  Service : {r['service']}\n")
            f.write(f"  CNAME   : {', '.join(r['cnames'])}\n\n")

    print(f"\n{GREEN}[+]{RESET} Results saved to {BOLD}{outfile}{RESET}")
    return outfile, len(confirmed), len(possible)

# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────
def main():
    print_banner()
    check_dependencies()

    # Fetch fingerprint DB
    fingerprints = fetch_fingerprints()

    # Ask for domain
    print(f"{CYAN}{BOLD}Enter target domain{RESET} (e.g. example.com): ", end="")
    domain = input().strip()
    if not domain:
        print(f"{RED}[!]{RESET} No domain provided. Exiting.")
        sys.exit(1)
    print()

    # Pipeline
    enumerate_subdomains(domain)
    dead = find_dead_subdomains()

    if not dead:
        print(f"{YELLOW}[!]{RESET} No dead subdomains found. Nothing to check.\n")
        sys.exit(0)

    results, ts = scan(dead, fingerprints)
    outfile, n_vuln, n_possible = save_results(results, ts)

    # Summary
    print(f"\n{CYAN}{BOLD}  ┌─ Scan Summary ──────────────────────────────────────┐{RESET}")
    print(f"{CYAN}{BOLD}  │{RESET}  Target          : {BOLD}{domain}{RESET}")
    print(f"{CYAN}{BOLD}  │{RESET}  Dead subdomains : {BOLD}{len(dead)}{RESET}")
    print(f"{CYAN}{BOLD}  │{RESET}  {RED}{BOLD}Confirmed vuln  : {n_vuln}{RESET}")
    print(f"{CYAN}{BOLD}  │{RESET}  {YELLOW}Possible vuln   : {n_possible}{RESET}")
    print(f"{CYAN}{BOLD}  │{RESET}  Output file     : {BOLD}{outfile}{RESET}")
    print(f"{CYAN}{BOLD}  └────────────────────────────────────────────────────┘{RESET}\n")

if __name__ == "__main__":
    main()
