  GNU nano 8.4                                                                                                                                                                                                                                                                                                           secret.py                                                                                                                                                                                                                                                                                                                    
import os
import re
import requests
from termcolor import colored

def banner():
    print(colored("""
  ███████╗███████╗ ██████╗███████╗████████╗
  ██╔════╝██╔════╝██╔════╝██╔════╝╚══██╔══╝
  ███████╗█████╗  ██║     █████╗     ██║   
  ╚════██║██╔══╝  ██║     ██╔══╝     ██║   
  ███████║███████╗╚██████╗███████╗   ██║   
  ╚══════╝╚══════╝ ╚═════╝╚══════╝   ╚═╝   
    """, "cyan"))
    print(colored("[+] Secret & Endpoint Scanner - Developed by TehanG07\n", "green"))

def find_secrets(content):
    pattern = re.compile(
        r'''(?i)(?:"|')?                
        (api[_-]?key|access[_-]?key|secret|token|bearer|auth[_-]?key|
        client[_-]?id|private[_-]?key|password|signature|session[_-]?id|
        public|env|portal|exe|dll|authorization|auth|key|cred|credentials|config)     
        (?:["'\s:=]+)                  
        ([a-zA-Z0-9\-_\.\/:=@#\$%\^&\*\(\)\[\]\{\}\|\\]+)  
        (?:"|')?''', re.VERBOSE)
    
    found = []
    for match in pattern.findall(content):
        key = match[0].upper()
        val = match[1].strip()
        if len(val) > 5:
            found.append((key, val))
    return list(set(found))

def find_endpoints(content):
    pattern = re.compile(r'''(?i)(?:["'\s:])(/?(api|v[0-9]+(\.[0-9]+)*|auth|user|admin|portal|session|login|logout|config|users)[^\s"']*)''')
    matches = [match[0] for match in pattern.findall(content)]

    # Clean and format endpoint versions like v1.2.3 or "users"
    cleaned = set()
    for ep in matches:
        ep = ep.strip().lstrip("/")
        if ep:
            parts = ep.split('/')
            for p in parts:
                if p and not p.startswith("{") and len(p) < 50:
                    cleaned.add(p)
    return list(cleaned)

def scan_urls(file_path):
    if not os.path.exists(file_path):
        print(colored("[-] File does not exist!", "red"))
        return

    print(colored("[+] Scanning URLs from file...\n", "blue"))

    with open("scan_results.txt", "w") as out_file:
        with open(file_path, 'r', errors='ignore') as f:
            urls = f.read().splitlines()

        for url in urls:
            try:
                response = requests.get(url, timeout=10)
                print(colored(f"\n[+] Checking: {url}", "magenta"))
                content = response.text

                secrets = find_secrets(content)
                endpoints = find_endpoints(content)

                if secrets or endpoints:
                    out_file.write(f"{url}\n")

                for s in secrets:
                    print(colored(f"    🔐 SECRET => {s[0]} => {s[1]}", "green"))
                    out_file.write(f"SECRET => {s[0]} => {s[1]}\n")

                for ep in endpoints:
                    print(colored(f"    📍 ENDPOINT => {ep}", "blue"))
                    out_file.write(f"ENDPOINT => {ep}\n")

                if secrets or endpoints:
                    out_file.write("=" * 53 + "\n")

            except requests.RequestException as e:
                print(colored(f"[-] Error fetching {url}: {e}", "red"))

def main():
    banner()
    file_path = input(colored("[?] Enter file path containing URLs: ", "yellow"))
    scan_urls(file_path)

if __name__ == "__main__":
    main()


