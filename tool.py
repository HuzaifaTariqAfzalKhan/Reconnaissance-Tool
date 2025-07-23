#!/usr/bin/env python3

import whois, dns.resolver, requests, socket, subprocess, os
from datetime import datetime

# WHOIS Lookup
def whois_lookup(domain):
    try: return str(whois.whois(domain))
    except: return "WHOIS lookup failed."

# DNS Records
def get_dns_records(domain):
    records = {}
    for rtype in ['A', 'MX', 'TXT', 'NS']:
        try: records[rtype] = [r.to_text() for r in dns.resolver.resolve(domain, rtype)]
        except: records[rtype] = []
    return records

# Subdomain Enumeration (crt.sh)
def get_subdomains(domain):
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        return list({sub.strip() for entry in r.json() for sub in entry['name_value'].split('\n') if domain in sub})
    except: return []

# Port Scan with Nmap
def scan_ports_nmap(domain):
    try: return subprocess.check_output(['nmap', '-T4', '-F', domain], stderr=subprocess.DEVNULL).decode()
    except: return "Nmap scan failed."

# Banner Grabbing
def grab_banner(ip, port):
    try:
        s = socket.socket(); s.settimeout(1); s.connect((ip, port))
        banner = s.recv(1024).decode(errors='ignore').strip(); s.close()
        return banner
    except: return "No banner"

# Tech Detection via HTTP Headers
def detect_technologies(domain):
    try: return dict(requests.get(f"http://{domain}", timeout=5).headers)
    except: return {}

# Write Report
def write_report(domain, data):
    os.makedirs("reports", exist_ok=True)
    with open(f"reports/{domain}_report.txt", 'w') as f:
        f.write(f"Recon Report for {domain}\nGenerated: {datetime.now()}\n\n")
        for section, content in data.items():
            f.write(f"--- {section.upper()} ---\n")
            if isinstance(content, dict): f.writelines([f"{k}: {v}\n" for k, v in content.items()])
            elif isinstance(content, list): f.writelines([f"- {item}\n" for item in content])
            else: f.write(f"{content}\n")
            f.write("\n")

# Main Menu
def main():
    domain = input("Target domain (e.g., example.com): ")
    report = {}
    while True:
        print("\n1.WHOIS 2.DNS 3.Subdomains 4.Nmap 5.Banners 6.Tech 7.Report & Exit")
        choice = input("Choose (1-7): ")
        if choice == "1": report['whois'] = whois_lookup(domain)
        elif choice == "2": report['dns'] = get_dns_records(domain)
        elif choice == "3": report['subdomains'] = get_subdomains(domain)
        elif choice == "4": report['nmap'] = scan_ports_nmap(domain)
        elif choice == "5":
            ip = socket.gethostbyname(domain)
            report['banners'] = {p: grab_banner(ip, p) for p in [80, 443, 21, 22, 25, 3306]}
        elif choice == "6": report['technologies'] = detect_technologies(domain)
        elif choice == "7": write_report(domain, report); print("Report generated."); break
        else: print("Invalid option.")

if __name__ == "__main__": main()
