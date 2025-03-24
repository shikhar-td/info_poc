import os
import sys
import whois
import dns.resolver
import requests
import argparse
import socket
import ssl
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

# Display the scan menu to the user
def show_menu():
    print("\nAvailable Scans:")
    print("1. WHOIS Lookup (Basic Scan)")
    print("2. DNS Records Lookup (Basic Scan)")
    print("3. Geolocation Lookup (Basic Scan)")
    print("4. Banner Grabbing")
    print("5. Email Harvesting")
    print("6. SSL Certificate Information")
    print("7. Directory Bruteforcing")
    print("8. Subdomain Enumeration")
    print("9. Port Scanning")
    print("10. Master Scan (Runs all the above scans)")
    print("11. Exit")
    choice = input("\nEnter the scan number(s) you want to perform (comma-separated, e.g., 1,3,5): ")
    return [int(c.strip()) for c in choice.split(',') if c.strip().isdigit()]

# WHOIS Lookup
def whois_scan(domain, verbose=False):
    print("\n[+] Starting WHOIS Scan...")
    try:
        py = whois.whois(domain)
        result = f"""
        Name: {py.name}
        Registrar: {py.registrar}
        Creation Date: {py.creation_date}
        Expiration Date: {py.expiration_date}
        Registrant Country: {py.registrant_country}
        """
        if verbose:
            print("\n[+] Whois Scan Result:")
        print(result)
    except Exception as e:
        print(f"[-] Whois scan failed: {e}")
    return result

# DNS Records Lookup
def dns_scan(domain, verbose=False):
    print("\n[+] Starting DNS Scan...")
    result = ""
    try:
        for record in ['A', 'NS', 'MX', 'TXT']:
            answers = dns.resolver.resolve(domain, record)
            for answer in answers:
                result += f"{record} Record: {answer.to_text()}\n"
        if verbose:
            print("\n[+] DNS Scan Result:")
        print(result)
    except Exception as e:
        print(f"[-] DNS scan failed: {e}")
    return result

# Geolocation Lookup
def geolocation_scan(domain, verbose=False):
    print("\n[+] Starting Geoloaction Scan...")
    result = ""
    try:
        ip_address = socket.gethostbyname(domain)
        response = requests.get(f"http://geolocation-db.com/json/{ip_address}").json()
        result += f"IP Address: {ip_address}\nCountry: {response['country_name']}\n"
        if verbose:
            print("\n[+] Geolocation Scan Result:")
        print(result)
    except Exception as e:
        print(f"[-] Geolocation scan failed: {e}")
    return result

# Banner Grabbing
def banner_grabbing(domain, verbose=False):
    print("\n[+] Starting Banner Scan...")
    try:
        s = socket.socket()
        s.connect((domain, 80))
        s.send(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % domain.encode())
        banner = s.recv(1024).decode('utf-8')
        if verbose:
            print("\n[+] Banner Grabbed:")
        print(banner)
    except Exception as e:
        print(f"[-] Banner grabbing failed: {e}")
    return banner

# Email Harvesting
def email_harvest(domain, verbose=False):
    print("\n[+] Starting Email Scan...")
    try:
        url = f"http://{domain}"
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        emails = set([a["href"].replace("mailto:", "") for a in soup.find_all("a", href=True) if "mailto:" in a["href"]])
        result = "\n".join(emails) if emails else "No emails found."
        if verbose:
            print("\n[+] Email Harvesting Result:")
        print(result)
    except Exception as e:
        print(f"[-] Email harvesting failed: {e}")
    return result

# SSL Certificate Information
def ssl_cert_info(domain, verbose=False):
    print("\n[+] Starting SSL Cert. Scan...")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result = f"SSL Certificate Issued By: {cert['issuer']}\nExpires: {cert['notAfter']}\n"
                if verbose:
                    print("\n[+] SSL Certificate Info:")
                print(result)
    except Exception as e:
        print(f"[-] SSL Certificate scan failed: {e}")
    return result

# Directory Bruteforcing
def dir_bruteforce(domain, verbose=False):
    print("\n[+] Starting Dir Bruteforce Scan...")
    result = ""
    wordlist_file = "common.txt"  # Using common.txt wordlist
    try:
        with open(wordlist_file, 'r') as file:
            directories = [line.strip() for line in file if line.strip()]
        for directory in directories:
            url = f"http://{domain}/{directory}"
            response = requests.get(url)
            if response.status_code == 200:
                result += f"Found Directory: {url}\n"
        if verbose:
            print("\n[+] Directory Bruteforcing Result:")
        print(result)
    except Exception as e:
        print(f"[-] Directory bruteforcing failed: {e}")
    return result

# Subdomain Enumeration
def subdomain_enum(domain, verbose=False):
    print("\n[+] Starting Sub-Domain Scan...")
    result = ""
    subdomains = ["www", "mail", "ftp", "webmail", "admin"]  # Simple list of subdomains
    try:
        for subdomain in subdomains:
            url = f"{subdomain}.{domain}"
            try:
                ip = socket.gethostbyname(url)
                result += f"Subdomain Found: {url} -> {ip}\n"
            except socket.gaierror:
                pass
        if verbose:
            print("\n[+] Subdomain Enumeration Result:")
        print(result)
    except Exception as e:
        print(f"[-] Subdomain enumeration failed: {e}")
    return result

# Port Scanning
def port_scan(domain, verbose=False):
    print("\n[+] Starting Port Scan...")
    open_ports = []
    try:
        def scan_port(port):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            result = s.connect_ex((domain, port))
            s.close()
            return port if result == 0 else None

        ports_to_scan = range(1, 1025)
        with ThreadPoolExecutor(max_workers=100) as executor:
            open_ports = list(filter(None, executor.map(scan_port, ports_to_scan)))

        result = "Open Ports: " + ", ".join(map(str, open_ports))
        if verbose:
            print("\n[+] Port Scanning Result:")
        print(result)
    except Exception as e:
        print(f"[-] Port scanning failed: {e}")
    return result

# Master Scan - Run all scans
def master_scan(domain, verbose=False):
    print("\n[+] Starting Master Scan...")
    result = ""
    try:
        result += whois_scan(domain, verbose)
        result += dns_scan(domain, verbose)
        result += geolocation_scan(domain, verbose)
        result += banner_grabbing(domain, verbose)
        result += email_harvest(domain, verbose)
        result += ssl_cert_info(domain, verbose)
        result += dir_bruteforce(domain, verbose)
        result += subdomain_enum(domain, verbose)
        result += port_scan(domain, verbose)
    except Exception as e:
        print(f"[-] Error during Master Scan: {e}")
    print("\n[+] Master Scan Complete!")
    return result

def main():
    parser = argparse.ArgumentParser(description="Information Gathering Tool")
    parser.add_argument("-d", "--domain", help="Enter the domain name", required=True)
    parser.add_argument("-o", "--output", help="Output file to save results (optional)")
    parser.add_argument("-v", "--verbose", help="Enable verbose output", action="store_true")
    args = parser.parse_args()

    domain = args.domain
    output_file = args.output
    verbose = args.verbose
    results = ""

    while True:
        choices = show_menu()
        for choice in choices:
            if choice == 1:
                results += whois_scan(domain, verbose)
            elif choice == 2:
                results += dns_scan(domain, verbose)
            elif choice == 3:
                results += geolocation_scan(domain, verbose)
            elif choice == 4:
                results += banner_grabbing(domain, verbose)
            elif choice == 5:
                results += email_harvest(domain, verbose)
            elif choice == 6:
                results += ssl_cert_info(domain, verbose)
            elif choice == 7:
                results += dir_bruteforce(domain, verbose)
            elif choice == 8:
                results += subdomain_enum(domain, verbose)
            elif choice == 9:
                results += port_scan(domain, verbose)
            elif choice == 10:
                results += master_scan(domain, verbose)
            elif choice == 11:
                sys.exit("\nExiting the tool. Goodbye!")
            else:
                print(f"Invalid choice: {choice}")

        if output_file:
            with open(output_file, "w") as file:
                file.write(results)
                print(f"\n[+] Results saved to {output_file}")

        if input("\nRun more scans? (y/n): ").lower() != 'y':
            sys.exit("\nExiting. Goodbye!")

if __name__ == "__main__":
    main()
