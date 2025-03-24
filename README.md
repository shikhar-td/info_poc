# InfoPoc - Information Gathering Tool

## Description
InfoGatherer is a Python-based information-gathering tool designed to perform various reconnaissance scans on a target domain. It includes WHOIS lookups, DNS scans, geolocation, banner grabbing, subdomain enumeration, port scanning, and more.

## Features
- WHOIS Lookup
- DNS Records Lookup (A, NS, MX, TXT)
- Geolocation Lookup
- Banner Grabbing
- Email Harvesting
- SSL Certificate Information
- Directory Bruteforcing
- Subdomain Enumeration
- Port Scanning
- Master Scan (Runs all the above scans)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/InfoGatherer.git
   cd InfoGatherer

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt

4. Usage
Run the tool with the following command:
   ```bash
   python3 info_gathering.py -d <target_domain> [options]
   
   Option	Description
   -d	Specify the target domain (required).
   -o	Save scan results to an output file.
   -v	Enable verbose output (detailed logging).
   -h or --help	Display usage instructions.


