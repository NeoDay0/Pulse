#!/usr/bin/env python3
import argparse
import socket
from queue import Queue
from threading import Thread, Lock
import sys
import json
from datetime import datetime
import http.client
import ssl
import time
import struct
import re

# --- Colors ---
class C:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

BANNER = f"""{C.PURPLE}{C.BOLD}
                               ,---.
                              /    |
                             /     |
   ,---.  ,--,--. ,---.      /      |
  / .-. | |      | .-. |    /       |
 .\' '-'| | \\/\, | '-' '   /        |
 `----\'  `--\'--\' `---/   `--------\'
                 `---'              
        --- {C.END}{C.PURPLE}Pulse Security Toolkit{C.END}{C.PURPLE} ---
{C.END}"""

# The PulseTool Class remains the same as the previous version.
# All scanning logic is contained within it.
class PulseTool:
    # ... [The entire, complete PulseTool class from the previous step goes here] ...
    def __init__(self, args):
        self.args = args
        self.target = args.target
        self.target_ip = self._validate_host(self.target)
        self.queue = Queue()
        self.lock = Lock()
        self.start_time = datetime.now()
        self.open_ports = []
        self.web_results = {}
        self.found_subdomains = []
        self.udp_results = []
        self.vulnerabilities = []

    def _validate_host(self, host):
        try: return socket.gethostbyname(host)
        except socket.gaierror: print(f"{C.RED}[-] Error: Hostname '{host}' could not be resolved.{C.END}"); sys.exit(1)

    def run(self):
        print("-" * 60)
        print(f"{C.BLUE}[*] Target: {self.target} | Mode: {self.args.mode}{C.END}")
        print(f"{C.BLUE}[*] Time started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}{C.END}")
        print("-" * 60)
        if self.args.mode == 'portscan':
            if self.args.udp: self._run_udp_scan()
            else:
                self._run_tcp_scan()
                if self.args.web_enum: self._run_web_enum()
                if self.args.vuln_scan: self._run_vuln_scan()
        elif self.args.mode == 'subdomain': self._run_subdomain_mode()
        self._print_report()
        self._write_output()
        print("-" * 60)
    def _parse_ports(self):
        ports_to_scan = set()
        try:
            for r in (r.split("-") for r in self.args.port_range.split(",")):
                if len(r) == 1: ports_to_scan.add(int(r[0]))
                elif len(r) == 2: ports_to_scan.update(range(int(r[0]), int(r[1]) + 1))
            return list(ports_to_scan)
        except ValueError: print(f"{C.RED}[-] Invalid port range: '{self.args.port_range}'{C.END}"); sys.exit(1)
    def _run_tcp_scan(self):
        print(f"{C.CYAN}[*] Starting TCP Port Scan...{C.END}")
        ports_to_scan = self._parse_ports()
        for port in ports_to_scan: self.queue.put(port)
        threads = [Thread(target=self._scan_tcp_worker, daemon=True) for _ in range(min(100, len(ports_to_scan)))]
        for t in threads: t.start()
        self.queue.join()
        print(f"{C.CYAN}[*] TCP Port Scan Finished.{C.END}")
    def _scan_tcp_worker(self):
        while not self.queue.empty():
            port = self.queue.get()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex((self.target_ip, port)) == 0:
                        try: banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        except socket.timeout: banner = "No banner received"
                        with self.lock:
                            first_line = banner.splitlines()[0] if banner else "N/A"
                            print(f"{C.GREEN}[+]{C.END} Port {C.BOLD}{port:<5}{C.END} is open   |   Service: {C.YELLOW}{first_line}{C.END}")
                            self.open_ports.append({'port': port, 'service': banner})
            except Exception: pass
            finally: self.queue.task_done()
    def _run_udp_scan(self):
        print(f"{C.CYAN}[*] Starting UDP Scan... (This may require sudo and be slow){C.END}")
        self.closed_udp_ports = set(); self.permission_error = False
        listener_thread = Thread(target=self._icmp_listener, daemon=True); listener_thread.start()
        time.sleep(0.5)
        if self.permission_error: print(f"\n{C.RED}[-] PERMISSION ERROR: Cannot create raw socket.\n[-] Please try running the UDP scan with 'sudo'.{C.END}"); self.listening = False; return
        ports_to_scan = self._parse_ports()
        for port in ports_to_scan: self.queue.put(port)
        for _ in range(50): Thread(target=self._udp_sender, daemon=True).start()
        self.queue.join(); time.sleep(3); self.listening = False; listener_thread.join()
        for port in ports_to_scan:
            if port not in self.closed_udp_ports: self.udp_results.append(port)
        print(f"{C.CYAN}[*] UDP Scan Finished.{C.END}")
    def _icmp_listener(self):
        self.listening = True
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as icmp_sock:
                icmp_sock.settimeout(1)
                while self.listening:
                    try:
                        data, addr = icmp_sock.recvfrom(1024)
                        if addr[0] == self.target_ip:
                            icmp_header = struct.unpack('!BBHHH', data[20:28])
                            if icmp_header[0] == 3 and icmp_header[1] == 3:
                                udp_header = struct.unpack('!HHHH', data[28:36])
                                with self.lock: self.closed_udp_ports.add(udp_header[1])
                    except socket.timeout: continue
        except PermissionError: 
            with self.lock: self.permission_error = True
        except Exception: pass
    def _udp_sender(self):
        while not self.queue.empty():
            port = self.queue.get()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s: s.sendto(b'', (self.target_ip, port))
            except Exception: pass
            finally: self.queue.task_done()
    def _run_web_enum(self):
        print(f"\n{C.CYAN}[*] Starting Web Content Enumeration...{C.END}")
        http_ports = [p['port'] for p in self.open_ports if 'http' in p['service'].lower() or p['port'] in [80, 443, 8000, 8080]]
        if not http_ports: print(f"{C.YELLOW}[-] No HTTP services found to enumerate.{C.END}"); return
        try:
            with open(self.args.wordlist, 'r') as f: wordlist = f.readlines()
        except FileNotFoundError: print(f"{C.RED}[-] Error: Wordlist file not found at '{self.args.wordlist}'{C.END}"); return
        for port in http_ports:
            print(f"{C.BLUE}[*] Enumerating content on port {port}...{C.END}")
            for word in wordlist: self.queue.put((port, word.strip()))
            for _ in range(50): Thread(target=self._web_enum_worker, daemon=True).start()
            self.queue.join()
        print(f"{C.CYAN}[*] Web Content Enumeration Finished.{C.END}")
    def _web_enum_worker(self):
        while not self.queue.empty():
            port, path = self.queue.get()
            path = path.strip()
            if not path.startswith('/'): path = '/' + path
            try:
                is_https = port == 443 or any('https' in p.get('service', '').lower() for p in self.open_ports if p['port'] == port)
                conn_class = http.client.HTTPSConnection if is_https else http.client.HTTPConnection
                context = ssl._create_unverified_context() if is_https else None
                conn = conn_class(self.target, port, timeout=5, context=context)
                conn.request("GET", path); status = conn.getresponse().status
                if status in [200, 204, 301, 302, 307, 401, 403]:
                    with self.lock:
                        url_scheme = 'https' if is_https else 'http'
                        print(f"{C.GREEN}[+]{C.END} Web content found: {url_scheme}://{self.target}:{port}{path} (Status: {C.YELLOW}{status}{C.END})")
                        self.web_results.setdefault(port, []).append({'path': path, 'status': status})
                conn.close()
            except Exception: pass
            finally: self.queue.task_done()
    def _run_subdomain_mode(self):
        print(f"{C.CYAN}[*] Starting Subdomain Enumeration...{C.END}")
        try:
            with open(self.args.wordlist, 'r') as f: wordlist = f.readlines()
        except FileNotFoundError: print(f"{C.RED}[-] Error: Wordlist file not found at '{self.args.wordlist}'{C.END}"); return
        for word in wordlist: self.queue.put(word.strip())
        for _ in range(100): Thread(target=self._subdomain_worker, daemon=True).start()
        self.queue.join()
        print(f"{C.CYAN}[*] Subdomain Enumeration Finished.{C.END}")
    def _subdomain_worker(self):
        while not self.queue.empty():
            sub = self.queue.get()
            domain = f"{sub}.{self.target}"
            try:
                ip = socket.gethostbyname(domain)
                with self.lock:
                    print(f"{C.GREEN}[+]{C.END} Subdomain found: {C.BOLD}{domain:<40}{C.END} ({C.YELLOW}{ip}{C.END})")
                    self.found_subdomains.append({'subdomain': domain, 'ip': ip})
            except socket.gaierror: pass
            finally: self.queue.task_done()
    def _run_vuln_scan(self):
        print(f"\n{C.CYAN}[*] Starting Vulnerability Scan...{C.END}")
        try:
            with open('vulns.json', 'r') as f: vuln_db = json.load(f)
        except FileNotFoundError: print(f"{C.RED}[-] Vulnerability database 'vulns.json' not found.{C.END}"); return
        except json.JSONDecodeError: print(f"{C.RED}[-] Could not decode 'vulns.json'.{C.END}"); return
        for port_info in self.open_ports:
            service_banner = port_info.get('service', '').lower()
            if not service_banner: continue
            for service_name, vulnerabilities in vuln_db.items():
                if service_name in service_banner:
                    version_match = re.search(r'(\d+\.\d+\.\d+)', service_banner) or re.search(r'(\d+\.\d+)', service_banner)
                    if version_match:
                        detected_version = version_match.group(1)
                        for vuln in vulnerabilities:
                            if detected_version in vuln['versions']:
                                with self.lock:
                                    vuln_found = {'port': port_info['port'], 'service_name': service_name, 'detected_version': detected_version, 'vulnerability': vuln}
                                    print(f"{C.RED}{C.BOLD}[!] Vulnerability Found on port {port_info['port']}! CVE: {vuln['cve']}{C.END}")
                                    self.vulnerabilities.append(vuln_found)
        print(f"{C.CYAN}[*] Vulnerability Scan Finished.{C.END}")
    def _print_report(self):
        print(f"\n{C.BLUE}{C.BOLD}{C.UNDERLINE}Scan Complete. Final Report:{C.END}")
        if self.args.mode == 'portscan':
            if self.args.udp:
                if self.udp_results: print(f"\n{C.GREEN}--- Open|Filtered UDP Ports ---{C.END}\n" + ', '.join(map(str, sorted(self.udp_results))))
                else: print(f"\n{C.YELLOW}No Open|Filtered UDP ports found.{C.END}")
            else:
                if self.open_ports: 
                    print(f"\n{C.GREEN}--- Open TCP Ports ---{C.END}"); print(f"{C.BOLD}{'PORT':<10}{'SERVICE'}{C.END}"); print(f"{'-'*4:<10}{'-'*7}")
                    for p in sorted(self.open_ports, key=lambda x: x['port']): print(f"{p['port']:<10}{C.YELLOW}{p['service'].splitlines()[0] if p['service'] else 'N/A'}{C.END}")
                else: print(f"\n{C.YELLOW}No open TCP ports found.{C.END}")
                if self.web_results: 
                    print(f"\n{C.GREEN}--- Web Content Found ---{C.END}")
                    for port, findings in self.web_results.items():
                        print(f"  {C.BOLD}Port {port}:{C.END}")
                        for f in findings: print(f"    - {f['path']} (Status: {C.YELLOW}{f['status']}{C.END})")
        elif self.args.mode == 'subdomain':
            if self.found_subdomains: 
                print(f"\n{C.GREEN}--- Found Subdomains ---{C.END}")
                for s in sorted(self.found_subdomains, key=lambda x: x['subdomain']): print(f"  - {C.BOLD}{s['subdomain']:<40}{C.END} ({C.YELLOW}{s['ip']}{C.END})")
            else: print(f"\n{C.YELLOW}No subdomains found.{C.END}")
        if self.vulnerabilities: 
            print(f"\n{C.RED}{C.BOLD}--- VULNERABILITIES FOUND ---{C.END}")
            for v in self.vulnerabilities: 
                print(f"  {C.RED}[!] Port {v['port']} ({v['service_name']} {v['detected_version']}){C.END}")
                print(f"      {C.BOLD}CVE:{C.END} {v['vulnerability']['cve']}")
                print(f"      {C.BOLD}Description:{C.END} {v['vulnerability']['description']}")
    def _write_output(self):
        if not self.args.output_file: return
        results = {'target': self.target, 'mode': self.args.mode, 'start_time': self.start_time.strftime('%Y-%m-%d %H:%M:%S'), 'end_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        if self.args.mode == 'portscan':
            if self.args.udp: results['open_filtered_udp_ports'] = sorted(self.udp_results)
            else:
                results['open_tcp_ports'] = sorted(self.open_ports, key=lambda x: x['port'])
                results['web_enumeration'] = self.web_results
                results['vulnerabilities'] = self.vulnerabilities
        elif self.args.mode == 'subdomain':
            results['found_subdomains'] = sorted(self.found_subdomains, key=lambda x: x['subdomain'])
        try:
            with open(self.args.output_file, 'w') as f: json.dump(results, f, indent=4)
            print(f"\n{C.GREEN}[+] Scan results saved to {self.args.output_file}{C.END}")
        except IOError as e: print(f"{C.RED}[-] Error writing to file: {e}{C.END}")

def run_interactive_mode():
    print(BANNER)
    while True:
        print(f"\n{C.BLUE}{C.BOLD}--- Interactive Menu ---{C.END}")
        print("1. TCP Port Scan")
        print("2. UDP Port Scan")
        print("3. Subdomain Enumeration")
        print(f"4. {C.YELLOW}Exit{C.END}")
        choice = input(f"\nEnter your choice (1-4): ")

        if choice == '4': sys.exit(0)
        if choice not in ['1', '2', '3']: print(f"{C.RED}Invalid choice, please try again.{C.END}"); continue

        target = input("Enter the target domain/IP: ")
        
        # Set default args
        args = argparse.Namespace(target=target, mode=None, output_file=None, port_range='1-1024', udp=False, web_enum=False, vuln_scan=False, wordlist='default-wordlist.txt')

        if choice == '1': # TCP Scan
            args.mode = 'portscan'
            args.port_range = input(f"Enter port range (default: 1-1024): ") or '1-1024'
            args.web_enum = input("Perform web enumeration? (y/n): ").lower() == 'y'
            args.vuln_scan = input("Perform vulnerability scan? (y/n): ").lower() == 'y'

        elif choice == '2': # UDP Scan
            print(f"{C.YELLOW}Note: UDP scan requires sudo privileges.{C.END}")
            args.mode = 'portscan'
            args.udp = True
            args.port_range = input(f"Enter port range (default: 1-1024): ") or '1-1024'

        elif choice == '3': # Subdomain Scan
            args.mode = 'subdomain'
            args.wordlist = input(f"Enter wordlist path (default: subdomain-wordlist.txt): ") or 'subdomain-wordlist.txt'

        output_file = input("Save results to file? (e.g., results.json or leave blank): ")
        if output_file: args.output_file = output_file

        PulseTool(args).run()
        input("\nPress Enter to return to the menu...")

def main():
    # If run with arguments, parse them as usual
    if len(sys.argv) > 1:
        epilog = f""" ... [epilog from previous step] ... """
        parser = argparse.ArgumentParser(description=f"{C.BLUE}Pulse - A multi-function cyber security tool.{C.END}", formatter_class=argparse.RawTextHelpFormatter, epilog=epilog)
        # ... [the entire argparse setup from the previous step goes here] ...
        parser.add_argument("target", nargs='?', default=None, help="The target host or domain.")
        # ...
        args = parser.parse_args()
        if not args.target:
            parser.print_help()
            sys.exit(0)
        PulseTool(args).run()
    else:
        # If no arguments, run interactive mode
        run_interactive_mode()

if __name__ == "__main__":
    main()
