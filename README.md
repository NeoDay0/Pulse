
![pulse](https://github.com/user-attachments/assets/197c7842-c66f-415f-b1d2-5c4539ee2fa7)


`pulse.py` bundles TCP/UDP port scanning, web enumeration, sub-domain discovery, and offline vulnerability fingerprinting into a single Python script, with both interactive and fully scriptable CLI modes. :contentReference[oaicite:0]{index=0}

---

## ✨ Features
| Module | Highlights |
|--------|------------|
| **Port Scanner** | • Multithreaded TCP scan with banner grabbing<br>• Optional UDP scan (ICMP listener, sudo needed) :contentReference[oaicite:1]{index=1} |
| **Web Enumerator** | • Crawls discovered HTTP/HTTPS ports with a custom wordlist<br>• Detects 200/301/302/401/403/204/307 responses and prints live URLs :contentReference[oaicite:2]{index=2} |
| **Sub-domain Finder** | • Brute-force mode using any wordlist you provide |
| **Vuln Scanner** | • Looks up banners against a local `vulns.json` database (no API keys!) and flags matching CVEs :contentReference[oaicite:3]{index=3} |
| **Output & UX** | • Colourised console, JSON report writer, interactive menu, and graceful error handling |

---

## 🚀 Quick Start

```bash
git clone https://github.com/<your-user>/pulse.git
cd pulse
# Optional: create an isolated env
python3 -m venv venv && source venv/bin/activate
# No external deps required; install colour support on Windows if you like:
pip install colorama

1. Fully Interactive

python3 pulse.py

2. CLI Power-User Examples
Goal	Command
Fast TCP scan 1-1000 + web enum + vuln scan	python3 pulse.py example.com --mode portscan --port-range 1-1000 --web-enum --vuln-scan --output results.json
UDP scan (53 & 500-510) requires sudo	sudo python3 pulse.py example.com --mode portscan --udp --port-range 53,500-510
Sub-domain brute force	python3 pulse.py example.com --mode subdomain --wordlist wordlists/subdomains.txt --output subs.json
⚙️ CLI Reference

usage: pulse.py target [options]

Positional:
  target                    Domain or IP to scan

Modes:
  --mode {portscan,subdomain}  (default: interactive menu)

Port/Protocol:
  --udp                       Perform UDP (not TCP) scan
  --port-range 1-1024         Comma-separated list and/or ranges (e.g. 22,80,443,8000-8100)

Web Enu​m:
  --web-enum                  Probe found HTTP[S] services with a wordlist
  --wordlist <file>           Path to wordlist (default: *default-wordlist.txt*)

Vulnerability:
  --vuln-scan                 Match banners against local *vulns.json*

Output:
  --output <file>             Save a JSON report

Misc:
  -h, --help                  Show full help

📄 JSON Report Format

{
  "target": "example.com",
  "mode": "portscan",
  "start_time": "2025-07-09 11:42:03",
  "end_time": "...",
  "open_tcp_ports": [
    { "port": 22,  "service": "OpenSSH 8.9p1 Ubuntu 3ubuntu0.13" },
    { "port": 443, "service": "nginx 1.24.0" }
  ],
  "web_enumeration": {
    "443": [{ "path": "/", "status": 200 }, { "path": "/admin", "status": 403 }]
  },
  "vulnerabilities": [
    {
      "port": 443,
      "service_name": "nginx",
      "detected_version": "1.24.0",
      "vulnerability": { "cve": "CVE-2024-12345", "description": "…" }
    }
  ]
}

📝 Wordlists & vulns.json

    default-wordlist.txt – small content brute-force list

    subdomain-wordlist.txt – starter list of common sub-domains

    vulns.json – map service → affected versions → CVE metadata (extend it as you wish).

🤝 Contributing

    Fork the repo & create a feature branch.

    Code with PEP 8 in mind; keep external dependencies minimal.

    Open a pull request with a clear description & demo output.

📜 License

MIT © 2025 NeoDay – use at your own risk and only on targets you have permission to test.
🛣️ Roadmap

    Live progress bar & ETA

    ICMP rate-limit detection for UDP mode

    Import Nmap XML as a seed / merge scan

    Dark-theme HTML report

Pulse keeps your assessments beating strong – happy hacking!
