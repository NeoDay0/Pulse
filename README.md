
![pulse](https://github.com/user-attachments/assets/197c7842-c66f-415f-b1d2-5c4539ee2fa7)


# Pulse
A multi-function command-line tool for network reconnaissance and security scanning, written in Python.


## Features                                                                                                                                                                                                  │
 │     20                                                                                                                                                                                                              │
 │     21 - **Dual-Mode Operation**: Run with command-line arguments for scripting or without arguments for a user-friendly interactive menu.                                                                          │
 │     22 - **TCP Port Scanning**: Fast, multi-threaded TCP scanner to find open ports and grab service banners.                                                                                                       │
 │     23 - **UDP Port Scanning**: Scan for common UDP ports (requires `sudo`).                                                                                                                                        │
 │     24 - **Subdomain Enumeration**: Discover subdomains for a target domain using a wordlist.                                                                                                                       │
 │     25 - **Web Content Enumeration**: Find hidden directories and files on web servers.                                                                                                                             │
 │     26 - **Vulnerability Scanning**: Cross-references discovered services with a local database of known vulnerabilities.                                                                                           │
 │     27 - **Colorized Output**: Clean, color-coded output for improved readability.                                                                                                                                  │
 │     28 - **JSON Output**: Save scan results to a JSON file for analysis or use in other tools.                                                                                                                      │
 │     29                                                                                                                                                                                                              │
 │     30 ---                                                                                                                                                                                                          │
 │     31                                                                                                                                                                                                              │
 │     32 ## Setup                                                                                                                                                                                                     │
 │     33                                                                                                                                                                                                              │
 │     34 To run Pulse, you need the following files in the same directory:                                                                                                                                            │
 │     35                                                                                                                                                                                                              │
 │     36 1.  `pulse.py`: The main script.                                                                                                                                                                             │
 │     37 2.  `default-wordlist.txt`: Wordlist for web content enumeration.                                                                                                                                            │
 │     38 3.  `subdomain-wordlist.txt`: Wordlist for subdomain enumeration.                                                                                                                                            │
 │     39 4.  `vulns.json`: The local vulnerability database.                                                                                                                                                          │
 │     40                                                                                                                                                                                                              │
 │     41 Make the script executable:                                                                                                                                                                                  │
 │     42 ```bash                                                                                                                                                                                                      │
 │     43 chmod +x pulse.py                                                                                                                                                                                            │
 │     44 ```                                                                                                                                                                                                          │
 │     45                                                                                                                                                                                                              │
 │     46 ---                                                                                                                                                                                                          │
 │     47                                                                                                                                                                                                              │
 │     48 ## Usage                                                                                                                                                                                                     │
 │     49                                                                                                                                                                                                              │
 │     50 The tool can be run in two ways:                                                                                                                                                                             │
 │     51                                                                                                                                                                                                              │
 │     52 ### 1. Interactive Mode                                                                                                                                                                                      │
 │     53                                                                                                                                                                                                              │
 │     54 For a guided experience, run the script without any arguments. This is ideal for new users.                                                                                                                  │
 │     55                                                                                                                                                                                                              │
 │     56 ```bash                                                                                                                                                                                                      │
 │     57 python3 pulse.py                                                                                                                                                                                             │
 │     58 ```                                                                                                                                                                                                          │
 │     59                                                                                                                                                                                                              │
 │     60 The script will launch a menu that walks you through selecting a scan type and the required options.                                                                                                         │
 │     61                                                                                                                                                                                                              │
 │     62 ### 2. Command-Line Mode                                                                                                                                                                                     │
 │     63                                                                                                                                                                                                              │
 │     64 For scripting and automation, you can pass arguments directly.                                                                                                                                               │
 │     65                                                                                                                                                                                                              │
 │     66 **View Help Menu**                                                                                                                                                                                           │
 │     67 ```bash                                                                                                                                                                                                      │
 │     68 python3 pulse.py --help                                                                                                                                                                                      │
 │     69 ```                                                                                                                                                                                                          │
 │     70                                                                                                                                                                                                              │
 │     71 **TCP Port Scan (Default)**                                                                                                                                                                                  │
 │     72 ```bash                                                                                                                                                                                                      │
 │     73 # Scan the 1024 most common ports                                                                                                                                                                            │
 │     74 python3 pulse.py scanme.nmap.org                                                                                                                                                                             │
 │     75                                                                                                                                                                                                              │
 │     76 # Scan a specific port range and save the output                                                                                                                                                             │
 │     77 python3 pulse.py 192.168.1.1 -p 20-80,443 -o results.json                                                                                                                                                    │
 │     78 ```                                                                                                                                                                                                          │
 │     79                                                                                                                                                                                                              │
 │     80 **Full Scan (TCP + Web Enum + Vuln Scan)**                                                                                                                                                                   │
 │     81 ```bash                                                                                                                                                                                                      │
 │     82 python3 pulse.py example.com -p 22,80,443 --web-enum --vuln-scan                                                                                                                                             │
 │     83 ```                                                                                                                                                                                                          │
 │     84                                                                                                                                                                                                              │
 │     85 **UDP Scan**                                                                                                                                                                                                 │
 │     86 *Note: Requires sudo privileges.*                                                                                                                                                                            │
 │     87 ```bash                                                                                                                                                                                                      │
 │     88 sudo python3 pulse.py example.com --mode portscan --udp -p 53,123,161                                                                                                                                        │
 │     89 ```                                                                                                                                                                                                          │
 │     90                                                                                                                                                                                                              │
 │     91 **Subdomain Enumeration**                                                                                                                                                                                    │
 │     92 ```bash                                                                                                                                                                                                      │
 │     93 # Use the default wordlist (subdomain-wordlist.txt)                                                                                                                                                          │
 │     94 python3 pulse.py example.com --mode subdomain                                                                                                                                                                │
 │     95                                                                                                                                                                                                              │
 │     96 # Use a custom wordlist                                                                                                                                                                                      │
 │     97 python3 pulse.py example.com --mode subdomain --wordlist /path/to/your/subs.txt                                                                                                                              │
 │     98 ```                                                                                                                                                                                                          │
 │     99                                                                                                                                                                                                              │
 │    100 ---                                                                                                                                                                                                          │
 │    101                                                                                                                                                                                                              │
 │    102 ## Disclaimer                                                                                                                                                                                                │
 │    103                                                                                                                                                                                                              │
 │    104 This tool is intended for educational purposes and for use by security professionals on authorized systems only. Unauthorized scanning of networks is illegal. The developer assumes no liability            │
 │        and is not responsible for any misuse or damage caused by this program.   
