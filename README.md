# ScanX v2.0

> **Advanced Security Scanner** — Web UI + Terminal CLI  
> by [@iamunknown77](https://github.com/iamunknown77)

```
  ███████╗ ██████╗ █████╗ ███╗   ██╗██╗  ██╗
  ██╔════╝██╔════╝██╔══██╗████╗  ██║╚██╗██╔╝
  ███████╗██║     ███████║██╔██╗ ██║ ╚███╔╝ 
  ╚════██║██║     ██╔══██║██║╚██╗██║ ██╔██╗ 
  ███████║╚██████╗██║  ██║██║ ╚████║██╔╝ ██╗
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
```

> ⚠️ **Legal Warning:** Use only on systems you own or have **explicit written permission** to test.  
> Unauthorized scanning is illegal. The author is not responsible for misuse.

---

## Features

| Module | Description |
|--------|-------------|
| 🔌 **TCP Port Scanner** | Fast async scan with banner grabbing & service detection |
| 📡 **UDP Scanner** | Common UDP ports (DNS, SNMP, NTP, etc.) with protocol probes |
| 📂 **Directory Brute-Forcer** | Path enumeration with extension fuzzing (like gobuster) |
| 🌐 **Subdomain Enumerator** | DNS brute-force subdomain discovery |
| 🔒 **SSL/TLS Inspector** | Certificate info, expiry, cipher suite, deprecated protocol detection |
| 🛡️ **HTTP Header Auditor** | Security header check (HSTS, CSP, X-Frame-Options, etc.) |

Both the **Web UI** and **CLI** share the same functionality.

---

## Installation

### Requirements
- Python 3.9+
- pip

```bash
# Clone the repo
git clone https://github.com/iamunknown77/scanx.git
cd scanx

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### 🖥️ Web UI (Browser)

**Linux / macOS:**
```bash
bash run.sh
```

**Windows:**
```cmd
run.bat
```

Then open your browser at → **http://localhost:8000**  
_(The backend runs on port 8000; the `index.html` frontend connects to it automatically.)_

Or start manually:
```bash
python scanner_backend.py
# then open index.html in your browser
```

---

### 💻 Terminal CLI (like nmap / gobuster)

```bash
python scanx_cli.py <command> [options]
```

#### TCP Port Scan
```bash
# Scan top 100 ports (default)
python scanx_cli.py portscan -H 192.168.1.1

# Specific ports
python scanx_cli.py portscan -H 192.168.1.1 -p 22,80,443,8080-8090

# Top 1000 ports, save as JSON
python scanx_cli.py portscan -H 192.168.1.1 --preset top1000 -o results.json -f json

# Full scan (all 65535 ports)
python scanx_cli.py portscan -H 192.168.1.1 --preset full
```

#### UDP Scan
```bash
python scanx_cli.py udpscan -H 192.168.1.1
python scanx_cli.py udpscan -H 192.168.1.1 -p 53,161,123
```

#### Directory Brute-Force
```bash
# Built-in wordlist
python scanx_cli.py dirscan -u https://example.com

# Custom wordlist + extensions
python scanx_cli.py dirscan -u https://example.com -w wordlist.txt --ext php,html,txt

# Show only specific status codes
python scanx_cli.py dirscan -u https://example.com -c 200,403
```

#### Subdomain Enumeration
```bash
python scanx_cli.py subdomain -d example.com
python scanx_cli.py subdomain -d example.com -w subs.txt -o found.csv -f csv
```

#### SSL/TLS Check
```bash
python scanx_cli.py sslcheck -H example.com
python scanx_cli.py sslcheck -H example.com -p 8443
```

#### HTTP Header Audit
```bash
python scanx_cli.py headers -u https://example.com
python scanx_cli.py headers -u https://example.com -o headers.json -f json
```

---

## CLI Options Reference

| Flag | Description |
|------|-------------|
| `-H`, `--host` | Target hostname or IP |
| `-u`, `--url` | Target URL |
| `-d`, `--domain` | Target domain |
| `-p`, `--ports` | Port(s): `80`, `80,443`, `1-1000` |
| `--preset` | `top100` / `top1000` / `full` |
| `-w`, `--wordlist` | Path to wordlist file |
| `-x`, `--ext` | File extensions (e.g. `php,html,txt`) |
| `-T`, `--threads` | Concurrency (default varies per mode) |
| `--timeout` | Timeout in seconds |
| `-o`, `--output` | Output filename |
| `-f`, `--format` | `txt` / `json` / `csv` |

---

## File Structure

```
scanx/
├── index.html          # Web UI frontend (open in browser)
├── scanner_backend.py  # FastAPI backend (WebSocket API)
├── scanx_cli.py        # Terminal CLI tool
├── favicon.svg         # Browser tab icon
├── requirements.txt    # Python dependencies
├── run.sh              # Linux/macOS launcher
├── run.bat             # Windows launcher
├── README.md
└── LICENSE
```

---

## Wordlists

ScanX includes built-in wordlists for both directory and subdomain scanning.  
For more thorough testing, use external wordlists:

- [SecLists](https://github.com/danielmiessler/SecLists)
- [dirb common.txt](https://github.com/v0re/dirb/blob/master/wordlists/common.txt)
- [Sublist3r](https://github.com/aboul3la/Sublist3r)

Example with SecLists:
```bash
python scanx_cli.py dirscan -u https://example.com \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt

python scanx_cli.py subdomain -d example.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

---

## Output Formats

All CLI commands support `-o FILE -f FORMAT`:

```bash
# JSON (structured, best for scripting)
python scanx_cli.py portscan -H 10.0.0.1 -o scan.json -f json

# CSV (best for spreadsheets)
python scanx_cli.py dirscan -u https://example.com -o dirs.csv -f csv

# TXT (tab-separated, default)
python scanx_cli.py subdomain -d example.com -o subs.txt -f txt
```

---

## License

MIT — see [LICENSE](LICENSE)
