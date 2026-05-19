#!/usr/bin/env python3
"""
ScanX CLI v2.0  —  by iamunknown77
Use like nmap / gobuster from your terminal.

⚠  Use ONLY on systems you own or have explicit written permission to test.
   Unauthorized scanning is illegal. Use responsibly.

Examples
────────
  python scanx_cli.py portscan  -H 192.168.1.1 -p 80,443,8080
  python scanx_cli.py portscan  -H 192.168.1.1 --preset top100
  python scanx_cli.py udpscan   -H 192.168.1.1
  python scanx_cli.py dirscan   -u https://example.com -w wordlist.txt
  python scanx_cli.py dirscan   -u https://example.com --ext php,html
  python scanx_cli.py subdomain -d example.com -w subs.txt
  python scanx_cli.py sslcheck  -H example.com
  python scanx_cli.py headers   -u https://example.com
  python scanx_cli.py -h
"""

import argparse
import asyncio
import aiohttp
import ssl
import socket
import re
import sys
import platform
import json
import csv
import io
from datetime import datetime

# ── ANSI colours ──────────────────────────────────────────────────────────────
NO_COLOR = not sys.stdout.isatty() or platform.system() == "Windows" and "WT_SESSION" not in __import__("os").environ

def c(code, text):
    return text if NO_COLOR else f"\033[{code}m{text}\033[0m"

GREEN   = lambda t: c("92", t)
CYAN    = lambda t: c("96", t)
YELLOW  = lambda t: c("93", t)
RED     = lambda t: c("91", t)
DIM     = lambda t: c("90", t)
BOLD    = lambda t: c("1",  t)
MAGENTA = lambda t: c("95", t)

# ── Data tables (mirrors backend) ─────────────────────────────────────────────
PORT_SERVICES = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",67:"DHCP",69:"TFTP",
    80:"HTTP",88:"Kerberos",110:"POP3",111:"RPC",123:"NTP",135:"MSRPC",
    137:"NetBIOS",139:"NetBIOS",143:"IMAP",161:"SNMP",179:"BGP",389:"LDAP",
    443:"HTTPS",445:"SMB",465:"SMTPS",514:"Syslog",587:"SMTP",631:"IPP",
    636:"LDAPS",873:"rsync",902:"VMware",993:"IMAPS",995:"POP3S",1080:"SOCKS",
    1194:"OpenVPN",1433:"MSSQL",1521:"Oracle",1723:"PPTP",2049:"NFS",
    2082:"cPanel",2083:"cPanel-SSL",2222:"SSH-Alt",2375:"Docker",2376:"Docker-TLS",
    3000:"Node/React",3306:"MySQL",3389:"RDP",3690:"SVN",4000:"Node",
    5000:"Flask",5432:"PostgreSQL",5900:"VNC",5985:"WinRM",5986:"WinRM-TLS",
    6379:"Redis",6443:"Kubernetes",7001:"WebLogic",8000:"HTTP-Dev",
    8080:"HTTP-Proxy",8443:"HTTPS-Alt",8888:"Jupyter",9000:"PHP-FPM",
    9090:"Prometheus",9200:"Elasticsearch",9300:"Elasticsearch",
    10250:"Kubelet",27017:"MongoDB",27018:"MongoDB",28017:"MongoDB-Web",
}
TOP_100_PORTS = [
    7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,
    139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,
    554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,
    1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,
    3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,
    5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,
    9999,10000,32768,49152,49153,49154,49155,49156,49157,
]
DEFAULT_UDP_PORTS = [53,67,68,69,123,137,138,161,162,177,500,514,520,631,1194,1701,1900,4500,5353,5355]
UDP_PROBES = {
    53:  b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03',
    161: b'\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',
    123: b'\x1b' + b'\x00' * 47,
}
BUILTIN_WORDLIST = list(dict.fromkeys("""admin administrator login dashboard api v1 v2 v3 static assets
images css js javascript upload uploads backup backups db database config configuration
settings test tests dev development staging prod production www mail email ftp index
home user users account accounts profile profiles search auth oauth register signup
signin logout password reset forgot help support contact about blog news media download
downloads file files data logs log error errors robots.txt .htaccess .env .env.local
.git sitemap.xml wp-admin wp-login.php wp-content wp-includes phpmyadmin cpanel webmail
shell console panel manager management server system web app application portal intranet
internal private public old new bak tmp temp cache session token secret key ssl cert
security secure health status ping info version swagger api-docs graphql rest docs
documentation readme wp-json xmlrpc.php actuator metrics trace env beans heapdump
phpinfo.php info.php test.php server-status server-info crossdomain.xml""".split()))

BUILTIN_SUBDOMAINS = list(dict.fromkeys("""www mail ftp localhost webmail smtp pop imap smtps ssh sftp dev
staging test api api2 beta mobile m admin backend portal vpn remote mx mx1 mx2 ns ns1
ns2 ns3 blog shop store app apps cdn static assets media img images video files download
upload support help docs documentation wiki forum community social news careers jobs about
status monitor dashboard panel control admin2 administrator cpanel whm webdisk autodiscover
autoconfig cloud secure login auth sso oauth2 id accounts pay payment checkout cart git
gitlab jenkins ci cd build deploy uat qa sandbox demo monitoring grafana kibana prometheus
zabbix nagios mail2 webmail2 smtp2 imap2 exchange owa intranet extranet corporate lab
test2 dev2 api3 old new backup mysql ftp2 vpn2 gateway proxy""".split()))

SECURITY_HEADERS = {
    "strict-transport-security":    {"name":"HSTS",                  "risk":"HIGH",   "desc":"Missing HSTS — SSL stripping possible"},
    "content-security-policy":      {"name":"CSP",                   "risk":"HIGH",   "desc":"No CSP — XSS mitigation absent"},
    "x-frame-options":              {"name":"X-Frame-Options",       "risk":"MEDIUM", "desc":"Clickjacking protection missing"},
    "x-content-type-options":       {"name":"X-Content-Type-Options","risk":"MEDIUM", "desc":"MIME sniffing not prevented"},
    "referrer-policy":              {"name":"Referrer-Policy",       "risk":"LOW",    "desc":"Referrer info may leak"},
    "permissions-policy":           {"name":"Permissions-Policy",    "risk":"LOW",    "desc":"Browser features unrestricted"},
    "x-xss-protection":             {"name":"X-XSS-Protection",      "risk":"LOW",    "desc":"Legacy XSS filter not configured"},
    "cross-origin-opener-policy":   {"name":"COOP",                  "risk":"MEDIUM", "desc":"Cross-origin isolation not enforced"},
    "cross-origin-embedder-policy": {"name":"COEP",                  "risk":"MEDIUM", "desc":"Cross-origin embedding unrestricted"},
    "cross-origin-resource-policy": {"name":"CORP",                  "risk":"MEDIUM", "desc":"Cross-origin resource access unrestricted"},
}

# ── Helpers ───────────────────────────────────────────────────────────────────
def banner():
    art = r"""
  ███████╗ ██████╗ █████╗ ███╗   ██╗██╗  ██╗
  ██╔════╝██╔════╝██╔══██╗████╗  ██║╚██╗██╔╝
  ███████╗██║     ███████║██╔██╗ ██║ ╚███╔╝ 
  ╚════██║██║     ██╔══██║██║╚██╗██║ ██╔██╗ 
  ███████║╚██████╗██║  ██║██║ ╚████║██╔╝ ██╗
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝"""
    print(GREEN(art))
    print(CYAN("  Advanced Security Scanner v2.0  //  by iamunknown77"))
    print(DIM("  " + "─" * 50))
    print(YELLOW("  ⚠  Use only on systems you own or have written permission to test.\n"))


def parse_port_range(s: str) -> list:
    ports, seen = [], set()
    for part in s.split(","):
        part = part.strip()
        if "-" in part and not part.startswith("-"):
            try:
                a, b = part.split("-", 1)
                for p in range(int(a), min(int(b) + 1, 65536)):
                    if p not in seen:
                        ports.append(p); seen.add(p)
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 0 < p < 65536 and p not in seen:
                    ports.append(p); seen.add(p)
            except ValueError:
                continue
    return ports


def load_wordlist(path: str | None, builtin: list) -> list:
    if path:
        try:
            with open(path) as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            print(DIM(f"  [+] Loaded {len(words)} words from {path}"))
            return words
        except FileNotFoundError:
            print(YELLOW(f"  [!] Wordlist '{path}' not found — using built-in list"))
    return builtin


def save_results(results: list, output: str | None, fmt: str):
    if not output or not results:
        return
    if fmt == "json":
        with open(output, "w") as f:
            json.dump(results, f, indent=2)
    elif fmt == "csv":
        keys = list(results[0].keys())
        with open(output, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader(); w.writerows(results)
    else:  # txt
        with open(output, "w") as f:
            for r in results:
                f.write("\t".join(str(v) for v in r.values()) + "\n")
    print(GREEN(f"\n  [✓] Results saved → {output}"))


async def grab_banner(host: str, port: int, timeout: float = 2.5) -> str:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        if port in (80, 8080, 8000, 8008, 8888, 3000, 4000, 5000, 9000):
            writer.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass
        return data.decode("utf-8", errors="replace").strip().split("\n")[0][:100].strip()
    except Exception:
        return ""


# ── Port Scan ─────────────────────────────────────────────────────────────────
async def cmd_portscan(args):
    host = args.host
    if args.preset == "top100":
        ports = TOP_100_PORTS
    elif args.preset == "top1000":
        ports = list(range(1, 1001))
    elif args.preset == "full":
        ports = list(range(1, 65536))
        print(YELLOW("  [!] Full scan (65535 ports) — this may take a while"))
    elif args.ports:
        ports = parse_port_range(args.ports)
    else:
        ports = TOP_100_PORTS

    threads  = args.threads
    timeout  = args.timeout
    grab     = not args.no_banner
    results  = []
    open_cnt = 0
    scanned  = 0

    print(BOLD(f"\n  [TARGET]  {host}"))
    print(DIM(f"  [PORTS]   {len(ports)} ports  |  threads={threads}  timeout={timeout}s  banner={'yes' if grab else 'no'}"))
    print(DIM("  " + "─" * 50))
    print(f"  {'PORT':<8}{'STATE':<10}{'SERVICE':<16}{'BANNER'}")
    print(DIM("  " + "─" * 50))

    sem = asyncio.Semaphore(threads)

    async def scan_port(port):
        nonlocal open_cnt, scanned
        async with sem:
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
                w.close()
                try: await w.wait_closed()
                except Exception: pass
                svc    = PORT_SERVICES.get(port, "")
                bnr    = await grab_banner(host, port, timeout) if grab else ""
                result = {"port": port, "state": "open", "service": svc, "banner": bnr}
                results.append(result)
                open_cnt += 1
                bnr_str = DIM(f" ↳ {bnr[:60]}") if bnr else ""
                print(f"  {GREEN(str(port)):<18}{GREEN('OPEN'):<18}{CYAN(svc):<16}{bnr_str}")
            except Exception:
                pass
            finally:
                scanned += 1
                if scanned % 100 == 0:
                    pct = scanned * 100 // len(ports)
                    print(DIM(f"  ... {scanned}/{len(ports)} ({pct}%)"), end="\r")

    await asyncio.gather(*[scan_port(p) for p in ports])
    print(DIM("\n  " + "─" * 50))
    print(GREEN(f"  [✓] Done — {open_cnt} open port(s) found out of {len(ports)} scanned"))
    save_results(results, args.output, args.format)
    return results


# ── UDP Scan ──────────────────────────────────────────────────────────────────
async def cmd_udpscan(args):
    host    = args.host
    ports   = parse_port_range(args.ports) if args.ports else DEFAULT_UDP_PORTS
    timeout = args.timeout
    results = []

    print(BOLD(f"\n  [TARGET]  {host}  (UDP)"))
    print(DIM(f"  [PORTS]   {len(ports)} ports  |  timeout={timeout}s"))
    print(DIM("  " + "─" * 50))

    loop = asyncio.get_event_loop()

    async def probe(port):
        probe_data = UDP_PROBES.get(port, b"\x00" * 8)
        try:
            def _send():
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(timeout)
                try:
                    s.sendto(probe_data, (host, port))
                    data, _ = s.recvfrom(512)
                    return True, data[:50].hex()
                except socket.timeout:
                    return None, None
                except OSError as e:
                    if "refused" in str(e).lower():
                        return False, None
                    return None, None
                finally:
                    s.close()
            state, raw = await loop.run_in_executor(None, _send)
            svc = PORT_SERVICES.get(port, "")
            if state is True:
                results.append({"port": port, "state": "open", "service": svc})
                print(f"  {GREEN(str(port)):<18}{GREEN('OPEN|FILTERED'):<22}{CYAN(svc)}")
            elif state is False:
                pass  # closed
        except Exception:
            pass

    for p in ports:
        await probe(p)

    print(DIM("\n  " + "─" * 50))
    print(GREEN(f"  [✓] Done — {len(results)} responsive UDP port(s) found"))
    save_results(results, args.output, args.format)


# ── Dir Scan ──────────────────────────────────────────────────────────────────
async def cmd_dirscan(args):
    base_url = args.url.rstrip("/")
    wordlist = load_wordlist(args.wordlist, BUILTIN_WORDLIST)
    threads  = args.threads
    timeout  = args.timeout
    exts     = [""] + [f".{e.lstrip('.')}" for e in args.ext.split(",")] if args.ext else [""]
    codes    = [int(c) for c in args.codes.split(",")] if args.codes else None
    paths    = [f"/{w}{e}" for w in wordlist for e in exts]
    results  = []
    found    = 0

    print(BOLD(f"\n  [TARGET]  {base_url}"))
    print(DIM(f"  [PATHS]   {len(paths)} paths  |  threads={threads}  timeout={timeout}s"))
    if codes:
        print(DIM(f"  [FILTER]  show codes: {codes}"))
    print(DIM("  " + "─" * 50))
    print(f"  {'STATUS':<9}{'SIZE':<10}{'PATH'}")
    print(DIM("  " + "─" * 50))

    sem = asyncio.Semaphore(threads)
    conn = aiohttp.TCPConnector(ssl=False, limit=threads)

    async with aiohttp.ClientSession(connector=conn,
             headers={"User-Agent": "ScanX/2.0 DirScanner"}) as session:

        async def check(path):
            nonlocal found
            async with sem:
                url = base_url + path
                try:
                    async with session.get(url,
                             timeout=aiohttp.ClientTimeout(total=timeout),
                             allow_redirects=False, ssl=False) as r:
                        st   = r.status
                        size = int(r.headers.get("content-length", 0))
                        if codes and st not in codes:
                            return
                        if st == 404:
                            return
                        found += 1
                        color = GREEN if st == 200 else (YELLOW if st in (301,302,307,308) else (MAGENTA if st == 403 else RED))
                        result = {"status": st, "size": size, "url": url}
                        results.append(result)
                        print(f"  {color(str(st)):<17}{DIM(str(size) + 'B'):<18}{url}")
                except Exception:
                    pass

        await asyncio.gather(*[check(p) for p in paths])

    print(DIM("\n  " + "─" * 50))
    print(GREEN(f"  [✓] Done — {found} path(s) found out of {len(paths)} tested"))
    save_results(results, args.output, args.format)


# ── Subdomain Scan ────────────────────────────────────────────────────────────
async def cmd_subdomain(args):
    domain   = args.domain.lstrip("http://").lstrip("https://").split("/")[0]
    wordlist = load_wordlist(args.wordlist, BUILTIN_SUBDOMAINS)
    threads  = args.threads
    results  = []

    print(BOLD(f"\n  [DOMAIN]  {domain}"))
    print(DIM(f"  [WORDS]   {len(wordlist)} subdomains  |  threads={threads}"))
    print(DIM("  " + "─" * 50))
    print(f"  {'SUBDOMAIN':<40}{'IPs'}")
    print(DIM("  " + "─" * 50))

    sem  = asyncio.Semaphore(threads)
    loop = asyncio.get_event_loop()

    async def resolve(sub):
        full = f"{sub}.{domain}"
        async with sem:
            try:
                ips = await loop.run_in_executor(None, lambda: list({
                    a[4][0] for a in socket.getaddrinfo(full, None)
                }))
                if ips:
                    results.append({"subdomain": full, "ips": ips})
                    print(f"  {GREEN(full):<48}{CYAN(', '.join(ips))}")
            except Exception:
                pass

    await asyncio.gather(*[resolve(w) for w in wordlist])
    print(DIM("\n  " + "─" * 50))
    print(GREEN(f"  [✓] Done — {len(results)} subdomain(s) resolved out of {len(wordlist)} tested"))
    save_results(results, args.output, args.format)


# ── SSL Check ─────────────────────────────────────────────────────────────────
async def cmd_sslcheck(args):
    host = args.host
    port = args.port
    loop = asyncio.get_event_loop()

    print(BOLD(f"\n  [SSL/TLS]  {host}:{port}"))
    print(DIM("  " + "─" * 50))

    def _check():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        raw  = socket.create_connection((host, port), timeout=10)
        conn = ctx.wrap_socket(raw, server_hostname=host)
        cert = conn.getpeercert()
        ciph = conn.cipher()
        ver  = conn.version()
        conn.close()
        subj    = dict(x[0] for x in cert.get("subject",   []))
        issuer  = dict(x[0] for x in cert.get("issuer",    []))
        exp_str = cert.get("notAfter",  "")
        nb_str  = cert.get("notBefore", "")
        sans    = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"][:20]
        days_left = None
        try:
            exp = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp - datetime.utcnow()).days
        except Exception: pass
        return {"subject_cn": subj.get("commonName",""), "issuer_cn": issuer.get("commonName",""),
                "issuer_org": issuer.get("organizationName",""), "not_before": nb_str,
                "not_after": exp_str, "days_left": days_left, "sans": sans,
                "tls_version": ver, "cipher": ciph[0] if ciph else "", "cipher_bits": ciph[2] if ciph else 0}

    try:
        info = await loop.run_in_executor(None, _check)
        rows = [
            ("Subject CN",   info["subject_cn"]),
            ("Issuer",       f"{info['issuer_cn']} / {info['issuer_org']}"),
            ("Valid From",   info["not_before"]),
            ("Valid Until",  info["not_after"]),
            ("TLS Version",  info["tls_version"]),
            ("Cipher Suite", f"{info['cipher']} ({info['cipher_bits']} bit)"),
        ]
        for label, val in rows:
            print(f"  {CYAN(label + ':'):<28}{val}")

        days = info.get("days_left")
        if days is not None:
            if days < 0:
                print(f"  {RED('Expiry:'):<28}{RED(f'EXPIRED {abs(days)} days ago')}")
            elif days < 15:
                print(f"  {RED('Expiry:'):<28}{RED(f'{days} days left — CRITICAL')}")
            elif days < 30:
                print(f"  {YELLOW('Expiry:'):<28}{YELLOW(f'{days} days left — WARNING')}")
            else:
                print(f"  {GREEN('Expiry:'):<28}{GREEN(f'{days} days left — OK')}")

        ver = info.get("tls_version", "")
        if ver in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
            print(f"\n  {RED('⚠  ' + ver + ' is deprecated and insecure!')}")

        if info.get("sans"):
            print(f"\n  {CYAN('SANs:')}  {', '.join(info['sans'][:8])}" +
                  ("..." if len(info["sans"]) > 8 else ""))

        print(DIM("\n  " + "─" * 50))
        print(GREEN("  [✓] SSL/TLS inspection complete"))
    except Exception as e:
        print(RED(f"  [✗] Connection failed: {e}"))


# ── Header Check ──────────────────────────────────────────────────────────────
async def cmd_headers(args):
    url     = args.url
    results = []

    print(BOLD(f"\n  [HEADERS]  {url}"))
    print(DIM("  " + "─" * 50))

    conn = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=conn) as session:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                   allow_redirects=True, ssl=False,
                                   headers={"User-Agent": "ScanX/2.0 Security Audit"}) as r:
                hdrs = {k.lower(): v for k, v in r.headers.items()}
                print(f"  {CYAN('HTTP Status:'):<28}{r.status}")
                print(f"  {CYAN('Server:'):<28}{hdrs.get('server','?')}")
                print(f"  {CYAN('Content-Type:'):<28}{hdrs.get('content-type','?').split(';')[0]}")
                print(DIM("\n  ── Security Headers ──"))

                missing = 0
                for key, meta in SECURITY_HEADERS.items():
                    if key in hdrs:
                        print(f"  {GREEN('✓ PRESENT'):<18}{meta['name']:<26}{DIM(hdrs[key][:60])}")
                        results.append({"header": meta["name"], "status": "PRESENT", "risk": "OK", "value": hdrs[key][:100]})
                    else:
                        missing += 1
                        risk_color = RED if meta["risk"] == "HIGH" else (YELLOW if meta["risk"] == "MEDIUM" else DIM)
                        print(f"  {RED('✗ MISSING'):<18}{meta['name']:<26}{risk_color('[' + meta['risk'] + '] ' + meta['desc'])}")
                        results.append({"header": meta["name"], "status": "MISSING", "risk": meta["risk"], "value": meta["desc"]})

                print(DIM("\n  ── Info Leakage ──"))
                for lhdr in ("server","x-powered-by","x-aspnet-version","x-aspnetmvc-version","x-generator"):
                    if lhdr in hdrs:
                        print(f"  {YELLOW('⚠ LEAK'):<18}{lhdr.title():<26}{YELLOW(hdrs[lhdr])}")

                print(DIM("\n  " + "─" * 50))
                print(GREEN(f"  [✓] Header analysis complete — {missing} security header(s) missing"))
        except Exception as e:
            print(RED(f"  [✗] Request failed: {e}"))

    save_results(results, args.output, args.format)


# ── Argument Parser ───────────────────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        prog="scanx",
        description="ScanX CLI v2.0  —  Advanced Security Scanner  —  by iamunknown77",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanx_cli.py portscan  -H 192.168.1.1
  python scanx_cli.py portscan  -H 192.168.1.1 -p 22,80,443,8080-8090
  python scanx_cli.py portscan  -H 192.168.1.1 --preset top1000 -o results.json -f json
  python scanx_cli.py udpscan   -H 192.168.1.1
  python scanx_cli.py dirscan   -u https://example.com
  python scanx_cli.py dirscan   -u https://example.com -w /usr/share/wordlists/dirb/common.txt --ext php,html,txt
  python scanx_cli.py subdomain -d example.com -w subs.txt
  python scanx_cli.py sslcheck  -H example.com
  python scanx_cli.py headers   -u https://example.com -o headers.csv -f csv
        """,
    )
    sub = p.add_subparsers(dest="cmd", metavar="COMMAND")
    sub.required = True

    # shared output args
    def add_output(sp):
        sp.add_argument("-o", "--output",  metavar="FILE",   help="Save results to file")
        sp.add_argument("-f", "--format",  default="txt",    choices=["txt","json","csv"], help="Output format (default: txt)")

    # portscan
    ps = sub.add_parser("portscan", help="TCP port scanner (like nmap)")
    ps.add_argument("-H","--host",    required=True, metavar="HOST",    help="Target host or IP")
    ps.add_argument("-p","--ports",   metavar="PORTS",  help="Ports: 80,443 or 1-1000")
    ps.add_argument("--preset",       default="top100", choices=["top100","top1000","full"], help="Port preset (default: top100)")
    ps.add_argument("-T","--threads", type=int, default=300, metavar="N",  help="Concurrent threads (default: 300)")
    ps.add_argument("--timeout",      type=float, default=1.0, metavar="S", help="Timeout per port (default: 1.0s)")
    ps.add_argument("--no-banner",    action="store_true", help="Skip banner grabbing")
    add_output(ps)

    # udpscan
    us = sub.add_parser("udpscan", help="UDP port scanner")
    us.add_argument("-H","--host",    required=True, metavar="HOST",   help="Target host or IP")
    us.add_argument("-p","--ports",   metavar="PORTS", help="Ports (default: common UDP ports)")
    us.add_argument("--timeout",      type=float, default=2.0, metavar="S", help="Timeout (default: 2.0s)")
    add_output(us)

    # dirscan
    ds = sub.add_parser("dirscan", help="Directory/path brute-forcer (like gobuster dir)")
    ds.add_argument("-u","--url",     required=True, metavar="URL",    help="Target URL (e.g. https://example.com)")
    ds.add_argument("-w","--wordlist",metavar="FILE",                   help="Wordlist file path")
    ds.add_argument("-x","--ext",     metavar="EXT",                   help="File extensions (e.g. php,html,txt)")
    ds.add_argument("-c","--codes",   metavar="CODES",                 help="Show only these status codes (e.g. 200,403)")
    ds.add_argument("-T","--threads", type=int, default=50,  metavar="N", help="Concurrent threads (default: 50)")
    ds.add_argument("--timeout",      type=float, default=5.0, metavar="S", help="Timeout (default: 5.0s)")
    add_output(ds)

    # subdomain
    ss = sub.add_parser("subdomain", help="Subdomain brute-forcer (like gobuster dns)")
    ss.add_argument("-d","--domain",  required=True, metavar="DOMAIN", help="Target domain (e.g. example.com)")
    ss.add_argument("-w","--wordlist",metavar="FILE",                   help="Wordlist file path")
    ss.add_argument("-T","--threads", type=int, default=100, metavar="N", help="Concurrent threads (default: 100)")
    add_output(ss)

    # sslcheck
    sl = sub.add_parser("sslcheck", help="SSL/TLS certificate inspector")
    sl.add_argument("-H","--host",    required=True, metavar="HOST",   help="Target host")
    sl.add_argument("-p","--port",    type=int, default=443, metavar="PORT", help="Port (default: 443)")
    add_output(sl)

    # headers
    hd = sub.add_parser("headers", help="HTTP security header auditor")
    hd.add_argument("-u","--url",     required=True, metavar="URL",    help="Target URL")
    add_output(hd)

    return p


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    banner()
    parser = build_parser()
    args   = parser.parse_args()

    dispatch = {
        "portscan":  cmd_portscan,
        "udpscan":   cmd_udpscan,
        "dirscan":   cmd_dirscan,
        "subdomain": cmd_subdomain,
        "sslcheck":  cmd_sslcheck,
        "headers":   cmd_headers,
    }

    try:
        asyncio.run(dispatch[args.cmd](args))
    except KeyboardInterrupt:
        print(YELLOW("\n\n  [!] Scan aborted by user"))
    except Exception as e:
        print(RED(f"\n  [✗] Error: {e}"))
        sys.exit(1)


if __name__ == "__main__":
    main()
