#!/usr/bin/env python3
"""
ScanX - Advanced Security Scanner Backend v2.0
by iamunknown77
─────────────────────────────────────────────────
⚠  Use ONLY on systems you own or have explicit written permission to test.
   Unauthorized scanning is illegal. Use responsibly.
"""

import asyncio
import aiohttp
import ssl
import socket
import re
import platform
import os
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

app = FastAPI(title="ScanX API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Serve frontend ────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return FileResponse("index.html")

@app.get("/favicon.svg")
async def favicon():
    return FileResponse("favicon.svg")

# ── Service fingerprints ──────────────────────────────────────────────────────
PORT_SERVICES = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS", 67:"DHCP", 69:"TFTP",
    80:"HTTP", 88:"Kerberos", 110:"POP3", 111:"RPC", 123:"NTP", 135:"MSRPC",
    137:"NetBIOS", 139:"NetBIOS", 143:"IMAP", 161:"SNMP", 179:"BGP", 389:"LDAP",
    443:"HTTPS", 445:"SMB", 465:"SMTPS", 514:"Syslog", 587:"SMTP", 631:"IPP",
    636:"LDAPS", 873:"rsync", 902:"VMware", 993:"IMAPS", 995:"POP3S", 1080:"SOCKS",
    1194:"OpenVPN", 1433:"MSSQL", 1521:"Oracle", 1723:"PPTP", 2049:"NFS",
    2082:"cPanel", 2083:"cPanel-SSL", 2222:"SSH-Alt", 2375:"Docker", 2376:"Docker-TLS",
    3000:"Node/React", 3306:"MySQL", 3389:"RDP", 3690:"SVN", 4000:"Node",
    5000:"Flask", 5432:"PostgreSQL", 5900:"VNC", 5985:"WinRM", 5986:"WinRM-TLS",
    6379:"Redis", 6443:"Kubernetes", 7001:"WebLogic", 8000:"HTTP-Dev",
    8080:"HTTP-Proxy", 8443:"HTTPS-Alt", 8888:"Jupyter", 9000:"PHP-FPM",
    9090:"Prometheus", 9200:"Elasticsearch", 9300:"Elasticsearch",
    10250:"Kubelet", 27017:"MongoDB", 27018:"MongoDB", 28017:"MongoDB-Web",
}

TOP_100_PORTS = [
    7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,
    139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,
    554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,
    1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,
    3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,
    5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,
    9999,10000,32768,49152,49153,49154,49155,49156,49157
]
TOP_1000_PORTS = list(range(1, 1001))
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

STATUS_LABELS = {
    200:"OK",201:"Created",204:"No Content",301:"Moved",302:"Found",
    307:"Temp Redirect",308:"Perm Redirect",400:"Bad Request",401:"Unauthorized",
    403:"Forbidden",404:"Not Found",405:"Not Allowed",429:"Too Many",
    500:"Server Error",502:"Bad Gateway",503:"Unavailable",504:"Timeout",
}


def parse_port_range(s: str) -> list:
    ports, seen = [], set()
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                for p in range(int(a), min(int(b)+1, 65536)):
                    if p not in seen: ports.append(p); seen.add(p)
            except ValueError:
                continue
        else:
            try:
                p = int(part)
                if 0 < p < 65536 and p not in seen: ports.append(p); seen.add(p)
            except ValueError:
                continue
    return ports


async def grab_banner(host: str, port: int, timeout: float = 2.5) -> str:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        if port in (80, 8080, 8000, 8008, 8888, 3000, 4000, 5000, 9000):
            writer.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=timeout)
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass
            return data.decode("utf-8", errors="replace").strip().split("\n")[0][:100].strip()
        except Exception:
            try: writer.close()
            except Exception: pass
            return ""
    except Exception:
        return ""


async def detect_os_ttl(host: str) -> str:
    try:
        flag = ["-n","1"] if platform.system().lower() == "windows" else ["-c","1","-W","3"]
        proc = await asyncio.create_subprocess_exec(
            "ping", *flag, host,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=6)
        m = re.search(r"ttl[=\s]+(\d+)", stdout.decode("utf-8", errors="replace"), re.IGNORECASE)
        if m:
            ttl = int(m.group(1))
            if ttl <= 64:   return f"Linux/Unix (TTL={ttl})"
            elif ttl <= 128: return f"Windows (TTL={ttl})"
            else:            return f"Network Device (TTL={ttl})"
        return "Host alive — TTL not parsed"
    except Exception:
        return "Unknown (ping failed or blocked)"


async def scan_port_tcp(host, port, sem, timeout, do_banner):
    async with sem:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass
            banner = await grab_banner(host, port, 2.5) if do_banner else ""
            return {"port":port, "status":"open", "service":PORT_SERVICES.get(port,"Unknown"), "banner":banner}
        except Exception:
            return {"port":port, "status":"closed"}


async def scan_port_udp(host, port, sem, timeout):
    async with sem:
        loop = asyncio.get_event_loop()
        def _probe():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(timeout)
                s.sendto(UDP_PROBES.get(port, b"\x00"), (host, port))
                try:
                    data, _ = s.recvfrom(1024); s.close()
                    return {"port":port,"status":"open","service":PORT_SERVICES.get(port,"Unknown"),"bytes":len(data)}
                except socket.timeout:
                    s.close()
                    return {"port":port,"status":"open|filtered","service":PORT_SERVICES.get(port,"Unknown"),"bytes":0}
                except OSError:
                    s.close(); return {"port":port,"status":"closed"}
            except Exception as e:
                return {"port":port,"status":"error","detail":str(e)}
        return await loop.run_in_executor(None, _probe)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.websocket("/ws/portscan")
async def ws_portscan(ws: WebSocket):
    await ws.accept()
    try:
        data = await ws.receive_json()
        host      = data.get("host","").strip()
        threads   = min(int(data.get("threads",500)), 2000)
        timeout   = float(data.get("timeout",1.0))
        do_banner = bool(data.get("banner",False))
        do_os     = bool(data.get("os_detect",False))
        preset    = data.get("preset","")

        if not host: await ws.send_json({"type":"error","message":"No host specified"}); return

        if   preset == "top100":  ports = TOP_100_PORTS[:]
        elif preset == "top1000": ports = TOP_1000_PORTS[:]
        elif preset == "full":    ports = list(range(1,65536))
        else:                     ports = parse_port_range(data.get("ports","1-1000"))

        if not ports: await ws.send_json({"type":"error","message":"Invalid port range"}); return

        if do_os:
            await ws.send_json({"type":"info","message":f"Running OS detection for {host}..."})
            os_hint = await detect_os_ttl(host)
            await ws.send_json({"type":"os","message":f"OS Hint: {os_hint}","os":os_hint})

        await ws.send_json({"type":"info","message":
            f"Target: {host}  |  Ports: {len(ports)}  |  Threads: {threads}  |  Timeout: {timeout}s  |  Banner: {'on' if do_banner else 'off'}"})

        sem = asyncio.Semaphore(threads)
        tasks = [scan_port_tcp(host,p,sem,timeout,do_banner) for p in ports]
        found, scanned = [], 0

        for coro in asyncio.as_completed(tasks):
            res = await coro; scanned += 1
            if res["status"] == "open":
                found.append(res["port"])
                await ws.send_json({"type":"result","data":res})
            if scanned % 200 == 0 or scanned == len(ports):
                await ws.send_json({"type":"progress","scanned":scanned,"total":len(ports),"open":len(found)})

        await ws.send_json({"type":"done",
            "message":f"TCP scan complete — {len(found)} open port(s) out of {len(ports)} scanned",
            "open_ports":found})
    except WebSocketDisconnect: pass
    except Exception as e:
        try: await ws.send_json({"type":"error","message":str(e)})
        except Exception: pass


@app.websocket("/ws/udpscan")
async def ws_udpscan(ws: WebSocket):
    await ws.accept()
    try:
        data    = await ws.receive_json()
        host    = data.get("host","").strip()
        threads = min(int(data.get("threads",30)), 100)
        timeout = float(data.get("timeout",2.0))
        custom  = data.get("ports","").strip()
        ports   = parse_port_range(custom) if custom else DEFAULT_UDP_PORTS[:]

        if not host: await ws.send_json({"type":"error","message":"No host specified"}); return

        await ws.send_json({"type":"info","message":
            f"UDP Target: {host}  |  Ports: {len(ports)}  |  Threads: {threads}  |  Timeout: {timeout}s"})
        await ws.send_json({"type":"warn","message":"Note: UDP scanning may require root/admin privileges on some systems"})

        sem = asyncio.Semaphore(threads)
        tasks = [scan_port_udp(host,p,sem,timeout) for p in ports]
        found, scanned = [], 0

        for coro in asyncio.as_completed(tasks):
            res = await coro; scanned += 1
            if res["status"] not in ("closed","error"):
                found.append(res["port"])
                await ws.send_json({"type":"result","data":res})
            if scanned % 10 == 0 or scanned == len(ports):
                await ws.send_json({"type":"progress","scanned":scanned,"total":len(ports),"open":len(found)})

        await ws.send_json({"type":"done",
            "message":f"UDP scan complete — {len(found)} open/filtered port(s) found","open_ports":found})
    except WebSocketDisconnect: pass
    except Exception as e:
        try: await ws.send_json({"type":"error","message":str(e)})
        except Exception: pass


@app.websocket("/ws/dirscan")
async def ws_dirscan(ws: WebSocket):
    await ws.accept()
    try:
        data       = await ws.receive_json()
        url        = data.get("url","").strip().rstrip("/")
        raw_words  = data.get("wordlist","").strip()
        exts       = [e.strip().lstrip(".") for e in data.get("extensions","").split(",") if e.strip()]
        threads    = min(int(data.get("threads",50)), 200)
        raw_filter = data.get("status_filter","200,301,302,401,403")
        allowed    = {int(s.strip()) for s in raw_filter.split(",") if s.strip().isdigit()}
        recursive  = bool(data.get("recursive",False))
        do_preview = bool(data.get("preview",False))
        proxy      = data.get("proxy","").strip() or None
        extra_hdrs = data.get("headers",{})

        if not url: await ws.send_json({"type":"error","message":"No URL specified"}); return

        wordlist = [w.strip() for w in raw_words.splitlines() if w.strip()] if raw_words else BUILTIN_WORDLIST

        def build_paths(words):
            paths = []
            for word in words:
                paths.append(word)
                for ext in exts:
                    if not word.endswith(f".{ext}"): paths.append(f"{word}.{ext}")
            return paths

        paths = build_paths(wordlist)

        await ws.send_json({"type":"info","message":
            f"Target: {url}  |  Paths: {len(paths)}  |  Threads: {threads}  |  Recursive: {'on' if recursive else 'off'}  |  Preview: {'on' if do_preview else 'off'}"
            + (f"  |  Proxy: {proxy}" if proxy else "")})

        base_headers = {"User-Agent":"ScanX/2.0 (Authorized Security Testing)"}
        base_headers.update(extra_hdrs)

        sem = asyncio.Semaphore(threads)
        found_total, scanned_total, found_dirs = [], 0, []

        async def probe(session, base_url, path):
            async with sem:
                full = f"{base_url}/{path}"
                try:
                    async with session.get(full, timeout=aiohttp.ClientTimeout(total=6),
                                           allow_redirects=False, ssl=False, proxy=proxy) as r:
                        preview_text = ""
                        if do_preview and r.status in allowed:
                            try:
                                chunk = await r.content.read(400)
                                preview_text = chunk.decode("utf-8",errors="replace").strip()[:200]
                            except Exception: pass
                        return {"path":path,"url":full,"status":r.status,
                                "label":STATUS_LABELS.get(r.status,str(r.status)),
                                "size":r.headers.get("Content-Length","?"),"preview":preview_text}
                except Exception:
                    return None

        conn = aiohttp.TCPConnector(limit=threads, ssl=False)
        async with aiohttp.ClientSession(connector=conn, headers=base_headers) as session:
            tasks = [probe(session,url,p) for p in paths]
            for coro in asyncio.as_completed(tasks):
                res = await coro; scanned_total += 1
                if res and res["status"] in allowed:
                    found_total.append(res)
                    if recursive and res["status"] in (200,301,302) and "." not in res["path"]:
                        found_dirs.append(res["path"])
                    await ws.send_json({"type":"result","data":res})
                if scanned_total % 100 == 0 or scanned_total == len(paths):
                    await ws.send_json({"type":"progress","scanned":scanned_total,"total":len(paths),"found":len(found_total)})

            if recursive and found_dirs:
                await ws.send_json({"type":"info","message":f"Recursive: scanning {len(found_dirs)} director(ies)..."})
                for d in found_dirs:
                    for coro in asyncio.as_completed([probe(session,f"{url}/{d}",p) for p in build_paths(wordlist[:60])]):
                        res = await coro; scanned_total += 1
                        if res and res["status"] in allowed:
                            res["path"] = f"{d}/{res['path']}"; res["url"] = f"{url}/{res['path']}"
                            found_total.append(res)
                            await ws.send_json({"type":"result","data":res})

        await ws.send_json({"type":"done",
            "message":f"Dir scan complete — {len(found_total)} path(s) found out of {scanned_total} tested"})
    except WebSocketDisconnect: pass
    except Exception as e:
        try: await ws.send_json({"type":"error","message":str(e)})
        except Exception: pass


@app.websocket("/ws/subdomain")
async def ws_subdomain(ws: WebSocket):
    await ws.accept()
    try:
        data      = await ws.receive_json()
        domain    = re.sub(r"^https?://","",data.get("domain","").strip()).split("/")[0].lstrip("www.")
        raw_words = data.get("wordlist","").strip()
        threads   = min(int(data.get("threads",100)), 500)

        if not domain: await ws.send_json({"type":"error","message":"No domain specified"}); return

        wordlist = list(dict.fromkeys(
            [w.strip() for w in raw_words.splitlines() if w.strip()] if raw_words else BUILTIN_SUBDOMAINS
        ))

        await ws.send_json({"type":"info","message":
            f"Domain: {domain}  |  Wordlist: {len(wordlist)}  |  Threads: {threads}"})

        sem = asyncio.Semaphore(threads)
        loop = asyncio.get_event_loop()
        found, scanned = [], 0

        async def resolve(sub):
            async with sem:
                fqdn = f"{sub}.{domain}"
                try:
                    info = await loop.getaddrinfo(fqdn,None)
                    ips  = list({r[4][0] for r in info})
                    return {"subdomain":fqdn,"ips":ips,"status":"resolved"}
                except Exception:
                    return {"subdomain":fqdn,"status":"nxdomain"}

        tasks = [resolve(w) for w in wordlist]
        for coro in asyncio.as_completed(tasks):
            res = await coro; scanned += 1
            if res["status"] == "resolved":
                found.append(res)
                await ws.send_json({"type":"result","data":res})
            if scanned % 50 == 0 or scanned == len(wordlist):
                await ws.send_json({"type":"progress","scanned":scanned,"total":len(wordlist),"open":len(found)})

        await ws.send_json({"type":"done",
            "message":f"Subdomain scan complete — {len(found)} resolved out of {len(wordlist)} tested"})
    except WebSocketDisconnect: pass
    except Exception as e:
        try: await ws.send_json({"type":"error","message":str(e)})
        except Exception: pass


@app.websocket("/ws/sslcheck")
async def ws_sslcheck(ws: WebSocket):
    await ws.accept()
    try:
        data = await ws.receive_json()
        host = data.get("host","").strip()
        port = int(data.get("port",443))

        if not host: await ws.send_json({"type":"error","message":"No host specified"}); return

        await ws.send_json({"type":"info","message":f"Inspecting SSL/TLS: {host}:{port}"})

        loop = asyncio.get_event_loop()

        def _check():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            try:
                raw  = socket.create_connection((host,port), timeout=10)
                conn = ctx.wrap_socket(raw, server_hostname=host)
                cert = conn.getpeercert()
                ciph = conn.cipher()
                ver  = conn.version()
                conn.close()
                subj    = dict(x[0] for x in cert.get("subject",[]))
                issuer  = dict(x[0] for x in cert.get("issuer",[]))
                exp_str = cert.get("notAfter","")
                nb_str  = cert.get("notBefore","")
                sans    = [v for (t,v) in cert.get("subjectAltName",[]) if t=="DNS"][:20]
                days_left = None
                try:
                    exp = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp - datetime.utcnow()).days
                except Exception: pass
                return {"ok":True,"subject_cn":subj.get("commonName",""),
                        "issuer_cn":issuer.get("commonName",""),"issuer_org":issuer.get("organizationName",""),
                        "not_before":nb_str,"not_after":exp_str,"days_left":days_left,"sans":sans,
                        "tls_version":ver,"cipher":ciph[0] if ciph else "","cipher_bits":ciph[2] if ciph else 0}
            except Exception as ex:
                return {"ok":False,"error":str(ex)}

        info = await loop.run_in_executor(None, _check)
        await ws.send_json({"type":"ssl_result","data":info})

        if info.get("ok"):
            for chk, val, status in [
                ("Subject CN",   info.get("subject_cn","?"),                                         "INFO"),
                ("Issuer",       f"{info.get('issuer_cn','')} / {info.get('issuer_org','')}",         "INFO"),
                ("Valid From",   info.get("not_before","?"),                                          "INFO"),
                ("Valid Until",  info.get("not_after","?"),                                           "INFO"),
                ("TLS Version",  info.get("tls_version","?"),                                         "INFO"),
                ("Cipher Suite", f"{info.get('cipher','')} ({info.get('cipher_bits',0)} bit)",        "INFO"),
            ]:
                await ws.send_json({"type":"result","data":{"check":chk,"value":val,"status":status}})

            days = info.get("days_left")
            if days is not None:
                st = "CRITICAL" if days < 0 else ("CRITICAL" if days < 15 else ("WARN" if days < 30 else "OK"))
                await ws.send_json({"type":"result","data":{"check":"Expiry",
                    "value":f"{abs(days)} days {'until expiry' if days>=0 else 'EXPIRED'}","status":st}})

            ver = info.get("tls_version","")
            if ver in ("TLSv1","TLSv1.1","SSLv2","SSLv3"):
                await ws.send_json({"type":"result","data":{"check":"Protocol",
                    "value":f"{ver} is deprecated and insecure","status":"CRITICAL"}})

            if info.get("sans"):
                await ws.send_json({"type":"result","data":{"check":"SANs",
                    "value":", ".join(info["sans"][:8])+("..." if len(info["sans"])>8 else ""),"status":"INFO"}})
        else:
            await ws.send_json({"type":"result","data":{"check":"Connection","value":info.get("error","Failed"),"status":"CRITICAL"}})

        await ws.send_json({"type":"done","message":"SSL/TLS inspection complete"})
    except WebSocketDisconnect: pass
    except Exception as e:
        try: await ws.send_json({"type":"error","message":str(e)})
        except Exception: pass


@app.websocket("/ws/headercheck")
async def ws_headercheck(ws: WebSocket):
    await ws.accept()
    try:
        data = await ws.receive_json()
        url  = data.get("url","").strip()

        if not url: await ws.send_json({"type":"error","message":"No URL specified"}); return

        await ws.send_json({"type":"info","message":f"Analyzing HTTP headers: {url}"})

        conn = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=conn) as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                   allow_redirects=True, ssl=False,
                                   headers={"User-Agent":"ScanX/2.0 Security Audit"}) as r:
                hdrs = {k.lower():v for k,v in r.headers.items()}
                await ws.send_json({"type":"info","message":
                    f"HTTP {r.status}  |  Server: {hdrs.get('server','?')}  |  Content-Type: {hdrs.get('content-type','?').split(';')[0]}"})

                missing = 0
                for key, meta in SECURITY_HEADERS.items():
                    if key in hdrs:
                        await ws.send_json({"type":"result","data":{"header":meta["name"],"status":"PRESENT","risk":"OK","value":hdrs[key][:100]}})
                    else:
                        missing += 1
                        await ws.send_json({"type":"result","data":{"header":meta["name"],"status":"MISSING","risk":meta["risk"],"value":meta["desc"]}})

                for lhdr in ("server","x-powered-by","x-aspnet-version","x-aspnetmvc-version","x-generator"):
                    if lhdr in hdrs:
                        await ws.send_json({"type":"result","data":{"header":lhdr.title(),"status":"LEAK","risk":"MEDIUM","value":f"Discloses: {hdrs[lhdr]}"}})

        await ws.send_json({"type":"done","message":f"Header analysis complete — {missing} security header(s) missing"})
    except WebSocketDisconnect: pass
    except Exception as e:
        try: await ws.send_json({"type":"error","message":str(e)})
        except Exception: pass


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    banner = r"""
  ███████╗ ██████╗ █████╗ ███╗   ██╗██╗  ██╗
  ██╔════╝██╔════╝██╔══██╗████╗  ██║╚██╗██╔╝
  ███████╗██║     ███████║██╔██╗ ██║ ╚███╔╝
  ╚════██║██║     ██╔══██║██║╚██╗██║ ██╔██╗
  ███████║╚██████╗██║  ██║██║ ╚████║██╔╝ ██╗
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝"""
    print("\033[92m" + banner + "\033[0m")
    print("  \033[96mAdvanced Security Scanner v2.0  //  by iamunknown77\033[0m")
    print("  \033[90m" + "─"*50 + "\033[0m")
    print("  \033[93m⚠  Use only on systems you own or have permission to test.\033[0m")
    print("  \033[92m●  Endpoints: /ws/portscan  /ws/udpscan  /ws/dirscan")
    print("              /ws/subdomain  /ws/sslcheck  /ws/headercheck\033[0m")
    print(f"  \033[92m●  API: http://0.0.0.0:8000\033[0m\n")
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning")
