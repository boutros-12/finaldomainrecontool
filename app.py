import dns.resolver
import requests
import subprocess
import shlex
import json
import whois
import threading
import socket
import ssl
import time
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# === API Keys ===
VIEWDNS_API_KEY = "YOUR_VIEWDNS_KEY"
IPINFO_TOKEN = "502b0e42f05a1c"
ABUSEIPDB_API_KEY = "4e58e37738104cd8ecbf10f5059e1fdeff0291e1b12243cc859d765bc450b951021ddd088c905a36"

# ===== DNS Functions =====
def resolve_domain_to_ips(domain):
    try:
        return [rdata.to_text() for rdata in dns.resolver.resolve(domain, 'A')]
    except Exception:
        return []

def get_dns_records(domain, record_type):
    try:
        return [rdata.to_text() for rdata in dns.resolver.resolve(domain, record_type)]
    except Exception:
        return []

def get_txt_records(domain):
    return get_dns_records(domain, 'TXT')

def get_dkim_selectors(domain):
    selectors = ['default', 'selector1', 'google', 'mail', 'smtp']
    found = {}
    for sel in selectors:
        txts = get_txt_records(f"{sel}._domainkey.{domain}")
        if txts:
            found[sel] = txts
    return found

# ===== External API Functions =====
def viewdns_dnsrecord(domain):
    try:
        url = f"http://pro.viewdns.info/dnsrecord/?domain={domain}&apikey={VIEWDNS_API_KEY}&output=json"
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def ipinfo_ip_lookup(ip):
    url = f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}"
    for attempt in range(3):
        try:
            resp = requests.get(url, timeout=(5, 5))
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.Timeout:
            time.sleep(1)
        except Exception as e:
            return {"error": f"IPinfo error: {str(e)}"}
    return {"error": "IPinfo timed out after 3 attempts"}

def abuseipdb_lookup(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
        r = requests.get(url, headers=headers, params=params, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# ===== WHOIS =====
def whois_lookup(domain):
    try:
        return whois.whois(domain).__dict__
    except Exception as e:
        return {"error": str(e)}

# ===== SSL Certificate Info =====
def get_ssl_info(domain):
    try:
        host, port = domain, 443
        if ':' in host:
            host, port = host.split(':', 1)
        ctx = ssl.create_default_context()
        with socket.create_connection((host, int(port)), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return {
                    "subject": cert.get('subject'),
                    "issuer": cert.get('issuer'),
                    "notBefore": cert.get('notBefore'),
                    "notAfter": cert.get('notAfter'),
                    "serialNumber": cert.get('serialNumber', '')
                }
    except Exception as e:
        return {"error": str(e)}

# ===== DNSSEC =====
def get_dnssec_status(domain):
    try:
        if dns.resolver.resolve(domain, 'DNSKEY'):
            return "DNSSEC enabled"
    except dns.resolver.NoAnswer:
        return "No DNSSEC records"
    except Exception as e:
        return f"DNSSEC check error: {str(e)}"
    return "No DNSSEC records"

# ===== HTTP Headers =====
def fetch_http_headers(domain):
    try:
        r = requests.head(f"https://{domain}", timeout=10, allow_redirects=True)
        return dict(r.headers)
    except Exception as e:
        return {"error": str(e)}

# ===== Subfinder Integration =====
def subfinder_scan(domain):
    try:
        cmd = f"subfinder -d {shlex.quote(domain)} -silent -oJ -"
        p = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=60)
        if p.returncode != 0:
            return {"error": p.stderr.strip()}
        subs = []
        for line in p.stdout.splitlines():
            if line.strip():
                data = json.loads(line)
                if "host" in data:
                    subs.append(data["host"])
        return {"domain": domain, "subdomains": subs}
    except subprocess.TimeoutExpired:
        return {"error": "Subfinder scan timed out"}
    except Exception as e:
        return {"error": str(e)}

# ===== Thread Helper =====
def threaded(fn):
    def wrapper(*args, **kwargs):
        result = {}
        def run(): 
            try: result['data'] = fn(*args, **kwargs)
            except Exception as e: result['data'] = {"error": str(e)}
        t = threading.Thread(target=run)
        t.daemon = True
        t.start()
        t.join(timeout=55)
        return result.get('data', {"error": "Timed out"})
    return wrapper

threaded_whois = threaded(whois_lookup)
threaded_subfinder = threaded(subfinder_scan)

# ===== Routes =====
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/recon")
def api_recon():
    domain = request.args.get("domain")
    if not domain:
        return jsonify({"error": "Please provide a domain"}), 400
    return jsonify({
        "DNS_Resolution": {"resolved_ips": resolve_domain_to_ips(domain) or "No A records"},
        "ViewDNS": viewdns_dnsrecord(domain),
        "DNS_Records": {r: get_dns_records(domain, r) for r in ['A','AAAA','MX','NS','TXT','CAA']},
        "Email_Security": {
            "SPF": [t for t in get_txt_records(domain) if t.lower().startswith('v=spf1')] or "No SPF record",
            "DMARC": get_txt_records(f"_dmarc.{domain}") or "No DMARC record",
            "DKIM": get_dkim_selectors(domain) or "No DKIM found"
        },
        "WHOIS": threaded_whois(domain),
        "SSL_Certificate": get_ssl_info(domain),
        "DNSSEC": get_dnssec_status(domain),
        "HTTP_Headers": fetch_http_headers(domain)
    })

@app.route("/api/ipinfo_ip")
def api_ipinfo_ip():
    ip = request.args.get("ip")
    if not ip: return jsonify({"error": "Please provide IP address"}), 400
    return jsonify(ipinfo_ip_lookup(ip))

@app.route("/api/abuseipdb_ip")
def api_abuseipdb_ip():
    ip = request.args.get("ip")
    if not ip: return jsonify({"error": "Please provide IP address"}), 400
    return jsonify(abuseipdb_lookup(ip))

@app.route("/api/subdomain_scan")
def api_subdomain_scan():
    domain = request.args.get("domain")
    if not domain: return jsonify({"error": "Please provide a domain"}), 400
    return jsonify(threaded_subfinder(domain))

if __name__ == "__main__":
    app.run(debug=True)
