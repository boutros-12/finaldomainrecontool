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
VIEWDNS_API_KEY = "622f5851adaccc39c603cd9afdd6a6f791ae2b08"
IPINFO_TOKEN = "502b0e42f05a1c"
ABUSEIPDB_API_KEY = "4e58e37738104cd8ecbf10f5059e1fdeff0291e1b12243cc859d765bc450b951021ddd088c905a36"

# === DNS Helper ===
def get_dns_records(domain, record_type):
    try:
        return [rdata.to_text() for rdata in dns.resolver.resolve(domain, record_type)]
    except Exception:
        return []

def get_txt_records(domain):
    return get_dns_records(domain, 'TXT')

# Thread helper
def threaded(fn):
    def wrapper(*args, **kwargs):
        result = {}
        def run():
            try:
                result['data'] = fn(*args, **kwargs)
            except Exception as e:
                result['data'] = {"error": str(e)}
        t = threading.Thread(target=run)
        t.daemon = True
        t.start()
        t.join(timeout=55)
        return result.get('data', {"error": "Timed out"})
    return wrapper

# WHOIS
def whois_lookup(domain):
    try:
        return whois.whois(domain)
    except Exception as e:
        return {"error": str(e)}

threaded_whois = threaded(whois_lookup)

# === /api/recon Returns SPF, DMARC, DKIM for selector1, selector2 ===
@app.route('/api/recon')
def api_recon():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error": "Please provide a domain"}), 400

    SPF_records = [t for t in get_txt_records(domain) if 'v=spf1' in t.lower()]
    DMARC_records = get_txt_records(f"_dmarc.{domain}")

    dkim_selectors = {}
    for sel in ['selector1', 'selector2']:
        txts = get_txt_records(f"{sel}._domainkey.{domain}")
        if txts:
            dkim_selectors[sel] = txts
    if not dkim_selectors:
        dkim_selectors = "No DKIM found for selector1 or selector2"

    return jsonify({
        "SPF": SPF_records or "No SPF record",
        "DMARC": DMARC_records or "No DMARC record",
        "DKIM": dkim_selectors
    })

# === Subdomain Enumeration ===
def subfinder_scan(domain):
    try:
        cmd = f"subfinder -d {shlex.quote(domain)} -silent -oJ -"
        p = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=60)
        if p.returncode != 0:
            # Return error in JSON instead of HTML
            return {"error": p.stderr.strip()}
        subs = []
        for line in p.stdout.splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    if "host" in data:
                        subs.append(data["host"])
                except json.JSONDecodeError:
                    # Skip lines that aren't valid JSON
                    continue
        return {"domain": domain, "subdomains": subs}
    except subprocess.TimeoutExpired:
        return {"error": "Subfinder scan timed out"}
    except Exception as e:
        return {"error": str(e)}

threaded_subfinder = threaded(subfinder_scan)

@app.route('/api/subdomain_scan')
def api_subdomain_scan():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error": "Please provide a domain"}), 400
    return jsonify(threaded_subfinder(domain))

# === Existing routes for IP info and abuse checks ===
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/ipinfo_ip')
def api_ipinfo_ip():
    ip = request.args.get('ip')
    if not ip:
        return jsonify({"error": "Please provide IP address"}), 400
    try:
        url = f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}"
        resp = requests.get(url, timeout=(5,5))
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}

@app.route('/api/abuseipdb_ip')
def api_abuseipdb_ip():
    ip = request.args.get('ip')
    if not ip:
        return jsonify({"error": "Please provide IP address"}), 400
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        query = {"ipAddress": ip, "maxAgeInDays": "90"}
        headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
        resp = requests.get(url, headers=headers, params=query, timeout=15)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}

if __name__ == '__main__':
    app.run(debug=True)
