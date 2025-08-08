import os
import dns.resolver
import requests
import subprocess
import shlex
import json
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# === API Keys from environment variables ===
VIEWDNS_API_KEY = os.getenv("VIEWDNS_API_KEY", "622f5851adaccc39c603cd9afdd6a6f791ae2b08")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "502b0e42f05a1c")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "4e58e37738104cd8ecbf10f5059e1fdeff0291e1b12243cc859d765bc450b951021ddd088c905a36")

# === DNS Helper Functions ===
def resolve_domain_to_ips(domain):
    ips = []
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            ips.append(rdata.to_text())
    except Exception:
        pass
    return ips

def get_dns_records(domain, record_type):
    records = []
    try:
        answers = dns.resolver.resolve(domain, record_type)
        for rdata in answers:
            records.append(rdata.to_text())
    except Exception:
        pass
    return records

def get_txt_records(domain):
    return get_dns_records(domain, 'TXT')

def get_dkim_selectors(domain):
    selectors = ['default', 'selector1', 'google', 'mail', 'smtp']
    found = {}
    for sel in selectors:
        dkim_domain = f"{sel}._domainkey.{domain}"
        txts = get_txt_records(dkim_domain)
        if txts:
            found[sel] = txts
    return found

# === External API Query Functions ===
def viewdns_dnsrecord(domain):
    try:
        url = f"http://pro.viewdns.info/dnsrecord/?domain={domain}&apikey={VIEWDNS_API_KEY}&output=json"
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": f"ViewDNS error: {str(e)}"}

def ipinfo_ip_lookup(ip):
    try:
        url = f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}"
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": f"IPinfo error: {str(e)}"}

def abuseipdb_lookup(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        query = {"ipAddress": ip, "maxAgeInDays": "90"}
        headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
        resp = requests.get(url, headers=headers, params=query, timeout=15)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": f"AbuseIPDB error: {str(e)}"}

# === Subfinder Subdomain Enumeration ===
def subfinder_scan(domain):
    try:
        cmd = f"./bin/subfinder -d {shlex.quote(domain)} -silent -oJ -"
        process = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=60)
        if process.returncode != 0:
            return {"error": process.stderr.strip()}

        subs = []
        for line in process.stdout.splitlines():
            if line.strip():
                data = json.loads(line)
                if "host" in data:
                    subs.append(data["host"])
        return {"domain": domain, "subdomains": subs}
    except subprocess.TimeoutExpired:
        return {"error": "Subfinder scan timed out."}
    except Exception as e:
        return {"error": str(e)}

# === Flask Routes ===

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/recon')
def api_recon():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error": "Please provide a domain"}), 400

    result = {}
    resolved_ips = resolve_domain_to_ips(domain)
    result["DNS_Resolution"] = {"resolved_ips": resolved_ips or "No A records"}
    result["ViewDNS"] = viewdns_dnsrecord(domain)
    result["DNS_Records"] = {rtype: get_dns_records(domain, rtype) for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA']}

    spf = [txt for txt in get_txt_records(domain) if txt.lower().startswith('v=spf1')]
    dmarc = get_txt_records(f"_dmarc.{domain}")
    dkim = get_dkim_selectors(domain)
    result["Email_Security"] = {
        "SPF": spf or "No SPF record",
        "DMARC": dmarc or "No DMARC record",
        "DKIM": dkim or "No DKIM found"
    }
    return jsonify(result)

@app.route('/api/ipinfo_ip')
def api_ipinfo_ip():
    ip = request.args.get('ip')
    if not ip:
        return jsonify({"error": "Please provide IP address"}), 400
    return jsonify(ipinfo_ip_lookup(ip))

@app.route('/api/abuseipdb_ip')
def api_abuseipdb_ip():
    ip = request.args.get('ip')
    if not ip:
        return jsonify({"error": "Please provide IP address"}), 400
    return jsonify(abuseipdb_lookup(ip))

@app.route('/api/subdomain_scan')
def api_subdomain_scan():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error": "Please provide a domain"}), 400
    return jsonify(subfinder_scan(domain))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
