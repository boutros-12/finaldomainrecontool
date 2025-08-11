import dns.resolver
import requests
import subprocess
import shlex
import json
import whois
import threading
from flask import Flask, request, jsonify, render_template
import shodan
import re
import base64

app = Flask(__name__)

# ====== API KEYS ======
ABUSEIPDB_API_KEY = "4e58e37738104cd8ecbf10f5059e1fdeff0291e1b12243cc859d765bc450b951021ddd088c905a36"
SHODAN_API_KEY = "Ok0alLl8r0kjNjyM0qIArF2mediolsf4"
shodan_api = shodan.Shodan(SHODAN_API_KEY)

# ====== DNS HELPERS ======
def get_dns_records(domain, record_type):
    try:
        return [rdata.to_text() for rdata in dns.resolver.resolve(domain, record_type)]
    except Exception:
        return []

def get_txt_records(domain):
    return get_dns_records(domain, 'TXT')

def resolve_domain_to_ips(domain):
    try:
        return [rdata.to_text() for rdata in dns.resolver.resolve(domain, 'A')]
    except Exception:
        return []

# ====== THREADING WRAPPER ======
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

# ====== SCORING ======
def extract_dkim_key_length(dkim_txt_list):
    for txt in dkim_txt_list:
        record = ''.join(part.strip('"') for part in txt.split())
        m = re.search(r'p=([A-Za-z0-9+/=]+)', record)
        if m:
            try:
                return len(base64.b64decode(m.group(1))) * 8
            except Exception:
                return 0
    return 0

def score_dkim(dkim_txt_list):
    key_len = extract_dkim_key_length(dkim_txt_list)
    if key_len >= 2048: return 100
    elif key_len >= 1024: return 70
    elif key_len > 0: return 50
    return 0

def score_dmarc(dmarc_txt_list):
    if not dmarc_txt_list: return 0
    for txt in dmarc_txt_list:
        m = re.search(r'p=([a-z]+)', txt.lower())
        if m:
            if m.group(1) == 'reject': return 100
            elif m.group(1) == 'quarantine': return 70
            elif m.group(1) == 'none': return 50
    return 0

def score_spf(spf_txt_list):
    if not spf_txt_list: return 0
    for txt in spf_txt_list:
        t = txt.lower()
        if 'v=spf1' in t:
            if '-all' in t: return 100
            elif '~all' in t: return 70
            elif '?all' in t: return 50
            elif '+all' in t: return 20
            else: return 50
    return 0

# ====== RECON API ======
@app.route('/api/recon')
def api_recon():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error": "Please provide a domain"}), 400
    
    SPF_records = [t for t in get_txt_records(domain) if 'v=spf1' in t.lower()]
    DMARC_records = get_txt_records(f"_dmarc.{domain}")

    dkim_selectors = {}
    dkim_scores = {}
    for sel in ['selector1', 'selector2']:
        recs = get_txt_records(f"{sel}._domainkey.{domain}")
        if recs:
            dkim_selectors[sel] = recs
            dkim_scores[sel] = score_dkim(recs)
    
    spf_score = score_spf(SPF_records)
    dmarc_score = score_dmarc(DMARC_records)
    resolved_ips = resolve_domain_to_ips(domain) or "No A records"

    return jsonify({
        "Resolved_IPs": resolved_ips,
        "SPF": {"records": SPF_records or "No SPF record", "score": spf_score},
        "DMARC": {"records": DMARC_records or "No DMARC record", "score": dmarc_score},
        "DKIM": {"records": dkim_selectors or "No DKIM found", "scores": dkim_scores}
    })

# ====== ABUSEIPDB ======
@app.route('/api/abuseipdb_ip')
def api_abuseipdb_ip():
    ip = request.args.get('ip')
    if not ip:
        return jsonify({"error": "Please provide IP address"}), 400
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        query = {"ipAddress": ip, "maxAgeInDays": "90"}
        headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
        r = requests.get(url, headers=headers, params=query, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# ====== SUBFINDER ======
def subfinder_scan(domain):
    try:
        cmd = f"subfinder -d {shlex.quote(domain)} -silent -oJ -"
        p = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=60)
        if p.returncode != 0: return {"error": p.stderr.strip()}
        subs = []
        for line in p.stdout.splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    if "host" in data:
                        subs.append(data["host"])
                except:
                    continue
        return {"domain": domain, "subdomains": subs}
    except subprocess.TimeoutExpired:
        return {"error": "Subfinder timed out"}
    except Exception as e:
        return {"error": str(e)}

threaded_subfinder = threaded(subfinder_scan)

@app.route('/api/subdomain_scan')
def api_subdomain_scan():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error": "Please provide a domain"}), 400
    return jsonify(threaded_subfinder(domain))

# ====== SHODAN ======
@app.route('/api/shodan_ip')
def api_shodan_ip():
    ip = request.args.get('ip')
    if not ip:
        return jsonify({"error": "Please provide IP address"}), 400
    try:
        return jsonify(shodan_api.host(ip))
    except shodan.APIError as e:
        return {"error": f"Shodan API error: {str(e)}"}
    except Exception as e:
        return {"error": str(e)}

# ====== ROOT ======
@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
