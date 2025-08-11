import dns.resolver, requests, subprocess, shlex, json, threading, re, base64
from flask import Flask, request, jsonify, render_template
import shodan

app = Flask(__name__)

# === API Keys ===
ABUSEIPDB_API_KEY = "4e58e37738104cd8ecbf10f5059e1fdeff0291e1b12243cc859d765bc450b951021ddd088c905a36"
SHODAN_API_KEY = "HgtpvC3QpPQdudjjvom8KsmQbLVYm1tw"
shodan_api = shodan.Shodan(SHODAN_API_KEY)

# Common DKIM selectors
COMMON_DKIM_SELECTORS = ["selector1", "selector2", "default", "google", "k1"]

# === DNS Helpers ===
def get_dns_records(domain, record_type):
    try:
        return [rdata.to_text() for rdata in dns.resolver.resolve(domain, record_type)]
    except Exception:
        return []

def get_txt_records(domain):
    return get_dns_records(domain, 'TXT')

def resolve_domain_to_ips(domain):
    return get_dns_records(domain, 'A')

def get_mx_records(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return [f"{r.preference} {r.exchange.to_text()}" for r in answers]
    except Exception:
        return []

# === Thread wrapper ===
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

# === Scoring ===
def extract_dkim_key_length(lst):
    for txt in lst:
        record = ''.join(part.strip('"') for part in txt.split())
        m = re.search(r'p=([A-Za-z0-9+/=]+)', record)
        if m:
            try:
                return len(base64.b64decode(m.group(1))) * 8
            except Exception:
                return 0
    return 0

def score_dkim(lst):
    k = extract_dkim_key_length(lst)
    if k >= 2048: return 100
    elif k >= 1024: return 70
    elif k > 0: return 50
    return 0

def score_dmarc(lst):
    if not lst: return 0
    for txt in lst:
        m = re.search(r'p=([a-z]+)', txt.lower())
        if m:
            if m.group(1) == 'reject': return 100
            elif m.group(1) == 'quarantine': return 70
            elif m.group(1) == 'none': return 50
    return 0

def score_spf(lst):
    if not lst: return 0
    for txt in lst:
        t = txt.lower()
        if 'v=spf1' in t:
            if '-all' in t: return 100
            elif '~all' in t: return 70
            elif '?all' in t: return 50
            elif '+all' in t: return 20
            else: return 50
    return 0

# === Recon API ===
@app.route('/api/recon')
def api_recon():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error":"Please provide a domain"}), 400

    SPF = [t for t in get_txt_records(domain) if 'v=spf1' in t.lower()]
    DMARC = get_txt_records(f"_dmarc.{domain}")
    MX = get_mx_records(domain)
    IPs = resolve_domain_to_ips(domain) or "No A records"

    dkim_recs, dkim_scores = {}, {}
    for sel in COMMON_DKIM_SELECTORS:
        recs = get_txt_records(f"{sel}._domainkey.{domain}")
        if recs:
            dkim_recs[sel] = recs
            dkim_scores[sel] = score_dkim(recs)

    return jsonify({
        "Resolved_IPs": IPs,
        "MX_Records": MX or "No MX record",
        "SPF": {"records": SPF or "No SPF record", "score": score_spf(SPF)},
        "DMARC": {"records": DMARC or "No DMARC record", "score": score_dmarc(DMARC)},
        "DKIM": {"records": dkim_recs or "No DKIM found", "scores": dkim_scores}
    })

# === AbuseIPDB ===
@app.route('/api/abuseipdb_ip')
def api_abuseipdb_ip():
    ip = request.args.get('ip')
    if not ip:
        return jsonify({"error":"Please provide IP address"}), 400
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
            headers={"Accept":"application/json", "Key":ABUSEIPDB_API_KEY},
            params={"ipAddress":ip, "maxAgeInDays":"90"}, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# === Subfinder ===
def subfinder_scan(domain):
    try:
        p = subprocess.run(shlex.split(f"subfinder -d {shlex.quote(domain)} -silent -oJ -"),
                           capture_output=True, text=True, timeout=60)
        if p.returncode != 0:
            return {"error": p.stderr.strip()}
        subs = []
        for line in p.stdout.splitlines():
            if line.strip():
                try:
                    data = json.loads(line)
                    if "host" in data: subs.append(data["host"])
                except json.JSONDecodeError: continue
        return {"domain": domain, "subdomains": subs}
    except subprocess.TimeoutExpired:
        return {"error": "Subfinder timed out"}
    except Exception as e:
        return {"error": str(e)}

@app.route('/api/subdomain_scan')
def api_subdomain_scan():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error":"Please provide a domain"}), 400
    return jsonify(threaded(subfinder_scan)(domain))

# === Shodan API ===
@app.route('/api/shodan_ip')
def api_shodan_ip():
    ip = request.args.get('ip')
    if not ip:
        return jsonify({"error":"Please provide IP address"}), 400
    try:
        return jsonify(shodan_api.host(ip))
    except shodan.APIError as e:
        return jsonify({"error": f"Shodan API error: {str(e)}"})
    except Exception as e:
        return jsonify({"error": str(e)})

# === Frontend ===
@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
