import dns.resolver
import requests
import subprocess
import shlex
import json
import whois
import threading
import socket
import ssl
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# === API Keys (leave as is per your request) ===
VIEWDNS_API_KEY = "622f5851adaccc39c603cd9afdd6a6f791ae2b08"
IPINFO_TOKEN = "502b0e42f05a1c"
ABUSEIPDB_API_KEY = "4e58e37738104cd8ecbf10f5059e1fdeff0291e1b12243cc859d765bc450b951021ddd088c905a36"

# === DNS Helpers ===
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

# === External APIs ===
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

# === WHOIS Integration ===
def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return w.__dict__
    except Exception as e:
        return {"error": f"WHOIS error: {str(e)}"}

# === SSL Certificate fetch ===
def get_ssl_info(domain):
    host = domain
    if ':' in host:
        host, port = host.split(':', 1)
    else:
        port = 443
    ctx = ssl.create_default_context()
    try:
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
        return {"error": f"SSL error: {str(e)}"}

# === DNSSEC status ===
def get_dnssec_status(domain):
    try:
        answers = dns.resolver.resolve(domain, 'DNSKEY')
        return "DNSSEC enabled" if answers else "No DNSSEC records"
    except dns.resolver.NoAnswer:
        return "No DNSSEC records"
    except Exception as e:
        return f"DNSSEC check error: {str(e)}"

# === HTTP headers ===
def fetch_http_headers(domain):
    try:
        url = f"https://{domain}"
        r = requests.head(url, timeout=10, allow_redirects=True)
        return dict(r.headers)
    except Exception as e:
        return {"error": f"HTTP headers error: {str(e)}"}

# === Subfinder Integration ===
def subfinder_scan(domain):
    try:
        cmd = f"subfinder -d {shlex.quote(domain)} -silent -oJ -"
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

# Common port to service mapping (partial, can be extended)
COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    443: "HTTPS",
    445: "Microsoft-DS",
    465: "SMTP over SSL",
    587: "SMTP (submission)",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP Alternate",
}

# === Threaded fast port scanner with service name detection ===
def threaded_port_scan(ip, ports="1-1024", timeout=0.4, max_threads=200):
    port_list = []
    try:
        if '-' in ports:
            start, end = ports.split('-')
            port_list = list(range(int(start), int(end) + 1))
        else:
            port_list = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]
    except:
        port_list = [int(ports)]

    open_ports = []
    lock = threading.Lock()

    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    with lock:
                        service = COMMON_PORTS.get(port, "Unknown")
                        open_ports.append({"port": port, "service": service})
        except:
            pass

    threads = []
    for port in port_list:
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()
        if len(threads) >= max_threads:
            for tt in threads:
                tt.join()
            threads = []

    for tt in threads:
        tt.join()

    return {"ip": ip, "open_ports": sorted(open_ports, key=lambda x: x["port"])}

# === Thread wrapper for heavy functions ===
def threaded(fn):
    def wrapper(*args, **kwargs):
        result = {}
        def run():
            try:
                result["data"] = fn(*args, **kwargs)
            except Exception as e:
                result["data"] = {"error": str(e)}
        t = threading.Thread(target=run)
        t.daemon = True
        t.start()
        t.join(timeout=55)
        return result.get("data", {"error": "Timed out."})
    return wrapper

threaded_whois = threaded(whois_lookup)
threaded_subfinder = threaded(subfinder_scan)
threaded_portscan = threaded(threaded_port_scan)

# === Flask Routes ===
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/recon")
def api_recon():
    domain = request.args.get("domain")
    if not domain:
        return jsonify({"error": "Please provide a domain"}), 400
    result = {
        "DNS_Resolution": {"resolved_ips": resolve_domain_to_ips(domain) or "No A records"},
        "ViewDNS": viewdns_dnsrecord(domain),
        "DNS_Records": {rtype: get_dns_records(domain, rtype) for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA']},
        "Email_Security": {
            "SPF": [txt for txt in get_txt_records(domain) if txt.lower().startswith('v=spf1')] or "No SPF record",
            "DMARC": get_txt_records(f"_dmarc.{domain}") or "No DMARC record",
            "DKIM": get_dkim_selectors(domain) or "No DKIM found"
        },
        "WHOIS": threaded_whois(domain),
        "SSL_Certificate": get_ssl_info(domain),
        "DNSSEC": get_dnssec_status(domain),
        "HTTP_Headers": fetch_http_headers(domain)
    }
    return jsonify(result)

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

@app.route("/api/portscan")
def api_portscan():
    ip = request.args.get("ip")
    ports = request.args.get("ports", "1-1024")
    if not ip: return jsonify({"error": "Please provide IP address"}), 400
    return jsonify(threaded_portscan(ip, ports))

if __name__ == "__main__":
    app.run(debug=True)
