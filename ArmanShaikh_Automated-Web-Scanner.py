import ipaddress
import json
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from io import BytesIO

app = Flask(__name__)
app.secret_key = "change-this-development-key"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "Helps browsers enforce HTTPS. Relevant for HTTPS websites."
    ),
    "Content-Security-Policy": (
        "Restricts permitted content sources and can reduce some injection risks."
    ),
    "X-Content-Type-Options": (
        "Use nosniff to reduce MIME-type confusion."
    ),
    "X-Frame-Options": (
        "Helps prevent clickjacking; CSP frame-ancestors is the modern alternative."
    ),
    "Referrer-Policy": (
        "Controls how much referrer information browsers send."
    ),
    "Permissions-Policy": (
        "Controls access to selected browser features."
    ),
}

def validate_public_url(raw_url):
    raw_url = (raw_url or "").strip()
    if not raw_url:
        raise ValueError("Enter a website URL.")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url
    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Enter a valid URL without embedded credentials.")
    if parsed.port and not (1 <= parsed.port <= 65535):
        raise ValueError("Invalid port.")
    host = parsed.hostname.rstrip(".")
    if host.lower() == "localhost" or host.lower().endswith(".localhost"):
        raise ValueError("Localhost targets are blocked.")
    try:
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            answers = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80),
                                         type=socket.SOCK_STREAM)
            addresses = {ipaddress.ip_address(answer[4][0]) for answer in answers}
        except socket.gaierror:
            raise ValueError("The hostname could not be resolved.")
    if not addresses:
        raise ValueError("The hostname did not resolve to an IP address.")
    for address in addresses:
        if not address.is_global:
            raise ValueError("Private, local, and non-public network targets are blocked.")
    return raw_url

def check_result(name, status, detail, severity="Info"):
    return {"name": name, "status": status, "detail": detail, "severity": severity}

def scan_website(raw_url):
    url = validate_public_url(raw_url)
    results = []
    session = requests.Session()
    session.headers.update({"User-Agent": "StudentWebSecurityScanner/1.0 (authorized educational checks)"})
    try:
        response = session.get(url, timeout=(4, 8), allow_redirects=True, stream=True)
        final_url = response.url
        final_parsed = urlparse(final_url)
        if final_parsed.scheme == "https":
            results.append(check_result("HTTPS", "PASS", "The final page uses HTTPS.", "Low"))
        else:
            results.append(check_result("HTTPS", "WARNING", "The final page is not using HTTPS.", "High"))

        for header, explanation in SECURITY_HEADERS.items():
            value = response.headers.get(header)
            if value:
                results.append(check_result(header, "PASS", f"Present: {value[:220]}. {explanation}", "Low"))
            else:
                if header == "Strict-Transport-Security" and final_parsed.scheme != "https":
                    detail = "Missing; only evaluate HSTS after HTTPS is correctly configured. " + explanation
                    severity = "Info"
                else:
                    detail = "Not detected in the response. " + explanation
                    severity = "Medium" if header in ("Content-Security-Policy", "X-Content-Type-Options") else "Low"
                results.append(check_result(header, "WARNING", detail, severity))

        cors = response.headers.get("Access-Control-Allow-Origin")
        if cors == "*":
            results.append(check_result("CORS", "REVIEW", "Access-Control-Allow-Origin is '*'. This may be intentional for public resources; review whether sensitive data is exposed.", "Medium"))
        elif cors:
            results.append(check_result("CORS", "INFO", f"Access-Control-Allow-Origin is set to {cors[:220]}. Verify it matches the intended trusted origins.", "Low"))
        else:
            results.append(check_result("CORS", "INFO", "No Access-Control-Allow-Origin header was seen on this GET response. This does not prove CORS is secure or insecure.", "Info"))

        results.append(check_result("Redirects", "INFO", f"Final URL: {final_url}; redirect count: {len(response.history)}.", "Info"))
        results.append(check_result("Server banner", "INFO", f"Server header: {response.headers.get('Server', 'Not disclosed')}. Server banners alone do not establish a vulnerability.", "Info"))
        status_code = response.status_code
        response.close()
        return {
            "url": url,
            "final_url": final_url,
            "status_code": status_code,
            "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "results": results,
            "notice": "Automated checks are indicators, not proof of vulnerability. Review findings manually."
        }
    except requests.exceptions.SSLError:
        raise ValueError("TLS/SSL verification failed. The scanner does not bypass certificate validation.")
    except requests.exceptions.Timeout:
        raise ValueError("The website took too long to respond.")
    except requests.exceptions.RequestException as exc:
        raise ValueError(f"Could not scan this website: {type(exc).__name__}. Check the URL and try again.")

@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    if request.method == "POST":
        try:
            report = scan_website(request.form.get("url", ""))
            session_data = json.dumps(report)
            return render_template("index.html", report=report, submitted_url=request.form.get("url", ""), report_json=session_data)
        except ValueError as exc:
            flash(str(exc), "error")
    return render_template("index.html", report=report, submitted_url="", report_json="")

@app.post("/download")
def download_report():
    raw = request.form.get("report_json", "")
    try:
        data = json.loads(raw)
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            raise ValueError()
    except (json.JSONDecodeError, ValueError):
        flash("Report data was invalid. Please run the scan again.", "error")
        return redirect(url_for("index"))
    output = BytesIO(json.dumps(data, indent=2).encode("utf-8"))
    output.seek(0)
    return send_file(output, mimetype="application/json", as_attachment=True,
                     download_name="web_security_scan_report.json")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
