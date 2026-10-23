# Automated Web Security Scanner

A beginner-friendly cybersecurity project built with Python, Flask, Requests, HTML, and CSS.

## Features
- Checks HTTPS usage after redirects.
- Looks for six common HTTP security headers.
- Displays basic CORS response signals with cautious interpretation.
- Shows HTTP status, final URL, redirect count, and server banner.
- Downloads a JSON report.
- Blocks localhost and non-public IP address targets.
- Uses TLS certificate verification and request timeouts.

## Requirements
- Python 3.10 or newer
- Internet connection for package installation and scanning
- Windows, macOS, or Linux

## Run on Windows
1. Extract the project ZIP.
2. Install Python 3.10+ from https://www.python.org/downloads/ and enable "Add Python to PATH".
3. Double-click `run_windows.bat`, or open a terminal in this folder and run:

```powershell
py -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python app.py
```

4. Open `http://127.0.0.1:5000` in your browser.
5. Enter a website URL and click **Scan Website**.

## Run on macOS/Linux
```bash
chmod +x run_mac_linux.sh
./run_mac_linux.sh
```
Then open `http://127.0.0.1:5000`.

## Suggested demonstration
Use a website you own or have explicit permission to test. Run one scan, explain PASS/WARNING/REVIEW/INFO labels, and download the JSON report. Do not treat missing headers as automatic proof of a vulnerability.

## Limitations
- This is a small educational scanner, not a full penetration-testing tool.
- It makes a single GET request and does not crawl pages, exploit vulnerabilities, or authenticate.
- CORS results from one response are only preliminary signals; proper testing needs controlled origin-based requests and context.
- Some sites block automated clients, use dynamic behavior, or have headers set at a CDN/proxy layer.
- DNS validation helps block private/local targets but is not a substitute for production-grade network egress controls.
- Run locally for coursework. Do not expose the Flask development server to the public internet.
- Before using this outside a classroom, replace the development secret key and add production-grade deployment controls.

## Project structure
- `app.py` — validation, scanning logic, and Flask routes
- `templates/index.html` — user interface
- `static/style.css` — responsive styling
- `requirements.txt` — Python dependencies
- `PROJECT_REPORT.docx` — project documentation

## Troubleshooting
- If `py` is not recognized, install Python and enable PATH, then reopen the terminal.
- If port 5000 is occupied, change `port=5000` at the bottom of `app.py` to `port=5001`, then visit `http://127.0.0.1:5001`.
- If dependency installation fails, check internet access and run `python -m pip install -r requirements.txt` inside the activated environment.
