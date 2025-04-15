from flask import Flask, request, jsonify, send_from_directory, send_file
import subprocess
import re
import requests
import time
import os

app = Flask(__name__, static_folder="static")

NESSUS_URL = "https://localhost:8834"
NESSUS_USERNAME = "your_username"
NESSUS_PASSWORD = "your_password"

requests.packages.urllib3.disable_warnings()

def get_nessus_token():
    resp = requests.post(f"{NESSUS_URL}/session", verify=False,
                         json={"username": NESSUS_USERNAME, "password": NESSUS_PASSWORD})
    return resp.json()["token"]

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/interfaces', methods=['GET'])
def get_interfaces():
    try:
        output = subprocess.check_output(['ip', 'link'], text=True)
        interfaces = []
        for line in output.splitlines():
            if ": " in line and not line.startswith(' '):
                iface = line.split(': ')[1].split(':')[0]
                if iface != 'lo':
                    interfaces.append(iface)
        return jsonify(interfaces)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/devices', methods=['POST'])
def get_devices():
    data = request.get_json()
    interface = data.get('interface')
    try:
        netdiscover_output = subprocess.check_output(
            ['netdiscover', '-i', interface, '-P', '-r', '192.168.1.0/24'], text=True)
        return jsonify({'output': netdiscover_output})
    except subprocess.CalledProcessError as e:
        return jsonify({'error': e.output}), 500

@app.route('/scan', methods=['POST'])
def scan_vulnerabilities():
    data = request.get_json()
    ip = data.get('ip')
    if not ip:
        return jsonify({'error': 'No IP provided'}), 400
    try:
        nmap_output = subprocess.check_output(
            ['nmap', '-T4', '--top-ports', '100', '-sV', '--script', 'vuln', ip],
            text=True
        )

        cves = re.findall(r'(CVE-\d{4}-\d+)', nmap_output)
        unique_cves = list(set(cves))

        # 🔍 Generate a user-friendly summary
        summary = "Summary of Findings:\n"
        if "CVE" in nmap_output:
            summary += "- Detected known vulnerabilities associated with specific CVEs.\n"
        if "vulnerable" in nmap_output.lower():
            summary += "- Some services are marked as potentially vulnerable.\n"
        if "ftp" in nmap_output.lower():
            summary += "- FTP service detected. Ensure it is secured or disabled if not needed.\n"
        if "http" in nmap_output.lower():
            summary += "- Web server open. Verify it is patched and protected.\n"
        if "ssl" in nmap_output.lower() or "tls" in nmap_output.lower():
            summary += "- SSL/TLS services found. Check for outdated versions or weak ciphers.\n"
        if "no vulnerabilities" in nmap_output.lower():
            summary += "- No known vulnerabilities were explicitly reported.\n"
        if summary.strip() == "Summary of Findings:":
            summary += "- No specific issues were identified, but manual review is advised.\n"

        return jsonify({
            'nmap': nmap_output,
            'cves': unique_cves,
            'summary': summary
        })
    except subprocess.CalledProcessError as e:
        return jsonify({'error': e.output}), 500

@app.route('/auto_scan_report', methods=['POST'])
def auto_scan_report():
    data = request.get_json()
    ip = data.get('ip')
    if not ip:
        return jsonify({'error': 'No IP provided'}), 400

    try:
        token = get_nessus_token()
        headers = {"X-Cookie": f"token={token}"}

        # Create scan
        scan_data = {
            "uuid": requests.get(f"{NESSUS_URL}/editor/scan/templates", headers=headers, verify=False).json()['templates'][0]['uuid'],
            "settings": {
                "name": f"AutoScan-{ip}",
                "enabled": True,
                "text_targets": ip,
                "launch_now": True
            }
        }
        scan_resp = requests.post(f"{NESSUS_URL}/scans", headers=headers, json=scan_data, verify=False).json()
        scan_id = scan_resp['scan']['id']

        # Wait for scan completion
        while True:
            scan_status = requests.get(f"{NESSUS_URL}/scans/{scan_id}", headers=headers, verify=False).json()
            if scan_status['info']['status'] == 'completed':
                break
            time.sleep(10)

        # Export PDF
        export_data = {"format": "pdf", "chapters": "vuln_hosts_summary"}
        export_resp = requests.post(f"{NESSUS_URL}/scans/{scan_id}/export", headers=headers, json=export_data, verify=False).json()
        file_id = export_resp["file"]

        while True:
            status = requests.get(f"{NESSUS_URL}/scans/{scan_id}/export/{file_id}/status", headers=headers, verify=False).json()
            if status['status'] == 'ready':
                break
            time.sleep(5)

        pdf_response = requests.get(f"{NESSUS_URL}/scans/{scan_id}/export/{file_id}/download", headers=headers, verify=False)
        report_path = f"nessus_auto_report_{ip.replace('.', '_')}.pdf"
        with open(report_path, 'wb') as f:
            f.write(pdf_response.content)

        return jsonify({'download_url': f'/download_report/{report_path}'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download_report/<filename>', methods=['GET'])
def download_report(filename):
    return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
