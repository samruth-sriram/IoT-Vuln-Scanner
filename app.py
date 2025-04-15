from flask import Flask, request, jsonify, send_from_directory
import subprocess
import re

app = Flask(__name__, static_folder="static")

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
        netdiscover_output = subprocess.check_output(['netdiscover', '-i', interface, '-P', '-r', '192.168.1.0/24'], text=True)
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
        nmap_output = subprocess.check_output(['nmap', '-Pn', '-sV', '--script', 'vuln', '-T4', ip], text=True)

        cves = re.findall(r'(CVE-\d{4}-\d+)', nmap_output)
        unique_cves = list(set(cves))

        metasploit_result = subprocess.check_output(['msfconsole', '-q', '-x',
            f"use auxiliary/scanner/portscan/tcp; set RHOSTS {ip}; run; exit"
        ], text=True)

        return jsonify({
            'nmap': nmap_output,
            'cves': unique_cves,
            'metasploit': metasploit_result
        })
    except subprocess.CalledProcessError as e:
        return jsonify({'error': e.output}), 500

if __name__ == '__main__':
    app.run(debug=True)
