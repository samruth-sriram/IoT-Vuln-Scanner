🔐 Automated Tool for Vulnerability Detection in IoT Ecosystems
A powerful, all-in-one tool for discovering, scanning, and reporting vulnerabilities across IoT networks. This project integrates Netdiscover, Nmap, Nessus, and Metasploit to automate the process of identifying and explaining potential security threats within IoT ecosystems.

🚀 Features

✅ Network Discovery
Automatically identify live hosts on the network using Netdiscover.

🔍 Port & Service Scanning
Perform comprehensive scanning with Nmap to detect open ports and running services.

🛡️ Vulnerability Assessment
Utilize Nessus to identify vulnerabilities and misconfigurations.

💥 Exploit Verification
Validate critical vulnerabilities through Metasploit exploitation modules.

📊 Human-Readable Reports
Generate summarized reports with vulnerability descriptions and their real-world impacts.

🎛️ IP Dropdown Selection
Easy-to-use interface to select discovered IPs directly from a dropdown list.

🧰 Tools Used

Tool	Role in the System
Netdiscover	Discover active hosts within the local network
Nmap	Scan ports and detect service versions
Nessus	Perform detailed vulnerability assessments
Metasploit	Verify vulnerabilities with proof-of-concept exploits
📸 Screenshots
<em>(Add your tool's UI screenshots here – showing dropdown IP selection, report view, etc.)</em>

🛠️ How It Works
Scan the Network
Start with Netdiscover to list all active IoT devices in the network.

Choose a Target IP
Select an IP from the dropdown (populated dynamically from Netdiscover results).

Run Nmap Scan
Conduct an in-depth scan on the selected IP to detect ports, services, and OS.

Assess Vulnerabilities with Nessus
Feed the data into Nessus to get a list of potential vulnerabilities.

Validate with Metasploit (Optional)
For high-risk vulnerabilities, attempt exploitation using Metasploit modules.

View Report
Review the summarized report with actionable insights.

📦 Installation
⚠️ Ensure you have administrative privileges and that all tools are installed and configured properly.

Prerequisites :
-> Python 3.x
-> Netdiscover
-> Nmap
-> Nessus (with API access)
-> Metasploit Framework

Clone the Repository

git clone https://github.com/your-username/iot-vuln-scanner.git
cd iot-vuln-scanner

Install Python Dependencies

pip install -r requirements.txt

🧪 Usage

python main.py

From the interface:
--> Select a device from the dropdown
--> Run scans in sequence
--> Generate report

📁 Project Structure

iot-vuln-scanner/
│
├── netdiscover_module/    # Handles network discovery
├── nmap_module/           # Nmap scan logic & parsing
├── nessus_module/         # Integration with Nessus API
├── metasploit_module/     # Metasploit automation
├── ui/                    # Frontend dropdown & interaction
├── reports/               # Generated reports
└── main.py                # Main orchestrator script

🧠 Future Improvements

Real-time alerts via email/Slack
CVE links and fix recommendations
Integration with Shodan or OSINT tools

🤝 Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you'd like to change.

📄 License
This project is licensed under the MIT License.
