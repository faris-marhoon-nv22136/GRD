#!/usr/bin/python3
import nmap
import json
import requests
from scapy.all import *
import sys
from shodan import Shodan
from msfrpc import MsfRpcClient
from routersploit.core.exploit.printer import print_status
from routersploit.core.exploit.utils import random_text
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import numpy as np
import pandas as pd
from reportlab.pdfgen import canvas
from jinja2 import Environment, FileSystemLoader
import time
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
import os
import joblib

# Load configuration
with open('config.json') as config_file:
    config = json.load(config_file)

class AdvancedRouterSecurityTool:
    def __init__(self):
        self.nmap = nmap.PortScanner()
        self.shodan = Shodan(config['SHODAN_API_KEY'])
        self.metasploit = MsfRpcClient("msf", port=55553)
        self.router_ip = self.detect_gateway()
        self.router_model = ""
        self.router_details = {
            "ip": self.router_ip,
            "os": "",
            "services": [],
            "model": ""
        }
        self.vulnerabilities = []
        self.exploit_results = []
        self.ml_predictions = {}
        self.ml_model = self.load_pretrained_model()
        self.scaler = self.load_scaler()
        self.encoder = self.load_encoder()
        
        self.legal_disclaimer()

    def legal_disclaimer(self):
        print("""
        ==============================================
        LEGAL DISCLAIMER
        ==============================================
        This tool is designed for authorized penetration testing only.
        Ensure you have explicit permission to test the target network.
        Unauthorized use may violate laws and regulations.
        ==============================================
        """)

    def detect_gateway(self):
        try:
            return subprocess.check_output(
                "ip route show default | awk '{print $3}'", shell=True
            ).decode().strip()
        except:
            return "192.168.1.1"

    def load_pretrained_model(self):
        if os.path.exists('pretrained_models/router_security_model.joblib'):
            return joblib.load('pretrained_models/router_security_model.joblib')
        else:
            print("[-] Pretrained ML model not found. Training a basic model...")
            return self.train_basic_model()

    def load_scaler(self):
        if os.path.exists('pretrained_models/scaler.joblib'):
            return joblib.load('pretrained_models/scaler.joblib')
        else:
            return StandardScaler()

    def load_encoder(self):
        if os.path.exists('pretrained_models/encoder.joblib'):
            return joblib.load('pretrained_models/encoder.joblib')
        else:
            return LabelEncoder()

    def train_basic_model(self):
        # Basic dataset for model training
        data = {
            'feature1': [1, 0, 1, 0, 1],
            'feature2': [0.8, 0.3, 0.6, 0.9, 0.7],
            'feature3': [8.5, 5.0, 7.0, 6.0, 9.8],
            'label': [1, 0, 1, 0, 1]
        }
        df = pd.DataFrame(data)
        X = df[['feature1', 'feature2', 'feature3']]
        y = df['label']
        
        model = RandomForestClassifier(n_estimators=100)
        model.fit(X, y)
        return model

    def scan_network(self):
        print("[+] Performing advanced network scan...")
        self.nmap.scan(self.router_ip, arguments="-sV -O -sC --script vulners,http-vulners*,ssl-enum-ciphers")
        
        # OS detection
        if 'osclass' in self.nmap[self.router_ip]:
            os_info = self.nmap[self.router_ip]['osclass'][0]
            self.router_details['os'] = f"{os_info['osfamily']} {os_info['osgen']}"
        
        # Service and port detection
        for proto in self.nmap[self.router_ip].all_protocols():
            ports = self.nmap[self.router_ip][proto].keys()
            for port in ports:
                if self.nmap[self.router_ip][proto][port]['state'] == 'open':
                    service_info = self.nmap[self.router_ip][proto][port]
                    self.router_details['services'].append({
                        'port': port,
                        'protocol': proto,
                        'service': service_info['name'],
                        'version': service_info['version'],
                        'cpe': service_info['cpe'] if 'cpe' in service_info else ''
                    })

    def cross_reference_cve(self):
        print("[+] Cross-referencing with CVE databases...")
        for service in self.router_details['services']:
            cve_data = self.fetch_cve_data(service)
            if cve_data:
                self.vulnerabilities.extend(cve_data['cves'])

    def fetch_cve_data(self, service_info):
        headers = {
            "Authorization": f"Bearer {config['OPENCVE_API_KEY']}"
        }
        params = {
            "vendor": service_info['service'],
            "product": service_info['service'],
            "version": service_info['version']
        }

        try:
            response = requests.get("https://app.opencve.io/api/cve", headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            cves = []
            for item in data.get("results", []):
                cves.append({
                    'cve_id': item.get('cve_id'),
                    'description': item.get('description'),
                    'severity': item.get('severity'),
                    'cvss_score': item.get('cvss_score', 0),
                    'exploit_available': item.get('exploit_available', False)
                })
            return {"service": service_info['service'], "cves": cves}
        except requests.exceptions.RequestException as e:
            print(f"[-] Failed to fetch CVEs for {service_info['service']}: {e}")
            return {"service": service_info['service'], "cves": []}

    def ml_analysis(self):
        print("[+] Performing ML analysis on scan results...")
        features = []
        for service in self.router_details['services']:
            # Extract features from service information
            port = service['port']
            protocol = 1 if service['protocol'] == 'udp' else 0
            cvss_score = max([cve['cvss_score'] for cve in self.vulnerabilities 
                             if cve['service'] == service['service']] + [0])
            service_type = service['service']
            
            # Encode service type
            try:
                encoded_service = self.encoder.transform([service_type])
            except:
                self.encoder.fit([service_type])
                encoded_service = self.encoder.transform([service_type])
            
            features.append([
                port,
                protocol,
                cvss_score,
                encoded_service[0]
            ])
        
        if features:
            scaled_features = self.scaler.transform(features)
            predictions = self.ml_model.predict(scaled_features)
            self.ml_predictions = {
                'high_risk_services': [self.router_details['services'][i] 
                                      for i, pred in enumerate(predictions) if pred == 1],
                'predicted_threats': predictions.tolist()
            }

    def test_vulnerabilities(self):
        print("[+] Validating vulnerabilities through automated testing...")
        for cve in self.vulnerabilities:
            if cve['exploit_available']:
                exploit_info = self.analyze_exploit(cve['cve_id'])
                if exploit_info:
                    test_result = self.simulate_attack(cve, exploit_info)
                    self.exploit_results.append({
                        'cve_id': cve['cve_id'],
                        'exploit_info': exploit_info,
                        'result': test_result,
                        'risk_level': self.calculate_risk(cve, test_result)
                    })

    def analyze_exploit(self, cve_id):
        # Search Exploit-DB
        exploit_db_response = requests.get(f"https://www.exploit-db.com/search/{cve_id}")
        if exploit_db_response.status_code == 200 and 'Exploits' in exploit_db_response.text:
            return {
                'source': 'Exploit-DB',
                'details': exploit_db_response.json()
            }
        
        # Search Rapid7
        rapid7_response = requests.get(f"https://www.rapid7.com/db/vulnerabilities/{cve_id}")
        if rapid7_response.status_code == 200:
            return {
                'source': 'Rapid7',
                'details': rapid7_response.json()
            }
        
        return None

    def simulate_attack(self, cve, exploit_info):
        print(f"[+] Simulating attack for {cve['cve_id']}...")
        try:
            # Use Metasploit RPC to simulate exploit
            exploit_module = self.metasploit.modules.use('exploit', exploit_info['details']['module_path'])
            exploit_module['RHOSTS'] = self.router_ip
            exploit_result = exploit_module.execute()
            
            # Analyze results
            if exploit_result['job_id'] and exploit_result['data']['status'] == 'success':
                return {
                    'status': 'exploitable',
                    'evidence': exploit_result['data']['output']
                }
            else:
                return {
                    'status': 'not exploitable',
                    'reason': exploit_result['data']['output']
                }
        except Exception as e:
            return {
                'status': 'unknown',
                'error': str(e)
            }

    def calculate_risk(self, cve, test_result):
        base_score = cve['cvss_score']
        exploitability = 1 if test_result['status'] == 'exploitable' else 0
        ml_prediction = 1 if any(pred == 1 for pred in self.ml_predictions['predicted_threats']) else 0
        
        risk_score = (base_score * 0.6) + (exploitability * 0.3) + (ml_prediction * 0.1)
        if risk_score >= 9:
            return 'Critical'
        elif risk_score >= 7:
            return 'High'
        elif risk_score >= 4:
            return 'Medium'
        else:
            return 'Low'

    def generate_report(self):
        print("[+] Generating comprehensive security report...")
        # Create report directory if not exists
        report_dir = "reports"
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"{report_dir}/router_security_report_{timestamp}.pdf"
        
        # Create PDF report
        pdf = canvas.Canvas(report_filename)
        pdf.setFont("Helvetica-Bold", 16)
        pdf.drawString(100, 750, "Router Security Assessment Report")
        
        y_position = 700
        pdf.setFont("Helvetica", 12)
        pdf.drawString(100, y_position, f"Router IP: {self.router_ip}")
        y_position -= 20
        pdf.drawString(100, y_position, f"Detected OS: {self.router_details['os']}")
        y_position -= 20
        pdf.drawString(100, y_position, f"Model: {self.router_model}")
        y_position -= 40
        
        pdf.drawString(100, y_position, "Discovered Services:")
        y_position -= 20
        for service in self.router_details['services']:
            pdf.drawString(120, y_position, f"Port {service['port']}/{service['protocol']}: {service['service']} {service['version']}")
            y_position -= 15
        
        y_position -= 20
        pdf.drawString(100, y_position, "Identified Vulnerabilities:")
        y_position -= 20
        for vuln in self.vulnerabilities:
            pdf.drawString(120, y_position, f"{vuln['cve_id']} - {vuln['description']} (Severity: {vuln['severity']})")
            y_position -= 15
        
        y_position -= 20
        pdf.drawString(100, y_position, "Exploit Validation Results:")
        y_position -= 20
        for result in self.exploit_results:
            status = result['result']['status'].upper()
            pdf.drawString(120, y_position, f"{result['cve_id']} - {status} (Risk Level: {result['risk_level']})")
            y_position -= 15
        
        y_position -= 20
        pdf.drawString(100, y_position, "ML Predictions:")
        y_position -= 20
        for pred in self.ml_predictions['high_risk_services']:
            pdf.drawString(120, y_position, f"High-risk service detected: {pred['service']} on port {pred['port']}")
            y_position -= 15
        
        y_position -= 40
        pdf.drawString(100, y_position, "Recommendations:")
        recommendations = [
            "Apply the latest firmware updates immediately.",
            "Disable unnecessary services and ports.",
            "Implement network segmentation to limit exposure.",
            "Configure strong authentication mechanisms.",
            "Deploy intrusion detection/prevention systems (IDS/IPS).",
            "Regularly monitor network traffic for anomalies."
        ]
        for i, rec in enumerate(recommendations, 1):
            pdf.drawString(120, y_position, f"{i}. {rec}")
            y_position -= 15
        
        pdf.save()
        
        print(f"[+] Report generated successfully: {report_filename}")

    def run(self):
        print("[+] Starting Advanced Router Security Assessment...")
        self.scan_network()
        self.cross_reference_cve()
        self.ml_analysis()
        self.test_vulnerabilities()
        self.generate_report()
        print("[+] Assessment completed.")

if __name__ == "__main__":
    tool = AdvancedRouterSecurityTool()
    tool.run()