import sys
import socket
import psutil
import nmap
import random
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit, QComboBox
from PyQt5.QtCore import QThread, pyqtSignal
from ipaddress import ip_network, ip_interface

class NetworkScannerThread(QThread):
    scan_finished = pyqtSignal(list)

    def __init__(self, ip_range):
        super().__init__()
        self.ip_range = ip_range

    def run(self):
        nm = nmap.PortScanner()
        nm.scan(hosts=self.ip_range, arguments='-sn')
        hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
        self.scan_finished.emit(hosts_list)

class NetworkScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('CSEC 603 IoT Home Network Scanner and Vulnerability')
        self.setGeometry(100, 100, 600, 400)
        
        layout = QVBoxLayout()
        
        self.networkComboBox = QComboBox(self)
        self.populate_networks()
        
        self.resultText = QTextEdit(self)
        self.resultText.setReadOnly(True)
        
        self.scanButton = QPushButton('Scan Network', self)
        self.scanButton.clicked.connect(self.start_scan)
        
        layout.addWidget(QLabel('Select Network Interface:'))
        layout.addWidget(self.networkComboBox)
        layout.addWidget(QLabel('CSEC 603 IoT Home Network Scanner and Vulnerability'))
        layout.addWidget(self.resultText)
        layout.addWidget(self.scanButton)
        
        self.setLayout(layout)

    def populate_networks(self):
        interfaces = psutil.net_if_addrs()
        for interface, addrs in interfaces.items():
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    self.networkComboBox.addItem(interface)

    def get_ip_address(self, interface):
        addrs = psutil.net_if_addrs()[interface]
        for addr in addrs:
            if addr.family == socket.AF_INET:
                return addr.address
        return None

    def get_subnet_and_gateway(self, interface):
        ip_address = None
        netmask = None
        gateway = None

        addrs = psutil.net_if_addrs()[interface]
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ip_address = addr.address
                netmask = addr.netmask

        gateways = psutil.net_if_stats()
        for g in gateways:
            if g == interface and gateways[g].isup:
                gateway = True  # psutil doesn't provide the gateway address directly

        return ip_address, netmask, gateway

    def calculate_subnet_range(self, ip_address, netmask):
        interface = ip_interface(f"{ip_address}/{netmask}")
        network = interface.network
        return str(network)

    def get_vulnerability_rate(self, ip):
        # Mock function for demonstration purposes
        vulnerability_rate = random.choice(['High', 'Medium', 'Low', 'Unknown'])
        return vulnerability_rate

    def get_suggestion(self, vulnerability_rate):
        if vulnerability_rate == 'High':
            return 'Immediate action required. Consider patching and further investigation.'
        elif vulnerability_rate == 'Medium':
            return 'Moderate risk. Monitor and consider updates.'
        elif vulnerability_rate == 'Low':
            return 'Low risk. No immediate action required.'
        else:
            return 'No data available.'

    def start_scan(self):
        selected_interface = self.networkComboBox.currentText()
        ip_address = self.get_ip_address(selected_interface)
        subnet, netmask, gateway = self.get_subnet_and_gateway(selected_interface)
        if ip_address and netmask:
            ip_range = self.calculate_subnet_range(ip_address, netmask)
            self.resultText.append(f'Scanning network: {ip_range}')
            
            self.scan_thread = NetworkScannerThread(ip_range)
            self.scan_thread.scan_finished.connect(self.display_results)
            self.scan_thread.start()
        else:
            self.resultText.append('Error retrieving network information.')

    def display_results(self, hosts):
        report = []
        for host, status in hosts:
            if status == 'up':
                vuln_rate = self.get_vulnerability_rate(host)
                suggestion = self.get_suggestion(vuln_rate)
                report.append(f'Host: {host},port[HIDDEN], Vulnerability Rate: {vuln_rate}, Suggestion: {suggestion}')
        
        self.resultText.append('\n'.join(report))

def main():
    app = QApplication(sys.argv)
    ex = NetworkScannerApp()
    ex.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
