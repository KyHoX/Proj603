import socket
import psutil
import nmap3
import json 
import ipaddress
import webbrowser

def get_working_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    l_ip_address = s.getsockname()[0]
    s.close()
    return l_ip_address

def get_netmask_from_ip(ip_address):
    interfaces = psutil.net_if_addrs()
    for interface_name, interface_addresses in interfaces.items():
        for address in interface_addresses:
            if address.family == socket.AF_INET and address.address == ip_address:
                return address.netmask
    return None

def netmask_to_bit(subnet_mask):
    import netaddr
    netmask_bit = netaddr.IPAddress(subnet_mask).netmask_bits()
    return netmask_bit

def nmap_scanner(target_net):
    nmap = nmap3.Nmap()
    print("Scanning network...")
    scan_results = nmap.nmap_version_detection(target_net, args="--privileged --script vulners --script-args mincvss+5.0")
    print("Scanning complete.")
    return scan_results

def is_valid_ipv4(address):
    try:
        ip = ipaddress.ip_address(address)
        return ip.version == 4
    except ValueError:
        return False

def extract_cve_suggestions(scan_results):
    cve_suggestions = {}
    for host, result in scan_results.items():
        if 'ports' in result:  # Check if 'ports' key exists
            for port in result['ports']:
                if 'script' in port and 'vulners' in port['script']:
                    for vuln in port['script']['vulners']:
                        cve = vuln['id']
                        suggestion = vuln['title']
                        if host not in cve_suggestions:
                            cve_suggestions[host] = []
                        cve_suggestions[host].append({'cve': cve, 'suggestion': suggestion})
    return cve_suggestions

def main():
    ip_to_find = get_working_ip()
    netmask_of_ip = get_netmask_from_ip(ip_to_find)
    netmask_num = netmask_to_bit(netmask_of_ip)    
    target_net = str(ip_to_find) + "/" + str(netmask_num)
    if netmask_of_ip:
        with open("results.html", "w") as html_file:
            html_file.write("<html><head><title>Network Scan Results</title></head><body>")
            html_file.write(f"<h2>Network Scan Results</h2>")
            html_file.write("<table border='1'>")
            html_file.write("<tr><th>Host IP</th><th>Protocol</th><th>Port</th><th>Service Name</th><th>CVE Code</th><th>CVE Suggestions</th></tr>")
            nmap_result = nmap_scanner(target_net)
            cve_suggestions = extract_cve_suggestions(nmap_result)
            for host, result in nmap_result.items():
                if is_valid_ipv4(host):
                    if result['state']['state'] == 'up':                    
                        for port in result['ports']:
                            if port['state'] == 'open':
                                html_file.write("<tr>")
                                html_file.write(f"<td>{host}</td>")
                                html_file.write(f"<td>{port['protocol']}</td>")
                                html_file.write(f"<td>{port['portid']}</td>")
                                if 'name' in port['service']:
                                    html_file.write(f"<td>{port['service']['name']}</td>")
                                else:
                                    html_file.write("<td></td>")
                                html_file.write("<td>")
                                if 'script' in port and 'vulners' in port['script']:
                                    for vuln in port['script']['vulners']:
                                        html_file.write(f"<p>{vuln['id']}</p>")
                                html_file.write("</td>")
                                html_file.write("<td>")
                                if host in cve_suggestions:
                                    for suggestion in cve_suggestions[host]:
                                        html_file.write(f"<p>{suggestion['suggestion']}</p>")
                                html_file.write("</td>")
                                html_file.write("</tr>")
            html_file.write("</table>")
            html_file.write("</body></html>")
        print("Results exported to results.html")
        webbrowser.open("results.html")  # Automatically open the HTML file
    else:
        print(f"No interface found with the IP address: {ip_to_find}")

if __name__ == '__main__':
    main()
