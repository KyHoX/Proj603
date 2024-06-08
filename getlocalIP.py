# Home network vulnerabilitiy scanner 
# find local IP address via connecting to a specific host outside
# refer document at https://nmap.readthedocs.io/en/latest/index.html
# 

import socket
import psutil
import nmap3
import json 
import ipaddress
import requests
import webbrowser

# Get working IP address of machine. it should be a NIC 
# which connected to a home network
def get_working_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    l_ip_address = s.getsockname()[0]
    # print("Your IP address is: ",l_ip_address)
    s.close()
    return l_ip_address

# Get subnet mask of working IP address
def get_netmask_from_ip(ip_address):
    interfaces = psutil.net_if_addrs()
    for interface_name, interface_addresses in interfaces.items():
        for address in interface_addresses:
            if address.family == 2 and address.address == ip_address:
                return address.netmask
    return None

# Calculate subnet mask bits to build nmap scan value of network
def netmask_to_bit(subnet_mask):
    import netaddr
    netmask_bit = netaddr.IPAddress(subnet_mask).netmask_bits()
    return netmask_bit

# Call nmap scanner to scan openning ports and version of protocols
def nmap_scanner(target_net):
    nmap = nmap3.Nmap()
    # nmap_args = "-n -Pn -sV"
    scan_results = nmap.nmap_version_detection(target_net, args="-O -A -T4 --privileged --script vulners --script-args mincvss=5.0")
    return scan_results

# Check whether it is a valid IPv4 address format
def is_valid_ipv4(address):
    try:
        ip = ipaddress.ip_address(address)
        return ip.version == 4
    except ValueError:
        return False

# Filter nmap result to get only host with status up
# write in JSON structure of each host IP and ports, service name and CPE are optional
def filter_result(raw_data):    
    filter_data = []
    for key, value in raw_data.items():
        if is_valid_ipv4(key):
            # check if the host is up
            if value['state']['state'] == 'up': 
                temp_data = {
                    'hostname': 'none',
                    'MAC_Address':'none',
                    'address':key,
                    'ports':[],
                }
                if len(value['hostname']) > 0:
                    temp_data['hostname'] = value['hostname'][0]['name']
                else:
                    temp_data['hostname'] = 'none'
                if value['macaddress'] is None:
                    temp_data['MAC_Address'] = 'none'                                
                else: 
                    temp_data['MAC_Address'] = value['macaddress']['addr']                   
                if len(value['ports']) > 0:
                    for value_port in value['ports']:
                        if value_port['state'] == 'open':
                            print(f"Host IP {key}: ")
                            print(f"Protocol: {value_port['protocol']}")
                            print(f"Port: {value_port['portid']}")
                            protocol = value_port['protocol']
                            port_id = value_port['portid']
                            if 'service' in value_port:
                                if 'name' in value_port['service']:
                                    print(f"Service Name: {value_port['service']['name']}")
                                    service_name = value_port['service']['name']
                                else:
                                    service_name = 'none'
                                if 'product' in value_port['service']:
                                    print(f"Product name: {value_port['service']['product']}")
                                    product_name = value_port['service']['product']
                                else:
                                    product_name = 'none'
                                if 'version' in value_port['service']:
                                    print(f"Product version: {value_port['service']['version']}")
                                    product_version = value_port['service']['version']
                                else: 
                                    product_version = 'none'
                            if 'cpe' in value_port:
                                cpe = ''
                                if len(value_port['cpe']) > 0:                            
                                    for cpes in value_port['cpe']:
                                        if 'cpe' in cpes: 
                                            print(f"CPE: {cpes['cpe']}")
                                            cpe = cpe + cpes['cpe'] + ','
                                        else:
                                            cpe = 'none'    
                                else:
                                    cpe = 'none'                         
                            else:
                                cpe = 'none'
                            advisories = 'Normal'
                            if 'scripts' in value_port:
                                if len(value_port['scripts']) > 0:
                                    for vul_script in value_port['scripts']:
                                        if ('data' in vul_script) and (cpe != 'none'):
                                            if cpe in vul_script['data']:
                                                for child in vul_script['data'][cpe]['children']:
                                                    if child['is_exploit'] == 'true':
                                                        advisories = 'Exploitable. Please disable or update/upgrade.'
                                                        print(advisories)
                                                        break
                                                    else: 
                                                        advisories = 'Normal'
                            # Collect ports info
                            temp_data['ports'].append({
                                'Protocol': protocol,
                                'Port' : port_id,
                                'Name' : service_name,
                                'Product' : product_name,
                                'Version' : product_version,
                                'CPE' : cpe,
                                'Advisories': advisories,
                                })
                    filter_data.append(temp_data)
    # write filter data to file
    with open('filter_result.json','w') as json_file:
        json.dump(filter_data,json_file, indent=4)
    # print(filter_data) 
    return filter_data

# get public information
# Public IP address
# City, Region, Timezone, ISP name
def get_public_Info():
    endpoint = 'https://ipinfo.io/json'
    response = requests.get(endpoint, verify=True)
    if response.status_code != 200:
        return 'Status:', response.status_code, 'Problem with the request. Exiting.'
        exit()
    data = response.json()
    return data
# list of information we can get
# home_info = get_public_Info()
# print(f"IP address: {home_info['ip']}")
# print(f"City: {home_info['city']}")
# print(f"Country: {home_info['country']}")
# print(f"Region: {home_info['region']}")
# print(f"Time zone: {home_info['timezone']}")
# print(f"ISP: {home_info['org']}")

# Use InternetDB to search for public IP address of home network
# reference guide at https://developer.shodan.io/api
def shodan_search(IP_address):
    API_KEY = "?key=" # API key - use academic key for search
    sd_url = 'https://api.shodan.io/shodan/host/'
    # IP_address = '172.67.193.90'
    qr_string = sd_url + IP_address + API_KEY
    response = requests.get(qr_string, verify=True)
    if response.status_code != 200:
        data = "none"
        return data
    data = response.json()
    return data['ports']

# write data into an HTML file 
def write_to_html(writing_data,html_file):
    home_info = get_public_Info()
    shodan_result = shodan_search(home_info['ip'])
    # shodan_result = shodan_search('172.67.193.90')
    #   Open file location
    with open(html_file, "w") as html_file:
        html_file.write("<html><head><title>Network Scan Results</title></head><body>")
        html_file.write(f"<h2>Network Scan Results</h2>")
        html_file.write("<table border='1'>")
        html_file.write("<tr><th>Host IP</th><th>MAC</th><th>Protocol</th><th>Port</th><th>Service Name</th><th>Suggestions</th></tr>")
        for i in range(len(writing_data)):
        #for host, result in writing_data.item():
            for y in range(len(writing_data[i]['ports'])):                
                html_file.write("<tr>")
                html_file.write(f"<td>{writing_data[i]['address']}</td>")
                html_file.write(f"<td>{writing_data[i]['MAC_Address']}</td>")
                html_file.write(f"<td>{writing_data[i]['ports'][y]['Protocol']}</td>")
                html_file.write(f"<td>{writing_data[i]['ports'][y]['Port']}</td>")
                html_file.write(f"<td>{writing_data[i]['ports'][y]['Name']}</td>")
                html_file.write(f"<td>{writing_data[i]['ports'][y]['Advisories']}</td>")
                html_file.write("</tr>")
        html_file.write("</table>")
        html_file.write("<div>")
        html_file.write(f"Internet address of your home is: <b> {home_info['ip']}</b><br>")
        html_file.write(f"it has {shodan_result} port(s) open to Internet. ")
        html_file.write("</div>")
        html_file.write("</body></html>")
    # print("Results exported to results.html")
    # webbrowser.open("results.html")  # Automatically open the HTML file

if __name__ == '__main__':
    ip_to_find = get_working_ip()
    # print("Your working IP address is: ",ip_to_find)
    netmask_of_ip = get_netmask_from_ip(ip_to_find)
    netmask_num = netmask_to_bit(netmask_of_ip)
    target_net = str(ip_to_find) + "/" + str(netmask_num)
    # target_net = '172.30.1.24'
    if netmask_of_ip:
        print(f"The IP address {ip_to_find} and netmask {netmask_of_ip} of your box, and CIDR is {netmask_num}, target network is {target_net}")
        nmap_result = nmap_scanner(target_net)
        # format JSON value to indent 2
        json_string = json.dumps(nmap_result, indent=4)
        # write scan result to json file
        with open('nmap_home_result.json','w') as json_file:
            json.dump(nmap_result,json_file, indent=4)
        # print(f"{json_string}")
        tmp_data = json.loads(json_string)
        data = filter_result(tmp_data)
        print(f"{data}")
        write_to_html(data,'nmap_results.html')
        webbrowser.open_new_tab('nmap_results.html')
    else:
        print(f"No interface found with the IP address: {ip_to_find}")


