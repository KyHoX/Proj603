import socket
import json
import nmap3

# nmap = nmap3.Nmap()
# scan_results = nmap.nmap_version_detection("10.0.3.4", args="--privileged -sV --script vulners --script-args mincvss=5.0")
# json_string = json.dumps(scan_results, indent= 2)
# print (f"{json_string}")

# data = json.loads(json_string)
# for key, value in data.items():
#     if value['state']['state'] == 'up':
#         print(f"Host IP {key}: ")
#         for value_port in value['ports']:
#             print(f"Protocol: {value_port['protocol']}")
#             print(f"Protocol: {value_port['portid']}")
#             if value_port['service']['name'] != None:
#                 print(f"Protocol: {value_port['service']['name']}")
#             if value_port['cpe'][0]['cpe'] != None: 
#                 print(f"Protocol: {value_port['cpe'][0]['cpe']}")


2
3
4
5
6
import os, platform
 
if platform.system() == "Windows":
    print(platform.uname().node)
else:
    print(os.uname()[1])   # doesnt work on windows
