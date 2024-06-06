# Project 603 - Cyber Security program - 2023/2024
# Saskatchewan Polytechnic 
# Team member: Le Tuan Vu, Pham Thanh Binh, Ho Minh Ky

Project deliverable

-	Setup scanning environment with Kali Linux and scanning tools.
-	Perform the scan, identify the vulnerabilities from scanning results and give the recommendations for countermeasures.
-	A full report includes an inventory, risk assessment, and results of the vulnerabilities of existing IoT devices in the home network, and a proposed countermeasures.


Tools to scan home network is nmap. 
Automation via Python 3.12.3

Steps to run the code

1. Depend on your current operating system, which is Windows or Linux, to start with installation script
    - If you are running Windows OS, please run this script first. ../scripts/windows_setup.bat
    - If you are running Linux OS, please run this script ../scripts/kali_setup.sh. At the moment, we work on Debian based OS with apt installed.
2. After running environment is configured. Run the getlocalIP.py to scan your network. We assume that the box you run the script connected to your home network, either Wi-Fi or cable plugged.
3. The scan result will display in HTML format with some suggestions if there are any vulnerabilities found.
4. If you are willing to support our project, please share your JSON file, its name is 'nmap_home_result.json' in your current working directory. It will be helpful for us to build device pattern to recognize device types.

# Thank you very much for your support.