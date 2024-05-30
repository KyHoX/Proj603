import socket

def get_hostname_by_ip(ip):
    try:
        hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None

# Example usage
ip = '192.168.42.25'
hostname = get_hostname_by_ip(ip)
if hostname:
    print(f"The hostname for IP {ip} is {hostname}")
else:
    print(f"Hostname for IP {ip} could not be found")
