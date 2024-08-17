import scapy.all as scapy
import requests
import socket
from tabulate import tabulate
import argparse

def get_args():
   parser =  argparse.ArgumentParser()
   parser.add_argument("-t", "--target", dest="target_ip", help="IP Address of the target.")
   arg = parser.parse_args()
   if not arg.target_ip:
      print("[+] Please specify an IP Address of the target machine,use --hlep for more infor ")
   return arg
def get_network_info(ip_target):
    # Tạo một yêu cầu ARP để lấy thông tin giao diện mạng
    arp_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip_target)
    result = scapy.srp(arp_request, timeout=3, verbose=0)[0]

    # Duyệt qua các gói tin nhận được và lấy thông tin cần thiết
    network_info = []
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        vendor = get_vendor(mac)
        hostname = get_hostname(ip)
        network_info.append([ip, mac, vendor, hostname])

    return network_info

def get_vendor(mac_address):
    url = f"https://api.macvendors.com/{mac_address}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.text.strip()
    return "Unknown"

def get_hostname(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except socket.herror:
        return "Unknown"

# Sử dụng hàm get_network_info() để lấy thông tin mạng
arg = get_args()
network_info = get_network_info(arg.target_ip)

# Tạo bảng đầu ra sử dụng tabulate
table_headers = ["IP", "MAC", "Vendor", "Hostname"]
table = tabulate(network_info, headers=table_headers, tablefmt="grid")

# In bảng đầu ra
print(table)