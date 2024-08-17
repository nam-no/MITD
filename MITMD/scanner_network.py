

import scapy.all as scapy
import argparse

def get_args():
   parser =  argparse.ArgumentParser()
   parser.add_argument("-t", "--target", dest="target_ip", help="IP Address of the target.")
   arg = parser.parse_args()
   if not arg.target_ip:
      print("[+] Please specify an IP Address of the target machine,use --hlep for more infor ")
   return arg
def scan(ip):
   arp_request = scapy.ARP(pdst=ip)
   broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
   arp_request_broadcast = broadcast / arp_request
   ans_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
   client_list = []
   for element in ans_list:
      client_dict = {"ip":element[1].psrc,"mac":element[1].hwsrc}
      client_list.append(client_dict)
   return client_list

def print_result(result_list):
   print("|-------------------------------------------------|")
   print("|IP\t\t\t   |\tMAC Address\t  |      ")
   print("|-------------------------------------------------|")
   for result in result_list :
      print("|"+result["ip"] + "\t\t   |\t" + result["mac"]  +" |")
   print("|-------------------------------------------------|")


# result_list = scan("192.168.1.1/24")
arg = get_args()
result_list = scan(arg.target_ip)
print_result(result_list)