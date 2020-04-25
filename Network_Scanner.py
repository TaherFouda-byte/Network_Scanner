#!/usr/bin/env python

import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", "-t", dest="target", help=" Target Subnets ot IP to be scanned")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please Specify the Target Subnet/IP, Use --help for more info")
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_broadcast, timeout=2, verbose=False)[0]

    target_list = []
    for entry in answered_list:
        target_dict = {"ip": entry[1].psrc, "mac": entry[1].hwsrc}
        target_list.append(target_dict)
    return target_list


def print_result(result_list):
    print("==========================================")
    print("|| IP\t\t\t  MAC ADDRESS\t ||\n==========================================")

    for element in result_list:
        print("| " + element["ip"] + "\t\t" + element["mac"] + " |")
        print("-------------------------------------------")


# ip_range = input("Please Enter the Network Subnet:")
options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
