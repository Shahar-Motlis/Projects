#!/bin/python3

import sys
import subprocess
import time
from datetime import datetime
from scapy.all import *
from art import tprint
from termcolor import colored


def packet_sniffer():

    network_interface = input(colored("--> Enter an interface that you want to use the sniffer on him (for example, 'enp0s3'): ", "yellow"))
    try:
        subprocess.check_call(["ifconfig", network_interface, "promisc"])
    except subprocess.CalledProcessError:
        print(colored("\n> Configuration failed.\n", "red"))
        sys.exit()
    else:
        print("\n> Interface {} set to Promiscuous mode.\n".format(network_interface))

    time_to_sniff = int(input(colored("--> How many time to run the capture (in seconds): ", "yellow")))
    while time_to_sniff <= 0:
        print(colored("\n> Error! enter a number that greater than 0.\n", "red"))
        time_to_sniff = int(input(colored("--> How many time to run the capture (in seconds): ", "yellow")))
    else:
        print("\n> The program will capture packets for {} seconds.\n".format(time_to_sniff))

    packets_sniff_num = int(input(colored("--> How many packets do you want to captured (enter a number)?\n  *[Enter 0 if you want to capture in all the session time]: ", "yellow")))
    if packets_sniff_num != 0:
        print("\n> The program will capture {} packets.\n".format(packets_sniff_num))
    elif packets_sniff_num == 0:
        print("\n> The program will capture packets until the timeout expires.\n")

    protocol_sniff = input(colored("--> Enter the protocol that you want for the capture (arp|icmp|tcp|udp): ", "yellow")).lower()
    possible_protocols = ["arp", "icmp", "tcp", "udp"]

    while protocol_sniff not in possible_protocols:
        print(colored("\n> Error! Choose one protocol from the list --> [arp, icmp, tcp, udp].\n ", "red"))
        protocol_sniff = input(colored("--> Enter the protocol that you want for the capture (arp|icmp|tcp|udp): ", "yellow")).lower()
    else:
        print("\n> The program will capture only {} packets.\n".format(protocol_sniff.upper()))

    log_file = input(colored("--> Enter a name for the log file: ", "yellow"))

    sniffer_log = open(log_file, "a")

    def sniffing(packet):

        time_now = datetime.now().time()

        if protocol_sniff in possible_protocols:
            print(colored("*Time: ", "yellow") + str(time_now) + colored(" *Protocol: ", "yellow") + protocol_sniff.upper() + colored(" *SRC-MAC: ", "yellow") + packet.src + colored(" *DST-MAC: ", "yellow") + packet.dst, file=sniffer_log)

    print("\n    *Starting the capture...*")
    print("\n    *Please wait until the timeout expires.*")

    if protocol_sniff in possible_protocols:
        sniff(iface=network_interface, filter=protocol_sniff, count=packets_sniff_num, timeout=time_to_sniff, prn=sniffing)

        while time_to_sniff:
            minutes, seconds = divmod(time_to_sniff, 60)
            timer = "{:02d}:{:02d}".format(minutes, seconds)
            print(colored("-->>", "red"), timer, end="\r")
            time.sleep(0.1)
            time_to_sniff -= 1
    print("    **Finished.")

    print(colored("\n    *Please check the -->{}<-- file to see the captured packets.*\n".format(log_file), "red"))

    sniffer_log.close()


def main():

    tprint("Packet   Sniffer")
    print(colored("[NOTE: Run this program with 'sudo' command! ---> 'sudo python3 packet_sniffer.py']\n\n", "red"))

    packet_sniffer()


if __name__ == "__main__":
    main()
