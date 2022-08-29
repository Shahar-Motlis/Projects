from socket import socket, AF_INET, SOCK_STREAM, gethostbyaddr
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
from art import tprint
from datetime import datetime


def connection(ip_address, port):
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(20)
    try:
        s.connect((ip_address, port))
        return True
    except OSError:
        return False


def scan(ip_address, ports):
    print("Scanning ip address", colored(ip_address, 'green') + "...\n")
    scan_start = datetime.now()
    executor = ThreadPoolExecutor(len(ports))
    results = executor.map(connection, [ip_address] * len(ports), ports)
    for port, is_open in zip(ports, results):
        if is_open:
            print("Port", colored(port, 'green'), "is", colored("OPEN", 'green') + ".")
        else:
            pass

    scan_stop = datetime.now()

    total_scan_time = scan_stop - scan_start
    print("\nScan time:", total_scan_time)


def main():
    tprint("TCP   PORT   SCANNER")

    host_ip = input(colored("Please enter an ip address, for scanning well-known open ports: ", 'yellow'))
    host_name = gethostbyaddr(host_ip)
    print("\nThe hostname that related to this ip address is:", colored(host_name[0], 'green'), "\n")
    well_known_ports = range(1024)
    scan(host_ip, well_known_ports)
    print("\nThe scan has completed.")


if __name__ == "__main__":
    main()
