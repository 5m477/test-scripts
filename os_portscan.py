import sys
import os
import time 
import colorama
from colorama import Fore, Style
import pyfiglet 
import ipaddress
import nmap
from tabulate import tabulate

colorama.init(autoreset=True)

def print_banner():
    banner = pyfiglet.figlet_format("477 OS+Port Scanner")
    print(Fore.YELLOW + banner)


def print_usage():
    syntax = f"Usage: python {os.path.basename(__file__)} <IP address or IP range in CIDR notation>"
    print(Fore.RED + syntax)


def validate_ip_address(ip_address):
    try:
        ipaddress.ip_network(ip_address)
    except ValueError:
        return False
    return True


def scan_host(ip_address):
    scanner = nmap.PortScanner()
    scan_results = scanner.scan(ip_address, arguments="-O -sS -sV -p-")
    if 'scan' in scan_results and ip_address in scan_results['scan'] and 'status' in scan_results['scan'][ip_address] and scan_results['scan'][ip_address]['status']['state'] == "up":
        return scan_results['scan'][ip_address]
    else:
        return None


def print_os_details(scan_results):
    if 'osmatch' not in scan_results:
        print(Fore.RED + "Could not find the operating system")
    else:
        osmatch = scan_results['osmatch'][0]
        cpe = osmatch['osclass'][0]['cpe']
        osfamily = osmatch['osclass'][0]['osfamily']
        ostype = osmatch['osclass'][0]['type']
        osgen = osmatch['osclass'][0]['osgen']
        vendor = osmatch['osclass'][0]['vendor']
        accuracy = osmatch['osclass'][0]['accuracy']
        print(Fore.GREEN + f"Operating system details for {scan_results['addresses']['ipv4']}")
        print(Fore.CYAN + f"CPE:\t\t{cpe}")
        print(f"Family:\t\t{osfamily}")
        print(f"Type:\t\t{ostype}")
        print(f"Generation:\t{osgen}")
        print(f"Vendor:\t\t{vendor}")
        print(f"Accuracy:\t{accuracy}%")


def print_open_ports(scan_results):
    open_ports = []
    for protocol in scan_results['tcp']:
        if scan_results['tcp'][protocol]['state'] == 'open':
            service = scan_results['tcp'][protocol]['name']
            version = scan_results['tcp'][protocol]['version']
            port = protocol
            open_ports.append([port, service, version])
    if len(open_ports) == 0:
        print(Fore.YELLOW + "No open ports found.")
    else:
        print(Fore.GREEN + f"Open ports for {scan_results['addresses']['ipv4']}")
        print(tabulate(open_ports, headers=["Port", "Service", "Version"], tablefmt="orgtbl"))


def save_results(ip_address, scan_results):
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    filename = f"{ip_address} - {timestamp}.txt"
    with open(filename, "w") as file:
        file.write(str(scan_results))


def main():
    try:
        print_banner()
        if len(sys.argv) < 2:
            print_usage()
            sys.exit(1)
        ip_address_or_range = sys.argv[1]
        if not validate_ip_address(ip_address_or_range):
            print(Fore.RED + "Invalid IP address or range")
            sys.exit(1)
        ip_network = ipaddress.ip_network(ip_address_or_range, strict=False)
        for ip_address in ip_network.hosts():
            ip_address = str(ip_address)
            scan_results = scan_host(ip_address)
            if scan_results is None:
                print(Fore.RED + f"Host {ip_address} is down")
                continue
            print_os_details(scan_results)
            print_open_ports(scan_results)
            save_results(ip_address, scan_results)
            print(Fore.GREEN + f"Results for {ip_address} saved to file")
        sys.exit(0)
    except KeyboardInterrupt:
        print("Script interrupted by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
