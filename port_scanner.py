import nmap
import colorama
from pyfiglet import Figlet
from tabulate import tabulate

colorama.init()

# Print banner
f = Figlet(font='slant')
print(colorama.Fore.BLUE + f.renderText("NMAP Scanner"))
print("By 477")

# Get IP range to scan
try:
    ip_range = input(colorama.Fore.WHITE + "Enter IP range to scan (ex: 192.168.1.1-255): ")
except KeyboardInterrupt:
    print(colorama.Fore.RED + "\nProgram execution canceled.")
    exit()

# Scan hosts for open ports
try:
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-p 1-65535 -sV -T4')

    # Print live hosts and their open ports
    headers = ['Host', 'Port', 'Service', 'Product', 'Version', 'Extra Info']
    table = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            for port in nm[host]['tcp']:
                state = nm[host]['tcp'][port]['state']
                if state == 'open':
                    service = nm[host]['tcp'][port]['name']
                    product = nm[host]['tcp'][port]['product']
                    version = nm[host]['tcp'][port]['version']
                    extra_info = nm[host]['tcp'][port]['extrainfo']
                    table.append([host, port, service, product, version, extra_info])

    print(colorama.Fore.GREEN + f"\nFound {len(table)} open ports on {len(nm.all_hosts())} hosts.")
    if len(table) > 0:
        print(tabulate(table, headers=headers, tablefmt='fancy_grid'))

except nmap.PortScannerError as e:
    print(colorama.Fore.RED + "\nNmap error occurred:")
    print(e)
except Exception as e:
    print(colorama.Fore.RED + "\nAn error occurred:")
    print(e)
