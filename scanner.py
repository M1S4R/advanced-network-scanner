from scapy.all import ARP, Ether, srp
from colorama import Fore, init
import socket
import netifaces
import ipaddress

init(autoreset=True)

# --------------------------------
# Banner
# --------------------------------

print(Fore.GREEN + """
 _   _      _                      _
| \\ | | ___| |___      _____  _ __| | __
|  \\| |/ _ \\ __\\ \\ /\\ / / _ \\| '__| |/ /
| |\\  |  __/ |_ \\ V  V / (_) | |  |   <
|_| \\_|\\___|\\__| \\_/\\_/ \\___/|_|  |_|\\_\\

        AUTO NETWORK SCANNER
""")

# --------------------------------
# Get Local Network Automatically
# --------------------------------

gateway = netifaces.gateways()['default'][netifaces.AF_INET][1]

ip_info = netifaces.ifaddresses(gateway)[netifaces.AF_INET][0]

ip_address = ip_info['addr']
netmask = ip_info['netmask']

network = ipaddress.IPv4Network(
    f"{ip_address}/{netmask}",
    strict=False
)

target_network = str(network)

print(Fore.CYAN + f"[INFO] Detected Network: {target_network}")

# --------------------------------
# ARP Scan Function
# --------------------------------

def scan(ip_range):

    arp = ARP(pdst=ip_range)

    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether / arp

    result = srp(
        packet,
        timeout=2,
        verbose=0
    )[0]

    devices = []

    for sent, received in result:

        ip = received.psrc
        mac = received.hwsrc

        try:
            hostname = socket.gethostbyaddr(ip)[0]

        except:
            hostname = "Unknown"

        devices.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname
        })

    return devices

# --------------------------------
# Start Scan
# --------------------------------

print(Fore.YELLOW + "[INFO] Scanning Devices...\n")

devices = scan(target_network)

# --------------------------------
# Display Results
# --------------------------------

print(Fore.GREEN + "-" * 90)

print(
    Fore.WHITE +
    f"{'IP ADDRESS':<20}"
    f"{'MAC ADDRESS':<25}"
    f"{'HOSTNAME'}"
)

print(Fore.GREEN + "-" * 90)

for device in devices:

    print(
        Fore.CYAN +
        f"{device['ip']:<20}"
        f"{device['mac']:<25}"
        f"{device['hostname']}"
    )

print(
    Fore.MAGENTA +
    f"\n[INFO] Total Devices Found: {len(devices)}"
)