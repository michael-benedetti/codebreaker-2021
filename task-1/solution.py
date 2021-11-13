import ipaddress

from scapy.layers.inet import IP
from scapy.utils import PcapReader

if __name__ == '__main__':
    all = set()

    # Extract all source IPs from the PCAP into a set
    for pkt in PcapReader("capture.pcap"):
        all.add(pkt[IP].src)

    with open("ip_ranges.txt", "r") as file:
        # Collect a list of all ip_ranges from the provided file
        ip_ranges = [ip.strip() for ip in file.readlines()]

    # For each source IP from our PCAP, check to see if it falls within one of the DIB ranges, and report if so.
    for ip in all:
        for network in ip_ranges:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(network):
                print(ip)
                break
