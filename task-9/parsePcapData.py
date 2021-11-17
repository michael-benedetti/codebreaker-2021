#!/usr/bin/python3
import sys

import dpkt


def hex_string(b):
    return ''.join('' + "%02x" % letter for letter in b)

if __name__ == '__main__':
    with open("dib_data", "w") as file:
        for ts, pkt in dpkt.pcap.Reader(open(sys.argv[1], "rb")):
            eth = dpkt.ethernet.Ethernet(pkt)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data
            ip_str = ".".join([str(c) for c in ip.src])
            if ip.data.dport == 6666 and ip.data.data:
                file.write(f"{hex_string(ip.data.data)},{int(ts)}\n")
    with open("lp_data", "w") as file:
        for ts, pkt in dpkt.pcap.Reader(open(sys.argv[1], "rb")):
            eth = dpkt.ethernet.Ethernet(pkt)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data
            ip_str = ".".join([str(c) for c in ip.dst])
            if ip.data.sport == 6666 and ip.data.data:
                file.write(f"{hex_string(ip.data.data)},{int(ts)}\n")
