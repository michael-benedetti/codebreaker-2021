# Task 1

For task 1, we are provided with a packet capture of data en route to a listening post and a list of DIB company IP ranges.  Our task is to identify any IPs associated with the DIB that have communicated with the LP.

Our IP ranges are depicted in [CIDR notation](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation):

```
198.19.49.112/29
198.19.50.160/29
172.18.254.240/28
172.17.191.16/28
198.19.48.136/29
10.84.64.0/18
10.116.12.128/26
192.168.81.160/28
198.18.79.192/27
172.18.33.0/24
198.19.39.192/26
10.88.80.0/20
192.168.72.0/22
172.26.8.96/27
10.99.32.0/19
172.26.158.160/27
172.26.12.128/26
172.25.220.0/22
10.215.8.0/21
172.24.130.64/26
```

Opening up the pcap data in wireshark gives us almost 200 lines of packet capture.  At first glace, we can see that there are a series of connections to what must be the IP of our LP: `198.19.217.148`.

![capture.pcap in wireshark](images/task1-1.png)

WIth this information, we can write a quick python script and utilize the `scapy` and `ipaddress` libraries to do the heavy lifting of determining which IPs fall within the CIDR blocks:

```python
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
```

Running the script yields the answer to task 1:

```
172.25.222.254
198.19.39.206
10.215.11.240
172.26.12.152
```