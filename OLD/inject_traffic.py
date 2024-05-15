from scapy.all import *

# Load the pcap file
packets = rdpcap('ddostrace.to-victim.20070804_134936.pcap')

# Send each packet to the network
for pkt in packets:
    sendp(pkt)


