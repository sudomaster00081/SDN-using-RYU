import os
import random
from scapy.all import *

def find_pcap_file():
    # Get current directory
    current_dir = os.getcwd()

    # List all files in current directory
    files = os.listdir(current_dir)

    # Filter .pcap files
    pcap_files = [file for file in files if file.endswith('.pcap')]

    if not pcap_files:
        print("No .pcap files found in the current directory.")
        exit(1)

    # Return the first .pcap file found
    return pcap_files[0]

def ddos_attack(pcap_file):
    print(f"Emulating traffic from pcap file: {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"Read {len(packets)} packets from pcap file")
    sent_packets = 0
    ip_addresses = ["10.0.0." + str(i) for i in range(1, 19)]  # Generate list of IP addresses 10.0.0.1 to 10.0.0.18

    try:
        while True:
            # Select a random packet from the pcap file
            packet = random.choice(packets)

            # Randomize source and destination IP addresses
            src_ip = random.choice(ip_addresses)
            dst_ip = random.choice(ip_addresses)
            
            # Make sure src_ip and dst_ip are different
            while dst_ip == src_ip:
                dst_ip = random.choice(ip_addresses)

            # Update the packet with randomized IPs
            packet = IP(src=src_ip, dst=dst_ip) / packet[IP].payload

            # Send the modified packet
            send(packet, verbose=0)
            sent_packets += 1
            if sent_packets % 1000 == 0:
                print(f"Sent {sent_packets} packets")

    except KeyboardInterrupt:
        print(f"\nTraffic emulation interrupted. Total packets sent: {sent_packets}")

if __name__ == "__main__":
    # Find the first .pcap file in the current directory
    pcap_file = find_pcap_file()

    ddos_attack(pcap_file)
