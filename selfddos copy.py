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
    print("Reading of pcap done")
    sent_packets = 0

    try:
        while True:
            # Select a random packet from the pcap file
            packet = random.choice(packets)

            # Send the selected packet
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
