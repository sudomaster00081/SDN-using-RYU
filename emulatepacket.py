from scapy.all import *
import time
import netifaces
import random

def get_default_interface():
    print("Searching for a suitable network interface...")
    
    # Get the default gateway interface
    gateways = netifaces.gateways()
    if 'default' in gateways and netifaces.AF_INET in gateways['default']:
        interface = gateways['default'][netifaces.AF_INET][1]
        print(f"Using default gateway interface: {interface}")
        return interface
    
    # If no default gateway, return the first non-loopback interface
    for interface in netifaces.interfaces():
        if interface != 'lo' and netifaces.AF_INET in netifaces.ifaddresses(interface):
            print(f"No default gateway found. Using first available interface: {interface}")
            return interface
    
    raise Exception("No suitable network interface found")

def emulate_pcap(pcap_file):
    interface = get_default_interface()
    print(f"Reading PCAP file: {pcap_file}")
    print(f"Emulating traffic on interface: {interface}")
    
    # Read the PCAP file
    print("Loading PCAP file...")
    packets = rdpcap(pcap_file)
    print(f"Loaded {len(packets)} packets from the PCAP file")
    
    # Get the timestamp of the first packet
    start_time = packets[0].time
    print(f"First packet timestamp: {start_time}")
    
    for i, packet in enumerate(packets, 1):
        # Calculate the delay
        delay = packet.time - start_time
        
        print(f"\nPacket {i}/{len(packets)}:")
        print(f"  Waiting for {delay:.6f} seconds")
        
        # Wait for the appropriate time
        time.sleep(delay)
        
        # Remove any existing Ethernet layer
        if Ether in packet:
            print("  Removing Ethernet layer")
            packet = packet[Ether].payload
        
        # Modify IP layer (assuming it's IP)
        if IP in packet:
            # Generate random source and destination IP addresses within 10.0.0.0/24
            src_ip = f"10.0.0.{random.randint(1, 18)}"
            dst_ip = f"10.0.0.{random.randint(1, 18)}"
            packet[IP].src = src_ip
            packet[IP].dst = dst_ip
            print(f"  Modified source IP: {src_ip}, destination IP: {dst_ip}")
        
        # Send the packet
        print(f"  Sending packet: {packet.summary()}")
        sendp(packet, iface=interface, verbose=False)
        
        print(f"  Packet sent successfully")
    
    print("\nEmulation complete")

if __name__ == "__main__":
    # Specify the path to your PCAP file here
    pcap_file_path = "ddostrace.to-victim.20070804_134936.pcap"
    
    print("Starting PCAP emulation script")
    print("==============================")
    
    try:
        emulate_pcap(pcap_file_path)
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    
    print("Script execution finished")
