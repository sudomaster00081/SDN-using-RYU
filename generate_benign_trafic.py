import random
import time
from scapy.all import IP, TCP, send
from scapy.all import sr1

def generate_high_volume_traffic(target_ip, target_port, duration=60, rate=100):
    print(f"Generating high-volume traffic to {target_ip}:{target_port}")
    start_time = time.time()
    sent_packets = 0
    
    while time.time() - start_time < duration:
        src_ip = "10.0.0.%i" % random.randint(1, 254)  # Assume 10.0.0.0/24 network
        src_port = random.randint(1024, 65535)
        
        # Create a full TCP handshake instead of just SYN
        syn = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")
        syn_ack = sr1(syn, timeout=1, verbose=0)
        if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags & 0x12:
            ack = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="A", seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
            send(ack, verbose=0)
        
        sent_packets += 1
        if sent_packets % 100 == 0:
            print(f"Sent {sent_packets} connections")
        
        time.sleep(1/rate)  # Control the rate of connections

if __name__ == "__main__":
    target_ip = "10.0.0.12"
    target_port = 80
    generate_high_volume_traffic(target_ip, target_port)