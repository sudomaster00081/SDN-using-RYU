import csv
import math
from collections import Counter
from scapy.all import rdpcap

def calculate_entropy(data):
    counter = Counter(data)
    entropy = 0
    total = sum(counter.values())
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy

def extract_features(pcap_file, interval=5):
    packets = rdpcap(pcap_file)
    features = []
    maxlen = len(packets)
    for i in range(0, maxlen, interval):
        print(f"\rProcessing {i} of {maxlen}", end='', flush=True)
        batch = packets[i:i+interval]
        
        src_ips = [pkt.src for pkt in batch if hasattr(pkt, 'src')]
        src_ports = [pkt.sport for pkt in batch if hasattr(pkt, 'sport')]
        dst_ports = [pkt.dport for pkt in batch if hasattr(pkt, 'dport')]
        protocols = [pkt.proto for pkt in batch if hasattr(pkt, 'proto')]
        
        etp_src_ip = calculate_entropy(src_ips)
        etp_src_p = calculate_entropy(src_ports)
        etp_dst_p = calculate_entropy(dst_ports)
        etp_protocol = calculate_entropy(protocols)
        total_packet = len(batch)
        
        features.append([etp_src_ip, etp_src_p, etp_dst_p, etp_protocol, total_packet])
    
    return features

def save_to_csv(features, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['etpSrcIP', 'etpSrcP', 'etpDstP', 'etpProtocol', 'totalPacket'])
        writer.writerows(features)

# Main execution
if __name__ == "__main__":
    # pcap_file = "ddostrace.to-victim.20070804_134936.pcap"  # Replace with your PCAP file path
    # output_file = "ddostrace.to-victim.20070804_134936.csv"
    pcap_file = "ddostrace.to-victim.20070804_145436.pcap"
    output_file = "ddostrace.to-victim.20070804_145436.csv"
    
    print("Extracting features...")
    features = extract_features(pcap_file)
    
    print("Saving features to CSV...")
    save_to_csv(features, output_file)
    
    print(f"Features saved to {output_file}")