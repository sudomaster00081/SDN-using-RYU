import csv
from scapy.all import *
import os
from collections import defaultdict

def pcap_to_csv(pcap_file):
    packets = rdpcap(pcap_file)
    print("Converting PCAP to CSV...")
    csv_file = os.path.splitext(pcap_file)[0] + '.csv'
    
    # Dictionary to store flow information
    flows = defaultdict(lambda: {
        'start_time': None, 'end_time': None, 'packet_count': 0, 'byte_count': 0,
        'datapath_id': 'N/A', 'flags': set(), 'idle_timeout': 'N/A', 'hard_timeout': 'N/A'
    })
    
    # Process packets to gather flow information
    for packet in packets:
        if IP in packet:
            flow_id = (packet[IP].src, packet[IP].dst, packet[IP].proto, 
                       packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0,
                       packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0)
            
            flow = flows[flow_id]
            flow['packet_count'] += 1
            flow['byte_count'] += len(packet)
            
            if flow['start_time'] is None:
                flow['start_time'] = packet.time
            flow['end_time'] = packet.time
    
    with open(csv_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            'timestamp', 'datapath_id', 'flow_id', 'ip_src', 'tp_src', 'ip_dst', 'tp_dst',
            'ip_proto', 'icmp_code', 'icmp_type', 'flow_duration_sec', 'flow_duration_nsec',
            'idle_timeout', 'hard_timeout', 'flags', 'packet_count', 'byte_count',
            'packet_count_per_second', 'packet_count_per_nsecond', 'byte_count_per_second',
            'byte_count_per_nsecond'
        ])
        
        for flow_id, flow_data in flows.items():
            ip_src, ip_dst, ip_proto, tp_src, tp_dst = flow_id
            duration = flow_data['end_time'] - flow_data['start_time']
            duration_sec = int(duration)
            duration_nsec = int((duration - duration_sec) * 1e9)
            
            packet_count = flow_data['packet_count']
            byte_count = flow_data['byte_count']
            
            writer.writerow([
                flow_data['start_time'],
                flow_data['datapath_id'],
                ','.join(map(str, flow_id)),
                ip_src,
                tp_src,
                ip_dst,
                tp_dst,
                ip_proto,
                packet[ICMP].code if ICMP in packet else 'N/A',
                packet[ICMP].type if ICMP in packet else 'N/A',
                duration_sec,
                duration_nsec,
                flow_data['idle_timeout'],
                flow_data['hard_timeout'],
                ','.join(flow_data['flags']),
                packet_count,
                byte_count,
                packet_count / duration if duration > 0 else 0,
                packet_count / (duration * 1e9) if duration > 0 else 0,
                byte_count / duration if duration > 0 else 0,
                byte_count / (duration * 1e9) if duration > 0 else 0
            ])
    
    print(f"Conversion complete. CSV file saved as: {csv_file}")

if __name__ == "__main__":
    import sys
    
    # if len(sys.argv) != 2:
    #     print("Usage: python script.py <pcap_file>")
    #     sys.exit(1)
    
    # pcap_file = sys.argv[1]
    # if not pcap_file.endswith('.pcap'):
    #     print("Error: Input file must be a .pcap file")
    #     sys.exit(1)
    pcap_file = "smlddostrace.to-victim.20070804_134936.pcap"
    pcap_to_csv(pcap_file)