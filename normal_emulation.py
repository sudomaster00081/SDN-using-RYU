from scapy.all import *
import random
import time

def generate_random_traffic(source_ip_range, destination_ip_range, num_packets):
    protocols = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'FTP', 'SMTP']  # List of protocols to choose from
    common_ports = [80, 443, 53, 123, 8080, 21, 25]  # List of common ports to choose from
    
    for _ in range(num_packets):
        # Choose random protocol, port, source IP, and destination IP
        protocol = random.choice(protocols)
        port = random.choice(common_ports)
        
        # Generate random source and destination IPs
        source_ip = f"{source_ip_range[0]}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        destination_ip = f"{destination_ip_range[0]}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        # Craft packet based on chosen protocol
        if protocol == 'TCP':
            # Simulate TCP three-way handshake
            packet1 = IP(src=source_ip, dst=destination_ip)/TCP(dport=port, flags="S")
            packet2 = IP(src=destination_ip, dst=source_ip)/TCP(sport=port, dport=port, flags="SA")
            packet3 = IP(src=source_ip, dst=destination_ip)/TCP(sport=port, dport=port, flags="A")
            
            # Send packets for three-way handshake
            send(packet1)
            time.sleep(0.1)
            send(packet2)
            time.sleep(0.1)
            send(packet3)
        
        elif protocol == 'UDP':
            # Simulate UDP multicast or broadcast traffic
            if random.random() < 0.1:  # 10% chance of multicast/broadcast
                destination_ip = "224.0.0.1"  # Example multicast address
            packet = IP(src=source_ip, dst=destination_ip)/UDP(dport=port)
            send(packet)
        
        elif protocol == 'ICMP':
            packet = IP(src=source_ip, dst=destination_ip)/ICMP()
            send(packet)
        
        elif protocol == 'DNS':
            # Simulate DNS query and response
            packet1 = IP(src=source_ip, dst=destination_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="www.example.com"))
            packet2 = IP(src=destination_ip, dst=source_ip)/UDP(sport=53)/DNS(id=packet1[DNS].id, an=DNSRR(rrname="www.example.com", rdata="1.2.3.4"))
            
            # Send DNS query and response packets
            send(packet1)
            time.sleep(0.1)
            send(packet2)
        
        elif protocol == 'HTTP':
            # HTTP GET request
            packet1 = IP(src=source_ip, dst=destination_ip)/TCP(dport=80)/Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            # HTTP POST request
            packet2 = IP(src=source_ip, dst=destination_ip)/TCP(dport=80)/Raw(b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\nSomeData")
            
            # Send HTTP GET and POST requests
            send(packet1)
            time.sleep(0.1)
            send(packet2)
        
        elif protocol == 'FTP':
            # FTP login simulation
            packet1 = IP(src=source_ip, dst=destination_ip)/TCP(dport=21)/Raw(b"USER anonymous\r\n")
            packet2 = IP(src=destination_ip, dst=source_ip)/TCP(sport=21)/Raw(b"331 User name okay, need password.\r\n")
            packet3 = IP(src=source_ip, dst=destination_ip)/TCP(dport=21)/Raw(b"PASS anonymous\r\n")
            packet4 = IP(src=destination_ip, dst=source_ip)/TCP(sport=21)/Raw(b"230 Login successful.\r\n")
            # Simulate FTP file transfer (download)
            packet5 = IP(src=source_ip, dst=destination_ip)/TCP(dport=21)/Raw(b"RETR filename.txt\r\n")
            packet6 = IP(src=destination_ip, dst=source_ip)/TCP(sport=21)/Raw(b"150 Opening data connection.\r\n")
            
            # Send packets for FTP login and file transfer
            send(packet1)
            time.sleep(0.1)
            send(packet2)
            time.sleep(0.1)
            send(packet3)
            time.sleep(0.1)
            send(packet4)
            time.sleep(0.1)
            send(packet5)
            time.sleep(0.1)
            send(packet6)
        
        elif protocol == 'SMTP':
            # SMTP email simulation
            packet1 = IP(src=source_ip, dst=destination_ip)/TCP(dport=25)/Raw(b"EHLO example.com\r\n")
            packet2 = IP(src=destination_ip, dst=source_ip)/TCP(sport=25)/Raw(b"250 Hello example.com\r\n")
            packet3 = IP(src=source_ip, dst=destination_ip)/TCP(dport=25)/Raw(b"MAIL FROM:<sender@example.com>\r\n")
            packet4 = IP(src=destination_ip, dst=source_ip)/TCP(sport=25)/Raw(b"250 Sender ok\r\n")
            packet5 = IP(src=source_ip, dst=destination_ip)/TCP(dport=25)/Raw(b"RCPT TO:<recipient@example.com>\r\n")
            packet6 = IP(src=destination_ip, dst=source_ip)/TCP(sport=25)/Raw(b"250 Recipient ok\r\n")
            packet7 = IP(src=source_ip, dst=destination_ip)/TCP(dport=25)/Raw(b"DATA\r\n")
            packet8 = IP(src=destination_ip, dst=source_ip)/TCP(sport=25)/Raw(b"354 Enter mail, end with \".\" on a line by itself\r\n")
            packet9 = IP(src=source_ip, dst=destination_ip)/TCP(dport=25)/Raw(b"Subject: Test email\r\n\r\nHello, this is a test email.\r\n.\r\n")
            packet10 = IP(src=destination_ip, dst=source_ip)/TCP(sport=25)/Raw(b"250 Message accepted for delivery\r\n")
            
            # Send packets for SMTP email simulation
            send(packet1)
            time.sleep(0.1)
            send(packet2)
            time.sleep(0.1)
            send(packet3)
            time.sleep(0.1)
            send(packet4)
            time.sleep(0.1)
            send(packet5)
            time.sleep(0.1)
            send(packet6)
            time.sleep(0.1)
            send(packet7)
            time.sleep(0.1)
            send(packet8)
            time.sleep(0.1)
            send(packet9)
            time.sleep(0.1)
            send(packet10)
        
        # Introduce some variability in timing (inter-arrival times)
        time.sleep(random.uniform(0.1, 0.5))  # Random delay between 0.1 to 0.5 seconds

if __name__ == "__main__":
    source_ip_range = ("10.0.0.1", "10.0.0.18")  # Source IP range
    destination_ip_range = ("10.0.0.1", "10.0.0.18")  # Destination IP range
    num_packets = 20  # Number of packets to send
    
    generate_random_traffic(source_ip_range, destination_ip_range, num_packets)
