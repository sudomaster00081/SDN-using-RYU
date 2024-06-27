from scapy.all import *
import random
import time
import datetime

# Constants and configurations
SOURCE_IP_RANGE = ("10.0.0.1", "10.0.0.18")
DESTINATION_IP_RANGE = ("10.0.0.1", "10.0.0.18")
NUM_PACKETS = 100
PROTOCOLS = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS', 'FTP', 'SMTP', 'SSH']
COMMON_PORTS = {
    'HTTP': 80, 'HTTPS': 443, 'DNS': 53, 'FTP': 21, 'SMTP': 25, 'SSH': 22
}
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
]
DOMAIN_NAMES = ["example.com", "test.org", "sample.net", "demo.edu"]
HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
CONTENT_TYPES = ['application/json', 'application/x-www-form-urlencoded', 'text/xml']

def generate_random_ip(ip_range):
    start_ip = list(map(int, ip_range[0].split('.')))
    end_ip = list(map(int, ip_range[1].split('.')))
    return '.'.join(map(str, [random.randint(start_ip[i], end_ip[i]) for i in range(4)]))

def generate_random_traffic():
    for _ in range(NUM_PACKETS):
        protocol = random.choice(PROTOCOLS)
        source_ip = generate_random_ip(SOURCE_IP_RANGE)
        destination_ip = generate_random_ip(DESTINATION_IP_RANGE)
        
        if protocol in ['HTTP', 'HTTPS']:
            generate_http_traffic(source_ip, destination_ip, protocol)
        elif protocol == 'DNS':
            generate_dns_traffic(source_ip, destination_ip)
        elif protocol == 'FTP':
            generate_ftp_traffic(source_ip, destination_ip)
        elif protocol == 'SMTP':
            generate_smtp_traffic(source_ip, destination_ip)
        elif protocol == 'SSH':
            generate_ssh_traffic(source_ip, destination_ip)
        elif protocol == 'TCP':
            generate_tcp_traffic(source_ip, destination_ip)
        elif protocol == 'UDP':
            generate_udp_traffic(source_ip, destination_ip)
        elif protocol == 'ICMP':
            generate_icmp_traffic(source_ip, destination_ip)

        # Introduce variability in timing
        time.sleep(random.uniform(0.05, 0.5))

def generate_http_traffic(source_ip, destination_ip, protocol):
    port = COMMON_PORTS[protocol]
    method = random.choice(HTTP_METHODS)
    domain = random.choice(DOMAIN_NAMES)
    user_agent = random.choice(USER_AGENTS)
    
    if method in ['GET', 'DELETE']:
        payload = f"{method} / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: {user_agent}\r\n\r\n"
    else:
        content_type = random.choice(CONTENT_TYPES)
        content = "data=sample" if content_type == 'application/x-www-form-urlencoded' else '{"key": "value"}'
        payload = f"{method} / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: {user_agent}\r\nContent-Type: {content_type}\r\nContent-Length: {len(content)}\r\n\r\n{content}"

    packet = IP(src=source_ip, dst=destination_ip)/TCP(dport=port)/Raw(payload.encode())
    send(packet, verbose=False)

def generate_dns_traffic(source_ip, destination_ip):
    domain = random.choice(DOMAIN_NAMES)
    query = IP(src=source_ip, dst=destination_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
    response = IP(src=destination_ip, dst=source_ip)/UDP(sport=53)/DNS(id=query[DNS].id, qr=1, aa=1, qd=query[DNS].qd, an=DNSRR(rrname=domain, rdata="10.0.0.1"))
    send(query, verbose=False)
    time.sleep(0.01)
    send(response, verbose=False)

def generate_ftp_traffic(source_ip, destination_ip):
    commands = [b"USER anonymous\r\n", b"PASS anonymous@\r\n", b"PWD\r\n", b"TYPE I\r\n", b"PASV\r\n", b"LIST\r\n", b"QUIT\r\n"]
    for cmd in commands:
        packet = IP(src=source_ip, dst=destination_ip)/TCP(dport=21)/Raw(cmd)
        send(packet, verbose=False)
        time.sleep(0.05)

def generate_smtp_traffic(source_ip, destination_ip):
    commands = [
        b"EHLO example.com\r\n",
        b"MAIL FROM:<sender@example.com>\r\n",
        b"RCPT TO:<recipient@example.com>\r\n",
        b"DATA\r\n",
        b"Subject: Test Email\r\n\r\nThis is a test email.\r\n.\r\n",
        b"QUIT\r\n"
    ]
    for cmd in commands:
        packet = IP(src=source_ip, dst=destination_ip)/TCP(dport=25)/Raw(cmd)
        send(packet, verbose=False)
        time.sleep(0.05)

def generate_ssh_traffic(source_ip, destination_ip):
    # Simulate SSH handshake and some encrypted traffic
    syn = IP(src=source_ip, dst=destination_ip)/TCP(dport=22, flags="S")
    synack = IP(src=destination_ip, dst=source_ip)/TCP(sport=22, dport=syn.sport, flags="SA")
    ack = IP(src=source_ip, dst=destination_ip)/TCP(dport=22, sport=syn.sport, flags="A")
    
    send(syn, verbose=False)
    send(synack, verbose=False)
    send(ack, verbose=False)
    
    # Simulate some encrypted traffic
    for _ in range(3):
        data = IP(src=source_ip, dst=destination_ip)/TCP(dport=22)/Raw(RandString(size=random.randint(20, 100)))
        send(data, verbose=False)
        time.sleep(0.1)

def generate_tcp_traffic(source_ip, destination_ip):
    syn = IP(src=source_ip, dst=destination_ip)/TCP(dport=random.randint(1024, 65535), flags="S")
    synack = IP(src=destination_ip, dst=source_ip)/TCP(sport=syn.dport, dport=syn.sport, flags="SA")
    ack = IP(src=source_ip, dst=destination_ip)/TCP(sport=syn.sport, dport=syn.dport, flags="A")
    
    send(syn, verbose=False)
    send(synack, verbose=False)
    send(ack, verbose=False)

def generate_udp_traffic(source_ip, destination_ip):
    packet = IP(src=source_ip, dst=destination_ip)/UDP(dport=random.randint(1024, 65535))/Raw(RandString(size=random.randint(10, 100)))
    send(packet, verbose=False)

def generate_icmp_traffic(source_ip, destination_ip):
    packet = IP(src=source_ip, dst=destination_ip)/ICMP()
    send(packet, verbose=False)

if __name__ == "__main__":
    print("Starting random traffic generation...")
    start_time = time.time()
    generate_random_traffic()
    end_time = time.time()
    print(f"Traffic generation completed. Duration: {end_time - start_time:.2f} seconds")