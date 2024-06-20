# normal_traffic.py

import time
import random
import requests

def generate_normal_traffic(target_ip, duration=60):
    url = f"http://{target_ip}/"
    end_time = time.time() + duration
    sent_requests = 0

    while time.time() < end_time:
        try:
            response = requests.get(url)
            sent_requests += 1
            print(f"Sent request #{sent_requests}, status code: {response.status_code}")
        except requests.RequestException as e:
            print(f"Request failed: {e}")

        # Sleep for a random interval between requests to simulate normal user behavior
        time.sleep(random.uniform(0.5, 2.0))

if __name__ == "__main__":
    target_ip = "10.0.0.12"
    duration = 60  # Generate normal traffic for 60 seconds
    generate_normal_traffic(target_ip, duration)
