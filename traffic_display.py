# traffic_display.py
import time
import sys

def main():
    try:
        while True:
            with open("traffic_data.txt", "r") as file:
                traffic_data = file.read()
            clear_screen()
            print("Current Traffic Flow:")
            print(traffic_data)
            time.sleep(2)
    except KeyboardInterrupt:
        print("Stopping traffic display")

def clear_screen():
    import os
    os.system('cls' if os.name == 'nt' else 'clear')

if __name__ == "__main__":
    main()
