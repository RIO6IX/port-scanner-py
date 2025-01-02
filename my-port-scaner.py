#!/usr/bin/env python3
# To install the required software, use the following commands in Kali Linux:
#  sudo apt install python3-pip
#  pip install python-nmap

import nmap
import re

ip_type = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
port_range = re.compile("([0-9]+)-([0-9]+)")

port_max = 0
port_min = 65535

print("*"*75)
print("                      +-+-+-+-+ +-+-+-+-+-+-+")
print("                      |P|O|R|T| |S|C|A|N|E|R|")
print("                      +-+-+-+-+ +-+-+-+-+-+-+")
print("*"*75)
print(r""" ________  ___  ___  ________  ________   ___  ___  ___  __    ________     
|\   ____\|\  \|\  \|\   __  \|\   ___  \|\  \|\  \|\  \|\  \ |\   __  \    
\ \  \___|\ \  \\\  \ \  \|\  \ \  \\ \  \ \  \\\  \ \  \/  /|\ \  \|\  \   
 \ \  \    \ \   __  \ \   __  \ \  \\ \  \ \  \\\  \ \   ___  \ \   __  \  
  \ \  \____\ \  \ \  \ \  \ \  \ \  \\ \  \ \  \\\  \ \  \\ \  \ \  \ \  \ 
   \ \_______\ \__\ \__\ \__\ \__\ \__\\ \__\ \_______\ \__\\ \__\ \__\ \__\
    \|_______|\|__|\|__|\|__|\|__|\|__| \|__|\|_______|\|__| \|__|\|__|\|__|""")

# Copyright information
print("*"*75)
print("\n* Copyright of Chanuka Isuru Sampath, 2024                                *")
print("\n* https://www.linkedin.com/in/chanuka-isuru-sampath-289358247/            *\n")
print("*"*75)

open_ports = []

# Asking for the IP address to scan
while True:
    ip_add = input("\n Enter the ip address to scan: ").strip()  # Removed extra spaces
    if ip_type.search(ip_add):  # Validating IP
        print(f"{ip_add} is a valid IP address")
        break  # Exit

# Asking for the range of ports to scan
while True:
    print("Enter the range of ports to scan (like 10-150)")
    port_range_input = input("Enter the port range: ")
    port_range_valid = port_range.search(port_range_input.replace(" ", ""))  # Validating port range
    if port_range_valid:
        port_min = int(port_range_valid.group(1))
        port_max = int(port_range_valid.group(2))
        if port_min > port_max:
            print("Error: Port minimum is greater than port maximum.")
            continue
        break  # Exit

n = nmap.PortScanner()

# Looping through each port in range
for port in range(port_min, port_max + 1):
    try:
        result = n.scan(ip_add, str(port))
        # Port status from the result (open/closed)
        port_status = result['scan'][ip_add]['tcp'][port]['state']
        if port_status == "open":
            open_ports.append(port)
        print(f"Port {port} is {port_status}")  # Display the status of the port
    except Exception as e:
        print(f"Cannot scan port {port}. Error: {e}")  # Inform if the port cannot be scanned

# Printing open ports
print("\n==== Open Ports ====")
print(open_ports)
