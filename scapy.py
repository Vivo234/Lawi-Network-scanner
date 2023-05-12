from scapy.all import ARP, Ether, srp

# Define the IP range to scan
target_ip = "192.168.1.0/24"

# Create an ARP request packet
arp = ARP(pdst=target_ip)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether/arp

# Send the packet and capture the response
result = srp(packet, timeout=3, verbose=0)[0]

# Parse the response to extract the IP and MAC addresses of devices on the network
clients = []
for sent, received in result:
    clients.append({'ip': received.psrc, 'mac': received.hwsrc})

# Print the list of clients on the network
print("Devices on the network:")
for client in clients:
    print(f"IP: {client['ip']}\t MAC: {client['mac']}")
