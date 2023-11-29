from scapy.all import sniff, ARP, get_if_list

#function to output valid interface names for the user to choose from
def get_interfaces():
    interfaces = get_if_list()
    print("Available network interfaces:")
    for i, interface in enumerate(interfaces):
        print(f"{i + 1}. {interface}")
    
    while True:
        try:
            index = int(input("Enter the index of the network interface you want to use: "))
            selected_interface = interfaces[index - 1]
            return selected_interface
        except (ValueError, IndexError):
            print("Invalid input. Please enter a valid index.")

def arp_packet_callback(packet):
    if ARP in packet and packet[ARP].op in [1, 2]:  # ARP request or reply
        arp_protocol = "ARP"
        if packet[ARP].hwtype == 1 and packet[ARP].ptype == 0x0806:
            arp_protocol = "S-ARP"
        print(f"{arp_protocol} Packet Detected: {packet.summary()}")

interface = get_interfaces()

print(f"Using network interface: {interface}")
    
# Sniff for 10 packets
sniff(prn=arp_packet_callback, store=0, filter="arp", iface=interface, count=10)
