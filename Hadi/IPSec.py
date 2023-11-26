from scapy.all import IP, ESP, AH, sniff
from packet_fabrication import send_ipsec_packet

def detect_protocol(packet):
    # Check if the packet is long enough to contain IP header
    if IP not in packet:
        return "Invalid Packet: No IP Header"

    # Extract the IP header fields
    ip_header = packet[IP]
    # Check the length of the IP header
    ihl = ip_header.ihl  # Internet Header Length
    expected_header_length = ihl * 4  # IHL is in 4-byte units
    if len(ip_header) < expected_header_length:
        return f"Invalid Packet: IP Header Length Mismatch (Expected: {expected_header_length}, Actual: {len(ip_header)})"

    protocol = ip_header.proto

    # Check if it's an IP packet
    if protocol == 50:  # Protocol number for IPsec ESP
        return "IPsec ESP"
    elif protocol == 51:  # Protocol number for IPsec AH
        return "IPsec AH"
    elif protocol == 6:  # Protocol number for TCP
        return "IP (with TCP)"
    elif protocol == 17:  # Protocol number for UDP
        return "IP (with UDP)"
    else:
        return f"IP (with Unknown Protocol {protocol})"

def packet_handler(packet):
    result = detect_protocol(packet)
    print(f"Captured Packet: {result}")

# Sniff packets from the network and apply the detection function
def sniff_and_detect():
    sniff(prn=packet_handler)

# Start sniffing in a separate thread
import threading
sniff_thread = threading.Thread(target=sniff_and_detect)
sniff_thread.start()

# Keep the main thread running
sniff_thread.join()
