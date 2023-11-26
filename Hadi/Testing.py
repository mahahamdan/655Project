from scapy.all import IP, UDP, Ether, ESP, AH, send
import time

# Function to send IPSec packet
def send_ipsec_packet(packet):
    send(packet, verbose=0)

while True:

# Fabricate and send ESP packet
    esp_packet = IP(src="192.168.1.1", dst="192.168.1.2") / ESP()
    send_ipsec_packet(esp_packet)

# Fabricate and send AH packet
    ah_packet =  IP(src="192.168.1.1", dst="192.168.1.2") / AH()
    send_ipsec_packet(ah_packet)

    time.sleep(1)

# Fabricate and send packet with invalid IHL
    #invalid_ihl_packet = Ether(dst="28:3A:4D:46:A2:49") / IP(src="192.168.1.1", dst="192.168.1.2", ihl=6) / UDP()
    #send_ipsec_packet(invalid_ihl_packet)
