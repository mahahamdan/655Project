from scapy.all import sniff
from scapy.layers.l2 import ARP


def packet_found(packet):
    if ARP in packet:
        arp_layer = packet[ARP]
        #Arp request detected
        if arp_layer.op == 1:
            found_arp_request(arp_layer)
        # Arp response detected
        elif arp_layer.op == 2:
            found_arp_response(arp_layer)

def found_arp_request(arp_layer):
    # Detect arp request if ARP or SARP
    if is_sarp(arp_layer):
        print("Detect SARP Request")
    else:
        print("Detect ARP Request")


def found_arp_response(arp_layer):
    # Detect arp response if ARP or SARP
    if is_sarp(arp_layer):
        print("Detect SARP Response")
    else:
        print("Detect ARP Response")

def is_sarp(arp_layer):
    # This func recognize if the arp layer is arp or SARP
    if 'security_field' in arp_layer[ARP].fields:
        return True
    else:
        return False


def sniff_packets():
    sniff(prn=packet_found, store=0)


