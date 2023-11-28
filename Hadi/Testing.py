from scapy.all import IP, UDP, Ether, ESP, AH, send, conf
import time
#-------------------------------------------------------------------------------------------by Hadi
#this code is for testing IPSec code
#conf.iface = "Realtek RTL8822BE 802.11ac PCIe Adapter" #my default interface in case I remove src and dst
#function to send IPSec packet
def sendIPSecPacket(packet):
    send(packet, verbose=0)

while True:

    #fabricating and sending ESP packet 
    espPacket = IP(src="192.168.1.1", dst="192.168.1.2") / ESP()
    sendIPSecPacket(espPacket)

    #fabricating and sending AH packet
    ahPacket =  IP(src="192.168.1.1", dst="192.168.1.2") / AH()
    sendIPSecPacket(ahPacket)

    #fabricating and sending packet with invalid IHL
    invalidIHLPacket =  IP(src="192.168.1.1", dst="192.168.1.2", ihl=6) / UDP() #can be UDP or TCP
    sendIPSecPacket(invalidIHLPacket)

    time.sleep(1) #time before sending more packets
