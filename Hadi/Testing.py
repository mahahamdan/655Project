from scapy.all import IP, UDP, Ether, ESP, AH, send
import time
#-------------------------------------------------------------------------------------------by Hadi
#this code is for testing IPSec code
conf.iface = "Realtek RTL8822BE 802.11ac PCIe Adapter" #default interface
#function to send IPSec packet
def sendIPSecPacket(packet):
    send(packet, verbose=0)

while True:

    #fabricating and sending ESP packet 
    espPacket = IP() / ESP()
    sendIPsecPacket(espPacket)

    #fabricating and sending AH packet
    ahPacket =  IP() / AH()
    sendIPsecPacket(ahPacket)

    #fabricating and sending packet with invalid IHL
    invalidIHLPacket =  IP(ihl=6) / UDP() #can be UDP or TCP
    sendIPSecPacket(invalidIHLPacket)

    time.sleep(1) #time before sending more packets
