from scapy.all import IP, ESP, AH, sniff
#from Testing import fabricate_esp_packet
#from Testing import fabricate_ah_packet
import threading
#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------by Hadi
#IPSec
def detectProtocol(packet):
    try:
        if IP not in packet:
            return "Invalid Packet: No IP Header" #checks if packet contains an IP header; if not, it prints "Invalid Packet: No IP Header"
        ipHeader = packet[IP] #extracts IP header
        #checking the length of the IP header
        ihl = ipHeader.ihl  #extracts internet header length
        expectedHeaderLength = ihl * 4  #IHL is in 4-byte units
        if len(ipHeader) < expectedHeaderLength:
            return f"Invalid Packet: IP Header Length Mismatch (Expected: {expectedHeaderLength}, Actual: {len(ipHeader)})" #checks if the actual length of the IP header is less than the expected length; 
                                                                                                                            #if it is, it returns an "Invalid Packet: IP Header Length Mismatch" message.
        protocol = ipHeader.proto #extracts protocol number from the header

        #checing for IPSec
        if protocol == 50:  #Protocol number for IPsec ESP
            return "IPsec ESP"
        elif protocol == 51:  #Protocol number for IPsec AH
            return "IPsec AH"
        elif protocol == 6:  #Protocol number for TCP
            return "IP (with TCP)"
        elif protocol == 17:  #Protocol number for UDP
            return "IP (with UDP)"
        else:
            return f"IP (with Unknown Protocol {protocol})"
    except Exception as e: #handling errors gracefully using try except
        return f"Error during protocol detection: {str(e)}"
        
def packetHandler(packet):
    try:
        result = detectProtocol(packet)
        print(f"Captured Packet: {result}")#printing the results from the return statements
    except Exception as e:
        print(f"Error processing packet: {e}")

#sniffing packets from the network
def sniffPackets():
    sniff(prn=packetHandler)

#starting sniffing in a separate thread
sniffThread = threading.Thread(target=sniffPackets)
sniffThread.start()

#keeping the main thread running
sniffThread.join()
