import datetime

from nmap import PortScanner
from scapy.all import srp, conf
from scapy.layers.l2 import ARP, Ether
import threading

interface = 'wlp0s20f3'
ips = '192.168.0.1/24'

conf.verb = 0
ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ips), timeout = 2, iface=interface, inter = 0.1)
# now print ip found
targets = []
threads = []
for send,rcv in ans:
    targets.append(rcv.psrc)

# Nmap Scanner
def nmapScanner(target):
    startingDate = datetime.datetime.now()
    nm = PortScanner()

    # The target below is an online target used for testing
    # target = "176.148.84.19"

    #Choose the ports we need to scan on
    ports = "21,23,25,37,43,53,80,143,445,389,8888"
    # Start Scanning
    nm.scan(target, ports)

    # Results are stated
    print("Starting scan at", startingDate)
    for host in nm.all_hosts():
        hostName = nm[host].hostname()
        hostIP = host
        print(f"The host IP is : {hostIP}")
        print(f"The host name is : {hostName}")
        print(f"State : {nm[host].state()}\n")

        for proto in nm[host].all_protocols():
            print(f"The protocol for the below ports is: {proto}\n")
            lport = nm[host][proto].keys()

            i = 1
            for port in lport:
                print(f"{i}.Port : {port}")
                print(f"State : {nm[host][proto][port]['state']}")
                print(f"Reason : {nm[host][proto][port]['reason']}")
                print(f"Name : {nm[host][proto][port]['name']}")
                print(f"Product : {nm[host][proto][port]['product']}")
                print(f"Version : {nm[host][proto][port]['version']}")
                print(f"Extra Info : {nm[host][proto][port]['extrainfo']}")
                print(f"Configuration File : {nm[host][proto][port]['conf']}")
                print(f"CPE : {nm[host][proto][port]['cpe']}")
                print("\n")
                i = i+1
    endingDate = datetime.datetime.now()

    print("Ending Date is: ", endingDate)

for target in targets:
    thread = threading.Thread(target=nmapScanner, args=(target,))
    threads.append(thread)
    thread.start()

