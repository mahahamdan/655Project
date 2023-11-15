from nmap import PortScanner

# Nmap Scanner
nm = PortScanner()

# The target below is an online target used for testing
target = "176.148.84.19"

#Choose the ports we need to scan on
ports = "21,23,25,37,43,53,80,143,445,389,8888"

# Start Scanning
nm.scan(target, ports)

# Results are stated
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
