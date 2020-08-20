from scapy.all import *
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

if len(sys.argv) != 4:
    print("Proper format: %s target startPort endPort" % sys.argv[0])
    sys.exit(0)

target = str(sys.argv[1])
startPort = int(sys.argv[2])
endPort = int(sys.argv[3])

print("Scanning " + target + " for open TCP ports\n")

if startPort == endPort:
    endPort += 1

# ? 3 way handshake connection, SYN-> SYN-ACK -> ACK

for x in range(startPort, endPort):
    packet = IP(dst=target) / TCP(dport=x, flags='S')  # S = SYN flag
    response = sr1(packet, timeout=0.5, verbose=0)
    if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:  # ? 0x12 = SYN-ACK
        print('Port ' + str(x) + ' is open.')
    sr(IP(dst=target)/TCP(dport=response.sport, flags='R'),
       timeout=0.5, verbose=0)  # ? R = reset pkt, get rid of the connection asap move on to the next pkt.

print('Scan is complete!')
