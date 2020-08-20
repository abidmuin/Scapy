from scapy.all import *
import socket
import datetime
import os
from geoip2 import *
import time


def network_monitoring_for_visualization_version(pkt):
    # importing time to get the actual time when pkt is sniffed
    time = datetime.datetime.now()
    # TCP
    if pkt.haslayer(TCP):
        # Incoming pkt
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].dst:
            print(str("[") + str(time) + str("]") + " " + "TCP-IN:{}".format(len(pkt[TCP])) + " Bytes" + " " + "SRC-MAC:" + str(pkt.src) + " " + "DST-MAC:"+str(pkt.dst)+" " + "SRC-PORT:" +
                  str(pkt.sport)+" "+"DST-PORT:"+str(pkt.dport) + " " + "SRC-IP: "+str(pkt[IP].src)+" "+"DST-IP: "+str(pkt[IP].dst)+" " + "Location: ")
        # Outgoing pkt
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].src:
            print(str("[") + str(time) + str("]") + " " + "TCP-OUT:{}".format(len(pkt[TCP])) + " Bytes" + " " + "SRC-MAC:" + str(pkt.src) + " " + "DST-MAC:"+str(pkt.dst)+" " + "SRC-PORT:" +
                  str(pkt.sport)+" "+"DST-PORT:"+str(pkt.dport) + " " + "SRC-IP: "+str(pkt[IP].src)+" "+"DST-IP: "+str(pkt[IP].dst)+" " + "Location: ")

    # UDP
    if pkt.haslayer(UDP):
        # Incoming pkt
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].dst:
            print(str("[") + str(time) + str("]") + " " + "UDP-IN:{}".format(len(pkt[UDP])) + " Bytes" + " " + "SRC-MAC:" + str(pkt.src) + " " + "DST-MAC:"+str(pkt.dst)+" " + "SRC-PORT:" +
                  str(pkt.sport)+" "+"DST-PORT:"+str(pkt.dport) + " " + "SRC-IP: "+str(pkt[IP].src)+" "+"DST-IP: "+str(pkt[IP].dst)+" " + "Location: ")
        # Outgoing pkt
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].src:
            print(str("[") + str(time) + str("]") + " " + "UDP-OUT:{}".format(len(pkt[UDP])) + " Bytes" + " " + "SRC-MAC:" + str(pkt.src) + " " + "DST-MAC:"+str(pkt.dst)+" " + "SRC-PORT:" +
                  str(pkt.sport)+" "+"DST-PORT:"+str(pkt.dport) + " " + "SRC-IP: "+str(pkt[IP].src)+" "+"DST-IP: "+str(pkt[IP].dst)+" " + "Location: ")
    # ICMP
    if pkt.haslayer(ICMP):
        # Incoming pkt
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].dst:
            print(str("[") + str(time) + str("]") + " " + "ICMP-IN:{}".format(len(pkt[ICMP])) + " Bytes" + " " + "SRC-MAC:" + str(pkt.src) + " " + "DST-MAC:"+str(pkt.dst)+" " + "SRC-PORT:" +
                  str(pkt.sport)+" "+"DST-PORT:"+str(pkt.dport) + " " + "SRC-IP: "+str(pkt[IP].src)+" "+"DST-IP: "+str(pkt[IP].dst)+" " + "Location: ")
        # Outgoing pkt
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].src:
            print(str("[") + str(time) + str("]") + " " + "ICMP-OUT:{}".format(len(pkt[ICMP])) + " Bytes" + " " + "SRC-MAC:" + str(pkt.src) + " " + "DST-MAC:"+str(pkt.dst)+" " + "SRC-PORT:" +
                  str(pkt.sport)+" "+"DST-PORT:"+str(pkt.dport) + " " + "SRC-IP: "+str(pkt[IP].src)+" "+"DST-IP: "+str(pkt[IP].dst)+" " + "Location: ")


if __name__ == '__main__':
    sniff(prn=network_monitoring_for_visualization_version)
