from __future__ import print_function
from dadReply import DadReply


def dadReply(iface):
    dadReply= DadReply(iface)
    dadReply.sniffingAndReply()

dadReply("enp0s25")

