import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

def handle_pkt(pkt):
    pkt.show()
    #print(pkt)

def main():
    sys.stdout.flush()
    sniff(iface = "ens33",
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
