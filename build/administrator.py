import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR
from alert_header import Alert

TYPE_TRACE = 0x9999
TYPE_ALERT = 0x9997
TYPE_PROBE = 0x9998
TYPE_IPV4 = 0x0800

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        exit(1)
    return iface
    

def handle_pkt(pkt):
    if Alert in pkt:
        print ("got a packet")
        pkt.show()
        if pkt['Alert'].next_header == TYPE_IPV4:
            # send probe packet
            print(pkt['IP'])
        elif pkt['Alert'].next_header == TYPE_TRACE:
            print("trace")

def main():
    sys.stdout.flush()
    sniff(iface = "ens33",
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
