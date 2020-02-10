from scapy.all import *
import sys, os

TYPE_ALERT = 0x9997
TYPE_PROBE = 0x9998
TYPE_IPV4 = 0x0800

class Alert(Packet):
    name = "Alert"
    fields_desc = [
        BitField("type", 0, 8),
        BitField("switch_id", 0, 8),
        ShortField("next_header", 0)
    ]
    def alert_summary(self):
        return self.sprintf("type=%type%, switch_id=%switch_id%, next_header=%next_header%")

bind_layers(Ether, Alert, type=TYPE_ALERT)
