from scapy.all import *
import sys, os

TYPE_ALERT = 0x9997
TYPE_PROBE = 0x9998
TYPE_IPV4 = 0x0800

class Alert(Packet):
    name = "Alert"
    fields_desc = [
        XByteField("type", 0),
        XByteField("switch_id", 0),
        ShortField("next_header", 0)
    ]
    def alert_summary(self):
        return self.sprintf("type=%type%, switch_id=%switch_id%, next_header=%next_header%")

bind_layers(Ether, Alert, type=TYPE_ALERT)
