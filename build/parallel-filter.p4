/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define INGRESS_PORT 1
#define EGRESS_PORT 2

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP  = 0x0806;
const bit<16> TYPE_IDS  = 0xFFFF;
const bit<16> ARP_REQ = 0x0001;
const bit<16> ARP_RES = 0x0002;
const bit<9>  CON_PORT = 0x0;

const bit<8> DIS_IPV4 = 3;
const bit<8> DIS_TCP = 4;
const bit<8> DIS_UDP = 5;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<16> port_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> macAddr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header distribute_t {
    bit<32>  group;
    bit<8>   type;
    bit<64>  ruleIds;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}


header tcp_t{
    port_t srcPort;
    port_t dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}


header udp_t {
    port_t srcPort;
    port_t dstPort;
    bit<16> dataLen;
    bit<16> checksum;
}

struct metadata {
    bit<6> tcp_flag;
}

struct headers {
    ethernet_t        ethernet;
    distribute_t      dis;
    ipv4_t            ipv4;
    udp_t             udp;
    tcp_t             tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        packet.extract(hdr.dis);
        transition select(hdr.dis.type) {
            DIS_IPV4: parse_ipv4;
            DIS_TCP: parse_tcp;
            DIS_UDP: parse_udp;
            default: reject;
        }
    }
    
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.tcp_flag = (bit<6>)hdr.tcp.urg << 5 | (bit<6>)hdr.tcp.ack << 4 | (bit<6>)hdr.tcp.psh << 3 | (bit<6>)hdr.tcp.rst << 2 | (bit<6>)hdr.tcp.syn << 1 | (bit<6>)hdr.tcp.fin;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
    
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control ingress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action forward() {
        standard_metadata.egress_spec = EGRESS_PORT;
    }

    action mark_rule_ids(bit<64> rule_ids) {
        hdr.dis.ruleIds = rule_ids;
        standard_metadata.egress_spec = EGRESS_PORT;
    }

    action set_mac(macAddr_t portMacAddr, macAddr_t dstMacAddr) {
        hdr.ethernet.srcAddr = portMacAddr;
        hdr.ethernet.dstAddr = dstMacAddr;
    }

    table ipv4_filter {
        key = {
            hdr.ipv4.srcAddr: ternary;
            hdr.ipv4.dstAddr: ternary;
            hdr.ipv4.protocol: ternary;
        }

        actions = {
            mark_rule_ids;
            forward;
        }

        size = 1024;
        default_action = forward;
    }

    table tcp_filter {
        key = {
            hdr.tcp.srcPort: range;
            hdr.tcp.dstPort: range;
            meta.tcp_flag: ternary;
        }

        actions = {
            mark_rule_ids;
            forward;
        }

        size = 1024;
        default_action = forward;
    }

    table udp_filter {
        key = {
            hdr.udp.srcPort: range;
            hdr.udp.dstPort: range;
        }

        actions = {
            mark_rule_ids;
            forward;
        }

        size = 1024;
        default_action = forward;
    }

    // The table to store every port's mac of this switch. It is used to set the source mac the packet
    table port_mac {

        key = {
            standard_metadata.ingress_port: exact;
            standard_metadata.egress_spec: exact;
        }

        actions = {
            set_mac;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    apply {
        if(hdr.dis.type == DIS_IPV4) {
            ipv4_filter.apply();
        } else if (hdr.dis.type == DIS_TCP) {
            tcp_filter.apply();
        } else if(hdr.dis.type == DIS_UDP) {
            udp_filter.apply();
        } else if(hdr.dis.type == DIS_APP) {
            
        }
        port_mac.apply();
    }

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control egress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {


    apply {

    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply { }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.dis);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv4options);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
ingress(),
egress(),
MyComputeChecksum(),
MyDeparser()
) main;
