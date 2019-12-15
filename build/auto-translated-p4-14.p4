#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_ARP = 0x806;
const bit<8> TYPE_TCP = 0x6;
const bit<8> TYPE_UDP = 0x11;
const bit<16> ARP_REQ = 0x1;
const bit<16> ARP_RES = 0x2;
typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> port_t;
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
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

header arp_t {
    bit<16>   hardwareType;
    bit<16>   protocolType;
    bit<8>    hardwaresize;
    bit<8>    protocolSize;
    bit<16>   opCode;
    macAddr_t senderMacAddr;
    ip4Addr_t senderIpAddr;
    macAddr_t targetMacAddr;
    ip4Addr_t targetIpAddr;
}

header tcp_t {
    port_t  srcPort;
    port_t  dstPort;
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
    port_t  srcPort;
    port_t  dstPort;
    bit<16> dataLen;
    bit<16> checksum;
}

const bit<9> SEP_IP = 0x3;
const bit<9> SEP_TR = 0x3;
struct metadata {
    bit<9> sep;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    arp_t      arp;
    udp_t      udp;
    tcp_t      tcp;
}

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }
    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_UDP: parse_udp;
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action arp_response() {
        ip4Addr_t temp;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        hdr.arp.opCode = ARP_RES;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.arp.targetMacAddr = hdr.arp.senderMacAddr;
        temp = hdr.arp.targetIpAddr;
        hdr.arp.targetIpAddr = hdr.arp.senderIpAddr;
        hdr.arp.senderIpAddr = temp;
    }
    action drop() {
        mark_to_drop();
    }
    action set_smac(macAddr_t portMacAddr) {
        hdr.ethernet.srcAddr = portMacAddr;
        if (hdr.ethernet.etherType == TYPE_ARP) {
            hdr.arp.senderMacAddr = portMacAddr;
        }
    }
    table arp_response_table {
        key = {
            hdr.arp.targetIpAddr: exact;
        }
        actions = {
            arp_response;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    table port_mac {
        key = {
            standard_metadata.egress_spec: exact;
        }
        actions = {
            set_smac;
            drop;
            NoAction;
        }
        default_action = drop();
        size = 1024;
    }
    apply {
        if (hdr.ethernet.etherType == TYPE_ARP) {
            if (hdr.arp.isValid()) {
                if (hdr.arp.opCode == ARP_REQ) {
                    arp_response_table.apply();
                    port_mac.apply();
                }
            }
        }
        else 
            if (hdr.ethernet.etherType == TYPE_IPV4) {
                meta.sep = SEP_IP;
                clone3(CloneType.I2E, (bit<32>)SEP_IP, { meta.sep });
                meta.sep = SEP_TR;
                clone3(CloneType.I2E, (bit<32>)SEP_TR, { meta.sep });
                drop();
            }
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        if (meta.sep >= 1) {
            standard_metadata.egress_spec = meta.sep;
            standard_metadata.clone_spec = (bit<32>)meta.sep;
        }
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(hdr.ipv4.isValid(), { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;

