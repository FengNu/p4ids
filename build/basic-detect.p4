/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#define MAX_PORT_NUM 10

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP  = 0x0806;
const bit<16> ARP_REQ = 0x0001;
const bit<16> ARP_RES = 0x0002;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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

header arp_t{
    bit<16> hardwareType; // 0x0001 mac address
    bit<16> protocolType; // 0x0800 ipv4
    bit<8>  hardwaresize; // 0x06 mac address length
    bit<8>  protocolSize; // 0x04 ipv4 address length
    bit<16> opCode;       // arp request: 0x0001 arp reponse: 0x0002
    macAddr_t senderMacAddr;
    ip4Addr_t senderIpAddr;
    macAddr_t targetMacAddr;
    ip4Addr_t targetIpAddr;
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

header trace_header_t {
    bit<8>  length;
    varbit<64> elastic;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    arp_t        arp;
    udp_t        udp;
    tcp_t        tcp;
}

struct tmp {
    bit<32> a;
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
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP:  parse_arp;
            default: accept;
        }
    }
    
    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select (hdr.ipv4.ihl) {
            5 : dispatch_on_protocol;
            _ : accept;
        }
    }
    
    state dispatch_on_protocol {
        transition select(hdr.ipv4.protocol) {
            TYPE_UDP: parse_udp;
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        if()
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_trace_header {
        
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

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    register<bit<80>>(MAX_PORT_NUM) host_table;
    
    action set_host_info(inout bit<80> host_info) {
        host_info = 0;
        host_info = host_info | (((bit<80>)hdr.arp.senderMacAddr) << 32);
        host_info = host_info | (bit<80>)hdr.arp.senderIpAddr;
    }

    action get_host_info(in bit<80> host_info, inout macAddr_t mac, inout ip4Addr_t ip) {
        bit<80> mac_tmp;
        bit<80> ip_tmp;
        mac_tmp = (host_info & 1208925819614624879738880) >> 32;
        ip_tmp = host_info & 4294967295
        mac = (bit<48>) mac_tmp;
        ip = (bit<32>) ip_tmp;
    }

    action arp_response() {
        ip4Addr_t temp;
        // send back to the ingress port
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        // set the opCode, set the dst mac, target mac swap target ip and sender ip
        hdr.arp.opCode = ARP_RES;

        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;

        hdr.arp.targetMacAddr = hdr.arp.senderMacAddr;
        temp = hdr.arp.targetIpAddr;
        hdr.arp.targetIpAddr = hdr.arp.senderIpAddr;
        hdr.arp.senderIpAddr = temp;

        // update the host_table
        
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(bit<32> integer) {
        meta.tmp = integer;
        log_msg("value1 = {}", {integer});
    }

    action set_smac(macAddr_t portMacAddr) {
        hdr.ethernet.srcAddr = portMacAddr;
        if(hdr.ethernet.etherType == TYPE_ARP) {
            hdr.arp.senderMacAddr = portMacAddr;
        }
    }

    // this table is used to check if the target Ip of the ARP request is the switch's port's ip
    table arp_response_table {
        key = {
            hdr.arp.targetIpAddr: exact;
        }
        actions = {
            arp_response;
            drop;
            NoAction;
        }
        const entries = {
            (0x0a000101) : arp_response();
        }
        default_action = drop();
    }

    // this table is used to forward ipv4 packet
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: ternary;
            hdr.ipv4.srcAddr: ternary;
            hdr.ipv4.protocol: ternary;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    // The table to store every port's mac of this switch. It is used to set the source mac the packet
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
        const entries = {
            (1) : set_smac(0x000c29908cf6);
            (2) : set_smac(0x000c29908c00);
            (3) : set_smac(0x000c29908c0a);
        }


    }
    apply {
        bit<10000> test = 1;
        test = test<<256;
        log_msg("value_test={}",{test});
        test = test<<41;
        log_msg("value_test={}",{test});
        if(hdr.ethernet.etherType == TYPE_ARP) {
            if(hdr.arp.isValid()) {
                if(hdr.arp.opCode == ARP_REQ) {
                    arp_response_table.apply();
                    port_mac.apply();
                }
            }
        }else if (hdr.ethernet.etherType == TYPE_IPV4) {
            if(hdr.ipv4.isValid()){
                ipv4_lpm.apply();

            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
