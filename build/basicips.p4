/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define MAX_IDS 9

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP  = 0x0806;
const bit<16> TYPE_IDS  = 0xFFFF;
const bit<16> ARP_REQ = 0x0001;
const bit<16> ARP_RES = 0x0002;
const bit<9>  CON_PORT = 0x0;

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
    bit<16> checksum
}

header http_t {
}
const bit<2> LINK_LAYER = 0;
const bit<2> NET_LAYER = 1;
const bit<2> TRANS_LAYER =2;
const bit<2> APP_LAYER = 3;

const bit<2> ACCEPT = 0;
const bit<2> REJECT = 1;
const bit<2> UNKOWN = 2;
const bit<2> RESERVED = 3;

header ids_count_t{
    bit<8> count;
}

header ids_t {
    bit<2> layer; // 00: data link layer, 01: network layer, 10: transport layer, 11: application layer
    bit<2> flag;// 00: accept, 01:reject, 10:unkown, 11: reserved
}

struct metadata {
    /* empty */
}

struct headers {
    // data link layer
    ethernet_t  ethernet;
    // ids layer
    ids_count_t ids_count;
    ids_t[MAX_IDS] idses;
    // network layer
    ipv4_t          ipv4;
    arp_t            arp;
    // transport layer
    tcp_t            tcp;
    udp_t            udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    // init parse
    state start {
        transition parse_ethernet;
    }

    // parse data link layer
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP:  parse_arp;
            default: accept;
        }
    }
    
    // parse network layer
    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: tcp;
            TYPE_UDP: udp;
            default: accept;
        }
    }

    // parse transport layer
    state tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    // parse application layer

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

control Forward(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

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
    }

    action drop() {
        mark_to_drop();
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
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
        size = 1024;
        default_action = drop();
    }

    // this table is used to forward ipv4 packet
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;// if the host is directly connected with the switch host' ip/32 and the mac is the host'mac if the host isn't directly connected with the switch: network/mask and the mac is the next switch's port's mac
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
        size = 1024;

    }

    apply {

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
                port_mac.apply();
            }
        }
    }
}

/*************************************************************************
****************  I D S   P R O C E S S I N G   *******************
*************************************************************************/

control IDS(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action drop(){
        mark_to_drop();
    }
    action unkown_ip() {
        hdr.ids.layer = NET_LAYER;
        hdr.ids.flag = UNKOWN;
    }

    action black_ip() {
        hdr.ids.layer = NET_LAYER;
        hdr.ids.flag = REJECT;
        drop();
    }

    action white_ip() {
        hdr.ids.layer = NET_LAYER; // network layer
        hdr.ids.flag = ACCEPT; // accept action
    }

    table ip_address_ids {
        key = {
            hdr.ipv4.srcAddr: exact;
        }
        actions = {
            black_ip;
            white_ip;
        }
        size = 100;
    }

    action send_alert() {
        standart_metadata.egress_spec = CON_PORT;
        hdr.ids.flag = REJECT;
        hdr.ids.layer
    }

    actions is_white() {
        //!(flag == ACCEPT && layer == NET_LAYER)
        if(hdr.ids.flag != ACCEPT || hdr.ids.layer != NET_LAYER) {
            // illegal access
            // send alert to the control plane to add the ip to black list
            
        }
    }

    action is_unkown() {
        //!(flag == UNKOWN && layer == NET_LAYER)
        if(hdr.ids.flag != UNKOWN || hdr.ids.layer != NET_LAYER) {
            // illegal access
            // send alert to the control plane to add the ip to black list
        }
    }    

    table port_tcp_ids {
        key = {
            hdr.tcp.dstPort: exact;
        }
        actions = {
            is_white;
            is_unkown;
        }
    }

    apply {
        if(ip_adress_ids.apply().miss) {
            // the ip is not in the black or white list
            unkown_ip();
        }
    }
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
IDS(),
Forward(),
MyComputeChecksum(),
MyDeparser()
) main;
