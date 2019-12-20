/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP  = 0x0806;
const bit<16> TYPR_DIS  = 0x9999;

const bit<8>  TYPE_TCP = 0x06;
const bit<8>  TYPE_UDP = 0x11;
const bit<8>  TYPE_ICMP= 0x01;

const bit<16> ARP_REQ = 0x0001;
const bit<16> ARP_RES = 0x0002;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16>  port_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

const bit<8> DIS_IPV4 = 3;
const bit<8> DIS_TCP = 4;
const bit<8> DIS_UDP = 5;
const bit<8> DIS_APP = 6;

header distribute_t {
    bit<32>  group;
    bit<8>   type;
    bit<8>   segNum;
    bit<64>  ruleIds;
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

const bit<32> SEP_TR = 0x03;
const bit<32> SEP_AP = 0x04;

struct metadata {
    bit<1>  is_tcp;
    bit<32> groupId;
    bit<8>  segNum;
}

struct headers {
    ethernet_t        ethernet;
    distribute_t      dis;
    ipv4_t            ipv4;
    arp_t             arp;
    udp_t             udp;
    tcp_t             tcp;
}

error {
    InvalidIPv4Header,
    InvalidTCPHeader
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
            default: reject;
        }
    }
    
    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        verify(hdr.ipv4.ihl >= 5, error.InvalidIPv4Header);
        transition select (hdr.ipv4.ihl) {
            5 : dispatch_on_protocol;
            _ : reject;
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
        meta.is_tcp = 0;
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.is_tcp = 1;
        verify(hdr.tcp.dataOffset >= 5, error.InvalidTCPHeader);
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
    register<bit<32>>(1) globalGroupId;
    bit<32> currentGroupId;

    action arp_response(macAddr_t portMacAddr) {
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
        hdr.ethernet.srcAddr = portMacAddr;
        hdr.arp.senderMacAddr = portMacAddr;
    }

    action drop() {
        mark_to_drop(standard_metadata);
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
        default_action = drop();
        const entries = {
            (0x0a000101) : arp_response(0x000c29908cf6);
        }
    }


    apply {
        if(hdr.ethernet.etherType == TYPE_ARP) {
            if(hdr.arp.isValid()) {
                if(hdr.arp.opCode == ARP_REQ) {
                    arp_response_table.apply();
                }
            } else {
                drop();
            }
        } else if (hdr.ethernet.etherType == TYPE_IPV4) {
          globalGroupId.read(currentGroupId, 0);
          meta.segNum = 1;
          if((hdr.ipv4.protocol == TYPE_ICMP || hdr.ipv4.protocol == TYPE_TCP || hdr.ipv4.protocol == TYPE_UDP) && standard_metadata.instance_type == PKT_INSTANCE_TYPE_NORMAL) {
              standard_metadata.egress_spec = 2;// origin packet is used to ipv4 header packet
              meta.groupId = currentGroupId;
              if(hdr.tcp.isValid() || hdr.udp.isValid()) {
                  meta.segNum = 2;
                  clone3(CloneType.I2E, (bit<32>)SEP_TR, meta);
              }
              globalGroupId.write(0, currentGroupId + 1);
          } else {
              drop();
          }

        } else {
            drop();
        }

    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control egress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action reserve_ipv4_header(in bit<32> groupId) {
        hdr.dis.setValid();
        hdr.dis.group = groupId;
        hdr.dis.type = DIS_IPV4;
        hdr.dis.ruleIds = 0;
        hdr.dis.segNum = meta.segNum;
        hdr.tcp.setInvalid();
//        if(hdr.tcp.isValid()) {
//            hdr.tcp.srcPort = 0;
//            hdr.tcp.dstPort = 0;
//            hdr.tcp.seqNo = 0;
//            hdr.tcp.ackNo = 0;
//            hdr.tcp.dataOffset = 0;
//            hdr.tcp.res = 0;
//            hdr.tcp.cwr = 0;
//            hdr.tcp.ece = 0;
//            hdr.tcp.urg = 0;
//            hdr.tcp.ack = 0;
//            hdr.tcp.psh = 0;
//            hdr.tcp.rst = 0;
//            hdr.tcp.syn = 0;
//            hdr.tcp.fin = 0;
//            hdr.tcp.window = 0;
//            hdr.tcp.checksum = 0;
//            hdr.tcp.urgentPtr = 0;
//        }
        hdr.udp.setInvalid();
//        if(hdr.udp.isValid()) {
//            hdr.udp.srcPort = 0;
//            hdr.udp.dstPort = 0;
//            hdr.udp.dataLen = 0;
//            hdr.udp.checksum = 0;
//        }
    }
    
    action reserve_transport_header(in bit<32> groupId) {
        hdr.dis.setValid();
        hdr.dis.group = groupId;
        if(meta.is_tcp == 1) {
            hdr.dis.type = DIS_TCP;
        } else {
            hdr.dis.type = DIS_UDP;
        }
        hdr.dis.ruleIds = 0;
        hdr.dis.segNum = meta.segNum;
        
        hdr.ipv4.setInvalid();
//        hdr.ipv4.version = 0;
//        hdr.ipv4.ihl = 0;
//        hdr.ipv4.diffserv = 0;
//        hdr.ipv4.totalLen = 0;
//        hdr.ipv4.identification = 0;
//        hdr.ipv4.flags = 0;
//        hdr.ipv4.fragOffset = 0;
//        hdr.ipv4.ttl = 0;
//        hdr.ipv4.protocol = 0;
//        hdr.ipv4.hdrChecksum = 0;
//        hdr.ipv4.srcAddr = 0;
//        hdr.ipv4.dstAddr = 0;
    }

    action set_mac(macAddr_t portMacAddr, macAddr_t dstMacAddr) {
        hdr.ethernet.srcAddr = portMacAddr;
        hdr.ethernet.dstAddr = dstMacAddr;
        hdr.ethernet.etherType = TYPR_DIS;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    // The table to store every port's mac of this switch. It is used to set the source mac the packet
    table port_mac {

        key = {
            standard_metadata.egress_port: exact;
        }

        actions = {
            set_mac;
            drop;
            NoAction;
        }

        const entries = {
            (1) : set_mac(0x000c29908cf6, 0x005079666802);
            (2) : set_mac(0x000c29908c00, 0x000c29faac42);
            (3) : set_mac(0x000c29908c0a, 0x000c29d5103d);	
        }

        default_action = drop();
    }
    apply {
          if(hdr.ipv4.protocol == TYPE_ICMP || hdr.ipv4.protocol == TYPE_TCP || hdr.ipv4.protocol == TYPE_UDP){
          if (hdr.ipv4.srcAddr != 0x00000000 && standard_metadata.instance_type == PKT_INSTANCE_TYPE_NORMAL) {
              // normal packet to port 2
              log_msg("packet only contains ipv4 header, egress port = {}", {standard_metadata.egress_port});
              // remove other packet header
              reserve_ipv4_header(meta.groupId);
              port_mac.apply();
          }else if (hdr.ipv4.srcAddr != 0x00000000 && standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE){
              // ingress cloned packet to port 3
              log_msg("packet only contains transport header, egress port = {}", {standard_metadata.egress_port});
              //clone(CloneType.E2E, SEP_RE);
              reserve_transport_header(meta.groupId);
              port_mac.apply();
          }else if (hdr.ipv4.srcAddr != 0x00000000 && standard_metadata.instance_type == PKT_INSTANCE_TYPE_EGRESS_CLONE){

          }
          }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {   }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.dis);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
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
