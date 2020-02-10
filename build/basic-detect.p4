/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#define MAX_PORT_NUM 10
#define MAX_RECORD_NUM 10
#define MAX_SWITCH_NUM 16

// alert type
const bit<8> WRONG_DST = 0x01;
const bit<8> LOOP = 0x02;
const bit<8> BLACK_HOLE = 0x03;

// administrator's port
const bit<9>  ADMIN_PORT = 0x0;

// ethernet's type
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP  = 0x0806;
const bit<16> TYPE_TRACE = 0x9999;
const bit<16> TYPE_PROBE = 0x9998;
const bit<16> TYPE_ALERT = 0x9997;

// ip's type
const bit<8>  TYPE_TCP = 0x06;
const bit<8>  TYPE_UDP = 0x11;
const bit<8>  TYPE_ICMP= 0x01;

// arp type
const bit<16> ARP_REQ = 0x0001;
const bit<16> ARP_RES = 0x0002;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> port_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header recorder_t {
    bit<1> bos;
    bit<7> switch_id;
    bit<8> flow_id;
}

header record_t {
    bit<16>    next_header;
}

header alert_t {
    bit<8> type;
    bit<8> switch_id;
    bit<16> next_header;
}

header trace_elastic_t {
    bit<MAX_SWITCH_NUM>  elastic;
    bit<16>              next_header;
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

struct metadata {
    bit<8> switch_id_key;
    bit<7> switch_id;
    bit<8> flow_id;
    bit<32> next_index;
}

struct headers {
    ethernet_t                  ethernet;
    alert_t                     alert;
    recorder_t[MAX_RECORD_NUM]  records;
    record_t                    record;
    trace_elastic_t             elastic;
    arp_t                       arp;
    ipv4_t                      ipv4;
    udp_t                       udp;
    tcp_t                       tcp;
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
        meta.next_index = 0;
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP:  parse_arp;
            TYPE_TRACE: parse_trace;
            TYPE_PROBE: parse_probe;
            default: accept;
        }
    }

    state parse_probe {
        packet.extract(hdr.records.next);
        meta.next_index = meta.next_index + 1;
        transition select(hdr.records.last.bos) {
            1: parse_probe;
            default: parse_probe_next_header;
        }
    }

    state parse_probe_next_header {
        packet.extract(hdr.record);
        transition select(hdr.record.next_header) {
            TYPE_IPV4: parse_ipv4;
            TYPE_TRACE: parse_trace;
            default: accept;
        }
    }

    state parse_trace {
        packet.extract(hdr.elastic); // fill the elastic domain
        transition select(hdr.elastic.next_header) {
            TYPE_IPV4: parse_ipv4;
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
            TYPE_ICMP: parse_icmp;
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

    state parse_icmp {
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

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    register<bit<80>>(MAX_PORT_NUM) host_table;

    action add_new_record() {
        hdr.records[meta.next_index - 1].bos = 1;
        
        hdr.records[meta.next_index].setValid();
        hdr.records[meta.next_index].bos = 0;
        hdr.records[meta.next_index].switch_id = meta.switch_id;
        hdr.records[meta.next_index].flow_id = meta.flow_id;
    }

    action set_host_info(inout bit<80> host_info) {
        host_info = 0;
        host_info = host_info | (((bit<80>)hdr.arp.senderMacAddr) << 32);
        host_info = host_info | (bit<80>)hdr.arp.senderIpAddr;
    }

    action get_host_info(in bit<80> host_info, inout macAddr_t mac, inout ip4Addr_t ip) {
        bit<80> mac_tmp;
        bit<80> ip_tmp;
        mac_tmp = (host_info & 1208925819614624879738880) >> 32;
        ip_tmp = host_info & 4294967295;
        mac = (macAddr_t) mac_tmp;
        ip = (ip4Addr_t) ip_tmp;
    }

    action arp_response() {
        log_msg("arp_response");
        // update the host_table
        bit<80> host_info = 0;
        set_host_info(host_info);
        host_table.write((bit<32>)standard_metadata.ingress_port, host_info);
        
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
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port, bit<8> flow_id) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        meta.flow_id = flow_id;
        add_new_record();
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
        const entries = {
            (0x0a000002) : arp_response();
        }
        default_action = drop();
    }

    // this table is used to forward ipv4 packet
    table ipv4_exact {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;// if the host is directly connected with the switch host' ip/32 and the mac is the host'mac if the host isn't directly connected with the switch: network/mask and the mac is the next switch's port's mac
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }

        const entries = {
            (0x0a000001, 0x0a000101) : ipv4_forward(0x000c29bdb32e, 2, 0);
            (0x0a000101, 0x0a000001) : ipv4_forward(0x005079666801, 1, 1);
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

        const entries = {
            (0) : set_smac(0x000c29684c2a);
            (1) : set_smac(0x000c29684c34);
            (2) : set_smac(0x000c29684c3e);
        }

        default_action = drop();
        size = 1024;
    }

    action set_switch_id(bit<7> switch_id) {
        meta.switch_id = switch_id;
    }

    table switch_id_table {
        key = {
            meta.switch_id_key: exact;
        }
        
        actions = {
            set_switch_id;
            NoAction;
        }
        default_action = NoAction;
        const entries = {
            (0) : set_switch_id(1);
        }

        size = 2;
    }
    
    action send_alert(in bit<8> alert_type) {
        // send the packet to administrator
        standard_metadata.egress_spec = ADMIN_PORT;
        // add new packet header
        hdr.alert.setValid();
        hdr.alert.type = alert_type;
        hdr.alert.switch_id = (bit<8>)meta.switch_id;
        hdr.alert.next_header = hdr.ethernet.etherType;
        hdr.ethernet.etherType = TYPE_ALERT;
        add_new_record();
        hdr.records.pop_front(1);
    }

    action add_trace_header(in bit<MAX_SWITCH_NUM> trace_value) {
        hdr.elastic.setValid();
        hdr.elastic.elastic = hdr.elastic.elastic | trace_value;
        hdr.elastic.next_header = TYPE_IPV4;
        
        // set last header's next protocal
        if(hdr.ethernet.etherType == TYPE_PROBE) {
            hdr.record.next_header = TYPE_TRACE;
        } else {
            hdr.ethernet.etherType = TYPE_TRACE;
        }      
    }
    
    apply {
        // mark route path
        meta.switch_id_key = 0;
        switch_id_table.apply(); // get switch id
        bit<MAX_SWITCH_NUM> trace_tmp = 1 << (meta.switch_id - 1);

        if (hdr.ethernet.etherType == TYPE_ARP) {
            if(hdr.arp.isValid()) {
                if(hdr.arp.opCode == ARP_REQ) {
                    arp_response_table.apply(); // check if is the switch's ip
                }
            }
        } else if (hdr.ethernet.etherType == TYPE_IPV4 || hdr.ethernet.etherType == TYPE_TRACE || hdr.ethernet.etherType == TYPE_PROBE) {
            // switch in the internal network
            if (ipv4_exact.apply().miss) {
                send_alert(BLACK_HOLE);
            } else {
                // check if next is the end
                bit<80> host_info_tmp = 0;
                host_table.read(host_info_tmp, (bit<32>)standard_metadata.egress_spec);
                log_msg("host_table.read(host_info_tmp, {})",{standard_metadata.egress_spec});
                macAddr_t mac = 0;
                ip4Addr_t ip = 0;
                get_host_info(host_info_tmp, mac, ip);

                if (mac == 0 && ip == 0) {
                    // not to the end
                    if(hdr.elastic.isValid()) {
                        // trace header valid
                        if (trace_tmp & hdr.elastic.elastic == 1) {
                            send_alert(LOOP);
                        } else {
                            hdr.elastic.elastic = hdr.elastic.elastic | trace_tmp;
                        }
                    } else {
                        // trace header not valid
                        add_trace_header(trace_tmp);
                    }
                } else {
                    // to the end
                    if (hdr.ethernet.dstAddr != mac || hdr.ipv4.dstAddr != ip) {
                        log_msg("wrong destination");
                        // wrong destination
                        send_alert(WRONG_DST);
                    } else {
                        log_msg("to the end");
                        if(hdr.elastic.isValid()) {
                            hdr.elastic.setInvalid();
                            hdr.ethernet.etherType = TYPE_IPV4;
                        }
                    }
                }

            }
        }
        port_mac.apply();

    } // apply
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
        packet.emit(hdr.alert);
        packet.emit(hdr.records);
        packet.emit(hdr.record);
        packet.emit(hdr.elastic);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
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
