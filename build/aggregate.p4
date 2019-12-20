/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#define MAX_CACHED_PACKETS 16384
#define EGRESS_PORT 3
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_DIS  = 0x9999;
const bit<8>  TYPE_TCP = 0x06;
const bit<8>  TYPE_UDP = 0x11;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16>  port_t;

const bit<8> DIS_IPV4 = 3;
const bit<8> DIS_TCP = 4;
const bit<8> DIS_UDP = 5;
const bit<8> DIS_APP = 6;

// 112bit
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

// 144bit
header distribute_t {
    bit<32>  group;
    bit<8>   type;
    bit<8>   segNum;
    bit<64>  ruleIds; // max number of rules is 64
}

// 160bit
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

// 160bit
header tcp_t {
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

// 64bit
header udp_t {
    port_t srcPort;
    port_t dstPort;
    bit<16> dataLen;
    bit<16> checksum;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t        ethernet;
    distribute_t      dis;
    ipv4_t            ipv4;
    udp_t             udp;
    tcp_t             tcp;
}

struct cached_header {
    ipv4_t            ipv4;//160
    udp_t             udp;//64
    tcp_t             tcp;//160
    bit<64>           ruleid;//64
    bit<8>            segremain;//8
    bit<1>            is_using;//1
} // 457 bit

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
            TYPE_DIS: parse_dis;
            default: reject;
        }
    }

    state parse_dis {
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

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // need a register to save the incomplete packets
    register<bit<457>>(MAX_CACHED_PACKETS) cachedPacketHeaders;

    action set_cache_ipv4(inout bit<457> tmp) {
        bit<160> ipv4_header = 0;
        ipv4_header = ipv4_header | (((bit<160>)hdr.ipv4.version) << 156);
        ipv4_header = ipv4_header | (((bit<160>)hdr.ipv4.ihl) << 152);
        ipv4_header = ipv4_header | (((bit<160>)hdr.ipv4.diffserv) << 144);
        ipv4_header = ipv4_header | (((bit<160>)hdr.ipv4.totalLen) << 128);
        ipv4_header = ipv4_header | (((bit<160>)hdr.ipv4.identification) << 112);
        ipv4_header = ipv4_header | (((bit<160>)hdr.ipv4.flags) << 109);
        ipv4_header = ipv4_header | (((bit<160>)hdr.ipv4.fragOffset) << 96);
        ipv4_header = ipv4_header | (((bit<160>)hdr.ipv4.ttl) << 88);
        ipv4_header = ipv4_header | (((bit<160>)hdr.ipv4.protocol) << 80);
        ipv4_header = ipv4_header | (((bit<160>)hdr.ipv4.hdrChecksum) << 64);
        ipv4_header = ipv4_header | (((bit<160>)hdr.ipv4.srcAddr) << 32);
        ipv4_header = ipv4_header | (bit<160>)hdr.ipv4.dstAddr;
        log_msg("ip src = {} ip dst = {}", {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr});
        bit<457> ipv4_header_tmp = ((bit<457>)ipv4_header) << 256;
        tmp = tmp | (ipv4_header_tmp << 41);

    }

    action get_cache_ipv4(in bit<457> tmp) {
        bit<160> ipv4_header;
        bit<457> tmp2;
        tmp2 = tmp & 372141426839350727961253789638658321589064376671652217367081171219703759803008564472878384416238703535780893506238985439499298945577779200; // get first 160bit

        tmp2 = tmp2 >> 256;
        tmp2 = tmp2 >> 41;
        ipv4_header = (bit<160>) tmp2;

        bit<160> version = ipv4_header & 1370157784997721485815954530671515330927436759040;
        bit<160> ihl = ipv4_header & 85634861562357592863497158166969708182964797440;
        bit<160> diffserv = ipv4_header & 5686690025625308901091608159525332184025006080;
        bit<160> totalLen = ipv4_header & 22300404916163702203072254898040929737768960;
        bit<160> identification = ipv4_header & 340277174624079928635746076935438991360;
        bit<160> flags = ipv4_header & 4543259751217974174964184288067584;
        bit<160> fragOffset = ipv4_header & 648957879154339189228718497202176;
        bit<160> ttl = ipv4_header & 78918677504442992524819169280;
        bit<160> protocol = ipv4_header & 308276084001730439550074880;
        bit<160> hdrChecksum = ipv4_header & 1208907372870555465154560;
        bit<160> srcAddr = ipv4_header & 18446744069414584320;
        bit<160> dstAddr = ipv4_header & 4294967295;

        hdr.ipv4.version = (bit<4>)(version >> 156);
        hdr.ipv4.ihl = (bit<4>)(ihl >> 152);
        hdr.ipv4.diffserv = (bit<8>)(diffserv >> 144);
        hdr.ipv4.totalLen = (bit<16>)(totalLen >> 128);
        hdr.ipv4.identification = (bit<16>)(identification >> 112);
        hdr.ipv4.flags = (bit<3>)(flags >> 109);
        hdr.ipv4.fragOffset = (bit<13>)(fragOffset >> 96);
        hdr.ipv4.ttl = (bit<8>)(ttl >> 88);
        hdr.ipv4.protocol = (bit<8>)(protocol >> 80);
        hdr.ipv4.hdrChecksum = (bit<16>)(hdrChecksum >> 64);
        hdr.ipv4.srcAddr = (bit<32>)(srcAddr >> 32);
        hdr.ipv4.dstAddr = (bit<32>)dstAddr;
    }

    action set_cache_tcp(inout bit<457> tmp) {

        bit<160> tcp = 0;
        tcp = tcp | (((bit<160>)hdr.tcp.srcPort) << 144);
        tcp = tcp | (((bit<160>)hdr.tcp.dstPort) << 128);
        tcp = tcp | (((bit<160>)hdr.tcp.seqNo) << 96);
        tcp = tcp | (((bit<160>)hdr.tcp.ackNo) << 64);
        tcp = tcp | (((bit<160>)hdr.tcp.dataOffset) << 60);
        tcp = tcp | (((bit<160>)hdr.tcp.res) << 56);
        tcp = tcp | (((bit<160>)hdr.tcp.cwr) << 55);
        tcp = tcp | (((bit<160>)hdr.tcp.ece) << 54);
        tcp = tcp | (((bit<160>)hdr.tcp.urg) << 53);
        tcp = tcp | (((bit<160>)hdr.tcp.ack) << 52);
        tcp = tcp | (((bit<160>)hdr.tcp.psh) << 51);
        tcp = tcp | (((bit<160>)hdr.tcp.rst) << 50);
        tcp = tcp | (((bit<160>)hdr.tcp.syn) << 49);
        tcp = tcp | (((bit<160>)hdr.tcp.fin) << 48);
        tcp = tcp | (((bit<160>)hdr.tcp.window) << 32);
        tcp = tcp | (((bit<160>)hdr.tcp.checksum) << 16);
        tcp = tcp | (bit<160>)hdr.tcp.urgentPtr;

        tmp = tmp | ((bit<457>)tcp) << 73;
    }

    action get_cache_tcp(in bit<457> tmp) {
        bit<160> tcp;
        bit<457> tmp2;
        tmp2 = tmp & 13803492693581127574869511724554050904902217944331328377359309157171200; // get tcp 160bit
        tmp2 = tmp2 >> 73;
        tcp = (bit<160>) tmp2;

        bit<160> srcPort = tcp & 1461479336585704387580543296998010371294426562560;
        bit<160> dstPort = tcp & 22300404916163702203072254898040929737768960;
        bit<160> seqNo = tcp & 340282366841710300949110269838224261120;
        bit<160> ackNo = tcp & 79228162495817593519834398720;
        bit<160> dataOffset = tcp & 17293822569102704640;
        bit<160> res = tcp & 1080863910568919040;
        bit<160> cwr = tcp & 36028797018963968;
        bit<160> ece = tcp & 18014398509481984;
        bit<160> urg = tcp & 9007199254740992;
        bit<160> ack = tcp & 4503599627370496;
        bit<160> psh = tcp & 2251799813685248;
        bit<160> rst = tcp & 1125899906842624;
        bit<160> syn = tcp & 562949953421312;
        bit<160> fin = tcp & 281474976710656;
        bit<160> window = tcp & 281470681743360;
        bit<160> checksum = tcp & 4294901760;
        bit<160> urgentPtr = tcp & 65535;


        hdr.tcp.srcPort = (bit<16>)(srcPort >> 144);
        hdr.tcp.dstPort = (bit<16>)(dstPort >> 128);
        hdr.tcp.seqNo = (bit<32>)(seqNo >> 96);
        hdr.tcp.ackNo = (bit<32>)(ackNo >> 64);
        hdr.tcp.dataOffset = (bit<4>)(dataOffset >> 60);
        hdr.tcp.res = (bit<4>)(res >> 56);
        hdr.tcp.cwr = (bit<1>)(cwr >> 55);
        hdr.tcp.ece = (bit<1>)(ece >> 54);
        hdr.tcp.urg = (bit<1>)(urg >> 53);
        hdr.tcp.ack = (bit<1>)(ack >> 52);
        hdr.tcp.psh = (bit<1>)(psh >> 51);
        hdr.tcp.rst = (bit<1>)(rst >> 50);
        hdr.tcp.syn = (bit<1>)(syn >> 49);
        hdr.tcp.fin = (bit<1>)(fin >> 48);
        hdr.tcp.window = (bit<16>)(window >> 32);
        hdr.tcp.checksum = (bit<16>)(checksum >> 16);
        hdr.tcp.urgentPtr = (bit<16>)urgentPtr;
    }

    action set_cache_udp(inout bit<457> tmp) {

        bit<64> udp = 0;
        udp = udp | (((bit<64>)hdr.udp.srcPort) << 48);
        udp = udp | (((bit<64>)hdr.udp.dstPort) << 32);
        udp = udp | (((bit<64>)hdr.udp.dataLen) << 16);
        udp = udp | (bit<64>)hdr.udp.checksum;
        
        tmp = tmp | ((bit<457>)udp) << 233;
    }

    action get_cache_udp(in bit<457> tmp) {
        bit<64> udp;
        bit<457> tmp2;
        tmp2 = tmp & 254629497041810760769752218357591142556564037483687980424615338224956889360092039825326080; // get udp 64bit
        tmp2 = tmp2 >> 233;
        udp = (bit<64>) tmp2;

        bit<64> srcPort = udp & 18446462598732840960;
        bit<64> dstPort = udp & 281470681743360;
        bit<64> dataLen = udp & 4294901760;
        bit<64> checksum = udp & 65535;

        hdr.udp.srcPort = (bit<16>)(srcPort >> 48);
        hdr.udp.dstPort = (bit<16>)(dstPort >> 32);
        hdr.udp.dataLen = (bit<16>)(dataLen >> 16);
        hdr.udp.checksum = (bit<16>)checksum;
    }

    action set_cache_ruleid(inout bit<457> tmp, bit<64> ruleid){
        // remove the origin value
        tmp = tmp & 372141426839350727961253789638658321589064376671906846864122981980487315514059736743009817965446945567110411062408273657236750294560276991;
        tmp = tmp | ((bit<457>)ruleid) << 9;
    }

    action get_cache_ruleid(in bit<457> tmp, inout bit<64> ruleid){
        bit<457> tmp2;
        tmp2 = tmp & 9444732965739290426880;
        tmp2 = tmp2 >> 9;
        ruleid = (bit<64>)tmp2;
    }

    action set_cache_segremain(inout bit<457> tmp, bit<8> segremain){
        // remove the origin value
        tmp = tmp & 372141426839350727961253789638658321589064376671906846864122981980487315514059736743009817965446945567110411062408283101969716033850703361;
        tmp = tmp | ((bit<457>)segremain) << 1;
    }

    action get_cache_segremain(in bit<457> tmp, inout bit<8> segremain){
        
        segremain = (bit<8>) ((tmp & 510) >> 1);
    }

    action set_cache_is_using(inout bit<457> tmp, bit<1> is_using){
        // remove the origin value
        tmp = tmp & 372141426839350727961253789638658321589064376671906846864122981980487315514059736743009817965446945567110411062408283101969716033850703870;
        tmp = tmp | (bit<457>)is_using;
    }

    action get_cache_is_using(in bit<457> tmp, inout bit<1> is_using){
        is_using = (bit<1>) (tmp & 1);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action set_mac(macAddr_t portMacAddr, macAddr_t dstMacAddr) {
        hdr.ethernet.srcAddr = portMacAddr;
        hdr.ethernet.dstAddr = dstMacAddr;
    }

    // this table is used to forward ipv4 packet
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            NoAction;
        }
        size = 1024;
    }

    // The table to store every port's mac of this switch. It is used to set the source mac the packet
    table port_mac {

        key = {
            standard_metadata.egress_spec: exact;
        }

        actions = {
            set_mac;
            NoAction;
        }

        size = 1024;

    }

    action forward_packet(bit<32> index) {
        standard_metadata.egress_spec = EGRESS_PORT;
        hdr.ethernet.etherType = TYPE_IPV4;
        hdr.dis.setInvalid();
        cachedPacketHeaders.write(index, 0);
    }

    apply {

        // get the index to cache
        bit<32> index = hdr.dis.group % MAX_CACHED_PACKETS;
        bit<457> tmp;
        bit<1> is_using = 0;
        bit<8> segremain = 0;
    if(hdr.ethernet.etherType == TYPE_DIS){
        log_msg("the index of this packet = {}", {index});
        log_msg("packet's srcMac={},dstMac={},etherType={}",{hdr.ethernet.srcAddr,hdr.ethernet.dstAddr,hdr.ethernet.etherType});
    if(hdr.dis.segNum == 1) {
        forward_packet(index);
    } else {
        // if-else according to hdr.dis.type
        if (hdr.dis.type == DIS_IPV4) {
            log_msg("the type of this packet is ipv4");
            cachedPacketHeaders.read(tmp, index);
            get_cache_is_using(tmp, is_using);
            log_msg("is_using={}",{is_using});
            // is using
            if(is_using == 1) {
                get_cache_segremain(tmp, segremain);
                if(segremain - 1 <= 0) {
                    // headers are enough , it is time to aggregate the packet
                    if (hdr.ipv4.protocol == TYPE_TCP) {
                        hdr.tcp.setValid();
                        get_cache_tcp(tmp);
                    } else if (hdr.ipv4.protocol == TYPE_UDP) {
                        hdr.udp.setValid();
                        log_msg("used,tmp = {}",{tmp});
                        get_cache_udp(tmp);
                    }
                    forward_packet(index);
                    
                } else {
                    // there are remain headers, cache current header;
                    set_cache_ipv4(tmp);
                    set_cache_segremain(tmp, segremain - 1);
                    cachedPacketHeaders.write(index, tmp);
                }
            } else {
                log_msg("not used,tmp = {}",{tmp});
                // not used, first header
                set_cache_ipv4(tmp);
                set_cache_segremain(tmp, hdr.dis.segNum-1);
                set_cache_is_using(tmp, 1);
                log_msg("ready to write,tmp = {}",{tmp});
                cachedPacketHeaders.write(index, tmp);
            }

        } else if (hdr.dis.type == DIS_TCP){
            log_msg("the type of this packet is tcp");
            cachedPacketHeaders.read(tmp, index);
            get_cache_is_using(tmp, is_using);
            log_msg("is_using={}",{is_using});
            // is using
            if(is_using == 1) {
                get_cache_segremain(tmp, segremain);
                if(segremain - 1 <= 0) {
                    // headers are enough , it is time to aggregate the packet
                    hdr.ipv4.setValid();
                    get_cache_ipv4(tmp);
                    forward_packet(index);
                } else {
                    // there are remain headers, cache current header;
                    set_cache_tcp(tmp);
                    set_cache_segremain(tmp, segremain - 1);
                    cachedPacketHeaders.write(index, tmp);
                }
            } else {
                // not used, first header
                set_cache_tcp(tmp);
                set_cache_segremain(tmp, hdr.dis.segNum-1);
                set_cache_is_using(tmp, 1);
                cachedPacketHeaders.write(index, tmp);
            }

        } else if (hdr.dis.type == DIS_UDP) {
            log_msg("the type of this packet is udp");
            cachedPacketHeaders.read(tmp, index);
            get_cache_is_using(tmp, is_using);
            log_msg("is_using={}",{is_using});
            // is using
            if(is_using == 1) {
                log_msg("used,tmp = {}",{tmp});
                get_cache_segremain(tmp, segremain);
                log_msg("segremain = {}", {segremain});
                if(segremain - 1 <= 0) {
                    // headers are enough , it is time to aggregate the packet
                    hdr.ipv4.setValid();
                    get_cache_ipv4(tmp);
                    forward_packet(index);
                } else {
                    // there are remain headers, cache current header;
                    set_cache_udp(tmp);
                    set_cache_segremain(tmp, segremain - 1);
                    cachedPacketHeaders.write(index, tmp);
                }
            } else {
                // not used, first header
                log_msg("not used,tmp = {}",{tmp});
                set_cache_udp(tmp);
                set_cache_segremain(tmp, hdr.dis.segNum-1);
                set_cache_is_using(tmp, 1);
                log_msg("ready to write,tmp = {}",{tmp});
                cachedPacketHeaders.write(index, tmp);
            }
        }
 }
    log_msg("end of the packet index={}", {index});
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
