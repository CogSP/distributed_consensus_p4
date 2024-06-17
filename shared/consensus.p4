/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<8>  UDP_PROTOCOL = 0x11;
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV6 = 0x700;
const bit<16> TYPE_CONSENSUS = 0x600;
const bit<8> PROTOCOL_UDP = 0x12;
const bit<8> PROTOCOL_TCP = 0x11;

#define MAX_HOPS 9

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<128> ip6Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}


header consensus_t {
    bit<16> proto_id;
    bit<8>  allow_count;
    bit<8>  drop_count;
    bit<8>  abstain_count;
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


header ipv6_t { 
    /*TODO: check if these header fields are ok */
    bit<4>    version;
    bit<8>    traffic_class;
    bit<20>   flow_label;
    bit<16>   payload_length;
    bit<8>    next_header;
    bit<8>    hop_limit;
    ip6Addr_t  srcAddr;
    ip6Addr_t  dstAddr;
}


header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  reserved;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}


struct ingress_metadata_t {
    bit<16>  count;
}

struct parser_metadata_t {
    bit<16>  remaining;
}

struct egress_metadata_t {
    bool is_egress_node;
}

struct metadata {
    ingress_metadata_t   ingress_metadata;
    parser_metadata_t   parser_metadata;
    egress_metadata_t egress_metadata;
}

struct headers {
    ethernet_t  ethernet;
    consensus_t	consensus;
    ipv4_t      ipv4;
    ipv6_t		ipv6;
    udp_t       udp;
    tcp_t       tcp;
}

error { IPHeaderTooShort }

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
            TYPE_CONSENSUS: parse_consensus;
            TYPE_IPV4: parse_ipv4;
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTOCOL_UDP: parse_udp;
            PROTOCOL_TCP: parse_tcp;
            default: accept;
        }
    }
    
    state parse_ipv6 {
    	packet.extract(hdr.ipv6);
    	transition select(hdr.ipv6.next_header) {
    	    PROTOCOL_UDP: parse_udp;
    	    PROTOCOL_TCP: parse_tcp;
    	    default: accept;
    	}
    }
    
    state parse_consensus {
    	packet.extract(hdr.consensus);
    	transition select(hdr.consensus.proto_id) {
       	    TYPE_IPV4: parse_ipv4;
	        TYPE_IPV6: parse_ipv6;
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
    
    action ethernet_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action ipv4_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    action ipv6_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
    }
    
    action udp_forward(egressSpec_t port) {
    	standard_metadata.egress_spec = port;
    }
    
    action tcp_forward(egressSpec_t port) {
    	standard_metadata.egress_spec = port;
    }
    
    action vote_allow() {
        hdr.consensus.allow_count = hdr.consensus.allow_count + 1;
    }

    action vote_drop() {
        hdr.consensus.drop_count = hdr.consensus.drop_count + 1;
    }
    
    action vote_abstain() {
        hdr.consensus.abstain_count = hdr.consensus.abstain_count + 1;
    }
    
    action set_counters_to_zero() {
        hdr.consensus.allow_count = 0;
        hdr.consensus.drop_count = 0;
        hdr.consensus.abstain_count = 0;
    }
    
    
    table ethernet_table {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            ethernet_forward;
            NoAction;
        }
    }
        
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    table ipv6_lpm {
        key = {
            hdr.ipv6.dstAddr: lpm;
        }
        actions = {
            ipv6_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table udp_table {
        key = {
            hdr.udp.dstPort: exact;
        }
        actions = {
            udp_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table tcp_table {
        key = {
            hdr.tcp.dstPort: exact;
        }
        actions = {
            tcp_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    table is_ingress_table {
        key = {
            // matcha sugli indirizzi: 
            // è un ingress se il source è un l'host
            // direttamente attaccato allo switch
            hdr.ethernet.srcAddr: exact;
        }
        actions = {
            set_counters_to_zero;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    table l2_voting {
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        actions = {
            vote_allow;
            vote_drop;
            vote_abstain;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    table l3_ipv4_voting {
        key = {
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            vote_allow;
            vote_drop;
            vote_abstain;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    table l3_ipv6_voting {
        key = {
            hdr.ipv6.srcAddr: lpm;
        }
        actions = {
            vote_allow;
            vote_drop;
            vote_abstain;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    table l4_udp_voting {
        key = {
            hdr.udp.srcPort: exact;
        }
        actions = {
            vote_allow;
            vote_drop;
            vote_abstain;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    table l4_tcp_voting {
        key = {
            hdr.tcp.srcPort: exact;
        }
        actions = {
            vote_allow;
            vote_drop;
            vote_abstain;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
   
    apply {
        if(hdr.ethernet.isValid()) {
            is_ingress_table.apply();
            ethernet_table.apply();
            l2_voting.apply();
            if (hdr.ipv4.isValid()) {
                ipv4_lpm.apply();
                l3_ipv4_voting.apply();
                if (hdr.udp.isValid()) {
                    udp_table.apply();
                    l4_udp_voting.apply();
                } else if (hdr.tcp.isValid()) {
                    tcp_table.apply();
                    l4_tcp_voting.apply();
                }
            } else if (hdr.ipv6.isValid()) {
                ipv6_lpm.apply();
                l3_ipv6_voting.apply();
                if (hdr.udp.isValid()) {
                    udp_table.apply();
                    l4_udp_voting.apply();
                } else if (hdr.tcp.isValid()) {
                    tcp_table.apply();
                    l4_tcp_voting.apply();
                }
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
                 
    action mark_as_egress() {
        meta.egress_metadata.is_egress_node = true;
    }
	
	
    table is_egress_table {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            mark_as_egress;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
	apply {  
	    if (hdr.ethernet.isValid()) {
		    is_egress_table.apply();
		    if (hdr.consensus.allow_count <= hdr.consensus.drop_count + hdr.consensus.abstain_count && meta.egress_metadata.is_egress_node) {
		        mark_to_drop(standard_metadata);
		    }
		}
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
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
        packet.emit(hdr.consensus);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
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

