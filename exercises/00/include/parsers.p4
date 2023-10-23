/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        // setup for meta of CM sketch
        meta.index_cm0 = 0;
        meta.index_cm1 = 0;
        meta.index_cm2 = 0;
        meta.cnt_cm0 = 0;
        meta.cnt_cm1 = 0;
        meta.cnt_cm2 = 0;
        meta.min_cnt_cm = 0;

        // setup for meta of H-Table
        meta.index = 0;
        meta.key_idx0 = 0;
        meta.key_idx1 = 0;
        meta.key_idx2 = 0;
        meta.index_ht0 = 0;
        meta.index_ht1 = 0;
        meta.index_ht2 = 0;
        meta.cnt_ht0 = 0;
        meta.cnt_ht1 = 0;
        meta.cnt_ht2 = 0;
        meta.id_ht0 = 0;
        meta.id_ht1 = 0;
        meta.id_ht2 = 0;
        meta.id = 0;

        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        // transition accept;
        // TO DO
        transition parse_estimate;
    }

    // state parse_estimate {
    //    packet.extract(hdr.est_cm);
    //    transition parse_flowID;
    // }

    // state parse_flowID {
    //     // packet.extract(hdr.id);
    //     hdr.id.key_id = 0;
    //     hdr.id.matched = 0;
    //     hdr.id.min_cnt_ht = 0;
    //     hdr.id.min_index_ht = 0;
    //     hdr.id.min_stage = 0;
    //     transition accept;
    // }

    state parse_estimate {
        packet.extract(hdr.est_cm);
        transition select(hdr.est_cm.freq) {
            2 : parse_resubmit;
            0: parse_new;	
		}
    }

    state parse_new {
        hdr.id.key_id = 0;
        hdr.id.matched = 0;
        hdr.id.min_cnt_ht = 0;
        hdr.id.min_index_ht = 0;
        hdr.id.min_stage = 0;
        transition accept;
    }

    state parse_resubmit {
        packet.extract(hdr.id);
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

        //parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);

        //Only emited if valid
        packet.emit(hdr.tcp);
    }
}