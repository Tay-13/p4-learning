/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS */
const bit<32> SKETCH_BUCKET_LENGTH = 10;
const bit<32> TABLE_CELL_LENGTH = 50;

#define ID_CELL_SIZE 10w32

#define EMPTY_CELL 32w0


#define SKETCH_HASH_MAX 10w9  // define the max hash value, set to the SKETCH_BUCKET_LENGTH
#define TABLE_HASH_MAX 10w49
#define HASH_BASE 10w0






/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<8>>(1) flag_reg1;
    action write_flag_reg1() {
        flag_reg1.write(0, hdr.est_cm.freq);
    }

    register<bit<8>>(1) flag_reg2;
    action write_flag_reg2() {
        flag_reg2.write(0, hdr.est_cm.freq);
    }

    register<bit<32>>(2) count_pkt;
    action write_count_pkt() {
        bit<32> tmp;
        count_pkt.read(tmp, 0);
        tmp = tmp + 1;
        count_pkt.write(0, tmp);
    }

    action write_count_pkt1() {
        bit<32> tmp;
        count_pkt.read(tmp, 1);
        tmp = tmp + 1;
        count_pkt.write(1, tmp);
    }



    
    action drop() {
        mark_to_drop(standard_metadata);
    }
    action set_egress_port(bit<9> egress_port){
        standard_metadata.egress_spec = egress_port;
    }

    table forwarding {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_egress_port;
            drop;
            NoAction;
        }
        size = 64;
        default_action = drop;
    }


    apply {
        if (hdr.ipv4.isValid()){
            if (hdr.tcp.isValid()){
                if(hdr.est_cm.isValid()){
                    write_flag_reg1();
                    write_count_pkt();
                    hdr.est_cm.freq = 2;
                    meta.resubmit_meta.resubmit_f = 1;
                    // resubmit<resub_meta_t>(0);
                }
                // else{
                //    write_count_pkt1();
                //    write_flag_reg2();
                // }
                
            }   
            forwarding.apply();
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
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;