/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS */
const bit<32> SKETCH_BUCKET_LENGTH = 1024;
const bit<32> TABLE_CELL_LENGTH = 2048;



#define SKETCH_HASH_MAX 10w1023  // define the max hash value, set to the SKETCH_BUCKET_LENGTH
#define TABLE_HASH_MAX 12w2047
#define HASH_BASE 10w0



/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    

    action find_min(inout bit<32> mincnt, in bit<32> cnt1, in bit<32> cnt2,
                    in bit<32> cnt3) {
        if(cnt1 < cnt2) {
            mincnt = cnt1;
        } else {
            mincnt = cnt2;
        }

        if(mincnt > cnt3) {
            mincnt = cnt3;
        }
    }

    // *******  CM sketch ******************* //
    register<bit<32>>(SKETCH_BUCKET_LENGTH) cms_r0;
    action Insert_CM0() {
        hash(meta.index_cm0, HashAlgorithm.crc16, HASH_BASE,
                {hdr.ipv4.srcAddr}, SKETCH_HASH_MAX);
        cms_r0.read(meta.cnt_cm0, meta.index_cm0);
        meta.cnt_cm0 = meta.cnt_cm0 + 1;
        cms_r0.write(meta.index_cm0, meta.cnt_cm0);
    }
    action Query_CM0() {
        cms_r0.read(meta.cnt_cm0, meta.index_cm0);
    }

    register<bit<32>>(SKETCH_BUCKET_LENGTH) cms_r1;
    action Insert_CM1() {
        hash(meta.index_cm1, HashAlgorithm.crc32, HASH_BASE,
                {hdr.ipv4.srcAddr}, SKETCH_HASH_MAX);
        cms_r1.read(meta.cnt_cm1, meta.index_cm1);
        meta.cnt_cm1 = meta.cnt_cm1 + 1;
        cms_r1.write(meta.index_cm1, meta.cnt_cm1);
    }
    action Query_CM1() {
        cms_r1.read(meta.cnt_cm1, meta.index_cm1);
    }

    register<bit<32>>(SKETCH_BUCKET_LENGTH) cms_r2;
    action Insert_CM2() {
        hash(meta.index_cm2, HashAlgorithm.crc16_custom, HASH_BASE,
                {hdr.ipv4.srcAddr}, SKETCH_HASH_MAX);
        cms_r2.read(meta.cnt_cm2, meta.index_cm2);
        meta.cnt_cm2 = meta.cnt_cm2 + 1;
        cms_r2.write(meta.index_cm2, meta.cnt_cm2);
    }
    action Query_CM2() {
        cms_r2.read(meta.cnt_cm2, meta.index_cm2);
    }



    // *******  H-Table ******************* //
    
    
    action choose_stage() {
        
        hash(meta.index, HashAlgorithm.crc16, 2w0, 
            {hdr.ipv4.dstAddr}, 2w3);
        if(meta.index == 2w0){
            meta.key_idx0 = 1;
        }
        if(meta.index == 2w1){
            meta.key_idx1 = 1;
        }
        if(meta.index == 2w2){
            meta.key_idx2 = 1;
        }
    }
    
    register<bit<64>>(TABLE_CELL_LENGTH) ht_ID0;
    register<bit<32>>(TABLE_CELL_LENGTH) ht_counter0;
    action read_ID_Table0() {
        hash(meta.index_ht0, HashAlgorithm.crc16, HASH_BASE, 
            {hdr.ipv4.srcAddr}, TABLE_HASH_MAX);
        bit<64> curID = 0;
        curID[31:0] = hdr.ipv4.srcAddr;
        curID[63:32] = hdr.ipv4.dstAddr;
        ht_ID0.read(meta.id_ht0, meta.index_ht0);
        // matched cell
        if(meta.id_ht0 == curID){
            meta.matched = 1;
        }
        // empty cell
        if(meta.id_ht0 == 64w0){
            meta.matched = 2;
        }
    }
    action write_ID_Table0() {
        bit<64> curID = 0;
        curID[31:0] = hdr.ipv4.srcAddr;
        curID[63:32] = hdr.ipv4.dstAddr;
        ht_ID0.write(meta.index_ht0, curID);
    }
    action write_counter_Table0() {
        ht_counter0.read(meta.cnt_ht0, meta.index_ht0);
        meta.cnt_ht0 = meta.cnt_ht0 + 1;
        ht_counter0.write(meta.index_ht0, meta.cnt_ht0);
    }


    register<bit<64>>(TABLE_CELL_LENGTH) ht_ID1;
    register<bit<32>>(TABLE_CELL_LENGTH) ht_counter1;
    action read_ID_Table1() {
        hash(meta.index_ht1, HashAlgorithm.crc32, HASH_BASE, 
            {hdr.ipv4.srcAddr}, TABLE_HASH_MAX);
        bit<64> curID = 0;
        curID[31:0] = hdr.ipv4.srcAddr;
        curID[63:32] = hdr.ipv4.dstAddr;
        ht_ID1.read(meta.id_ht1, meta.index_ht1);
        if(meta.id_ht1 == curID){
            meta.matched = 1;
        }
        if(meta.id_ht1 == 64w0){
            meta.matched = 2;
        }
    }
    action write_ID_Table1() {
        bit<64> curID = 0;
        curID[31:0] = hdr.ipv4.srcAddr;
        curID[63:32] = hdr.ipv4.dstAddr;
        ht_ID1.write(meta.index_ht1, curID);
    }
    action write_counter_Table1() {
        ht_counter1.read(meta.cnt_ht1, meta.index_ht1);
        meta.cnt_ht1 = meta.cnt_ht1 + 1;
        ht_counter1.write(meta.index_ht1, meta.cnt_ht1);
    }


    register<bit<64>>(TABLE_CELL_LENGTH) ht_ID2;
    register<bit<32>>(TABLE_CELL_LENGTH) ht_counter2;
    action read_ID_Table2() {
        hash(meta.index_ht2, HashAlgorithm.crc32_custom, HASH_BASE, 
            {hdr.ipv4.srcAddr}, TABLE_HASH_MAX);
        bit<64> curID = 0;
        curID[31:0] = hdr.ipv4.srcAddr;
        curID[63:32] = hdr.ipv4.dstAddr;
        ht_ID2.read(meta.id_ht2, meta.index_ht2);
        if(meta.id_ht2 == curID){
            meta.matched = 1;
        }
        if(meta.id_ht2 == 64w0){
            meta.matched = 2;
        }
    }
    action write_ID_Table2() {
        bit<64> curID = 0;
        curID[31:0] = hdr.ipv4.srcAddr;
        curID[63:32] = hdr.ipv4.dstAddr;
        ht_ID2.write(meta.index_ht2, curID);
    }
    action write_counter_Table2() {
        ht_counter2.read(meta.cnt_ht2, meta.index_ht2);
        meta.cnt_ht2 = meta.cnt_ht2 + 1;
        ht_counter2.write(meta.index_ht2, meta.cnt_ht2);
    }


    action drop() {
        mark_to_drop(standard_metadata);
    }
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {

        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;

       //set the destination mac address that we got from the match in the table
        hdr.ethernet.dstAddr = dstAddr;

        //set the output port that we also get from the table
        standard_metadata.egress_spec = port;

        //decrease ttl by 1
        hdr.ipv4.ttl = hdr.ipv4.ttl -1;

    }
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()){
            if (hdr.tcp.isValid()){
                Insert_CM0();
                Insert_CM1();
                Insert_CM2();

                find_min(hdr.est_cm.freq, meta.cnt_cm0, meta.cnt_cm1, meta.cnt_cm2);

                // TO DO 
                // INSERT H-Table
                choose_stage();
                if(meta.key_idx0 == 1) {
                    read_ID_Table0();
                    if(meta.matched == 2){
                        write_ID_Table0();
                    }
                    write_counter_Table0();
                }
                if(meta.key_idx1 == 1) {
                    read_ID_Table1();
                    if(meta.matched == 2){
                        write_ID_Table1();
                    }
                    write_counter_Table1();
                }
                if(meta.key_idx2 == 1) {
                    read_ID_Table2();
                    if(meta.matched == 2){
                        write_ID_Table2();
                    }
                    write_counter_Table2();
                }
            }

            // TO DO
            // RESUBMIT

            ipv4_lpm.apply();
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