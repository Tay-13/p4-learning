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

    register<bit<32>>(1) count_pkt;
    action write_count_pkt() {
        bit<32> tmp;
        count_pkt.read(tmp, 0);
        tmp = tmp + 1;
        count_pkt.write(0, tmp);
    }

    // *******  CM sketch ******************* //
    register<bit<32>>(SKETCH_BUCKET_LENGTH) cms_r0;
    action Insert_CM0() {
        hash(meta.index_cm0, HashAlgorithm.crc16, HASH_BASE,
                {hdr.tcp.srcPort}, SKETCH_HASH_MAX);
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
                {hdr.tcp.srcPort}, SKETCH_HASH_MAX);
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
                {hdr.tcp.srcPort}, SKETCH_HASH_MAX);
        cms_r2.read(meta.cnt_cm2, meta.index_cm2);
        meta.cnt_cm2 = meta.cnt_cm2 + 1;
        cms_r2.write(meta.index_cm2, meta.cnt_cm2);
    }
    action Query_CM2() {
        cms_r2.read(meta.cnt_cm2, meta.index_cm2);
    }



    // *******  H-Table ******************* //
    
    action find_min_ht(inout bit<32> mincnt, in bit<32> cnt0, in bit<32> cnt1,
                    in bit<32> cnt2) {
        if(cnt0 < cnt1) {
            mincnt = cnt0;
            hdr.id.min_stage = 0;
            hdr.id.min_index_ht = meta.index_ht0;
        } else {
            mincnt = cnt1;
            hdr.id.min_stage = 1;
            hdr.id.min_index_ht = meta.index_ht1;
        }

        if(mincnt > cnt2) {
            mincnt = cnt2;
            hdr.id.min_stage = 2;
            hdr.id.min_index_ht = meta.index_ht2;
        }
    }

    
    action choose_stage() {
        
        hash(meta.index, HashAlgorithm.crc16, 2w0, 
            {hdr.tcp.dstPort}, 2w3);
        if(meta.index == 2w0){
            meta.key_idx0 = 1;
        }
        else if(meta.index == 2w1){
            meta.key_idx1 = 1;
        }
        else{
            meta.key_idx2 = 1;
        }
    }

    register<bit<ID_CELL_SIZE>>(TABLE_CELL_LENGTH) ht_ID0;
    register<bit<ID_CELL_SIZE>>(TABLE_CELL_LENGTH) ht_ID1;
    register<bit<ID_CELL_SIZE>>(TABLE_CELL_LENGTH) ht_ID2;
    register<bit<32>>(TABLE_CELL_LENGTH) ht_counter0;
    register<bit<32>>(TABLE_CELL_LENGTH) ht_counter1;
    register<bit<32>>(TABLE_CELL_LENGTH) ht_counter2;


    action read_ID_Table0() {
        hash(meta.index_ht0, HashAlgorithm.crc16, HASH_BASE, 
            {hdr.tcp.srcPort}, TABLE_HASH_MAX);
        ht_ID0.read(meta.id_ht0, meta.index_ht0);
        // matched cell
        if(meta.id_ht0 == hdr.id.key_id){
            hdr.id.matched = 1;
        }
        // empty cell
        else if(meta.id_ht0 == EMPTY_CELL){
            hdr.id.matched = 2;
        }
        // ATTENTION!!!!!!!!!!!!! initial here
        // otherwise, matched will be initialized with a random number (not 0 probably)
        else{
            hdr.id.matched = 0;
        }
    }
    action write_ID_Table0() {
        ht_ID0.write(meta.index_ht0, hdr.id.key_id);
    }
    action read_counter_Table0() {
        ht_counter0.read(meta.cnt_ht0, meta.index_ht0);
    }
    action write_counter_Table0() {
        ht_counter0.read(meta.cnt_ht0, meta.index_ht0);
        meta.cnt_ht0 = meta.cnt_ht0 + 1;
        ht_counter0.write(meta.index_ht0, meta.cnt_ht0);
    }


    
    action read_ID_Table1() {
        hash(meta.index_ht1, HashAlgorithm.crc32, HASH_BASE, 
            {hdr.tcp.srcPort}, TABLE_HASH_MAX);
        ht_ID1.read(meta.id_ht1, meta.index_ht1);
        if(meta.id_ht1 == hdr.id.key_id){
            hdr.id.matched = 1;
        }
        else if(meta.id_ht1 == EMPTY_CELL){
            hdr.id.matched = 2;
        }
        else{
            hdr.id.matched = 0;
        }
    }
    action write_ID_Table1() {
        ht_ID1.write(meta.index_ht1, hdr.id.key_id);
    }
    action read_counter_Table1() {
        ht_counter1.read(meta.cnt_ht1, meta.index_ht1);
    }
    action write_counter_Table1() {
        ht_counter1.read(meta.cnt_ht1, meta.index_ht1);
        meta.cnt_ht1 = meta.cnt_ht1 + 1;
        ht_counter1.write(meta.index_ht1, meta.cnt_ht1);
    }


    
    action read_ID_Table2() {
        hash(meta.index_ht2, HashAlgorithm.crc32_custom, HASH_BASE, 
            {hdr.tcp.srcPort}, TABLE_HASH_MAX);
        ht_ID2.read(meta.id_ht2, meta.index_ht2);
        if(meta.id_ht2 == hdr.id.key_id){
            hdr.id.matched = 1;
        }
        if(meta.id_ht2 == EMPTY_CELL){
            hdr.id.matched = 2;
        }
        else{
            hdr.id.matched = 0;
        }
    }
    action write_ID_Table2() {
        ht_ID2.write(meta.index_ht2, hdr.id.key_id);
    }
    action read_counter_Table2() {
        ht_counter2.read(meta.cnt_ht2, meta.index_ht2);
    }
    action write_counter_Table2() {
        ht_counter2.read(meta.cnt_ht2, meta.index_ht2);
        meta.cnt_ht2 = meta.cnt_ht2 + 1;
        ht_counter2.write(meta.index_ht2, meta.cnt_ht2);
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
                // if(meta.resubmit_meta.resubmit_f != 1) {
                if(hdr.est_cm.freq != 1) {
                    // write_count_pkt();
                    // ****************update cm sketch************//
                    Insert_CM0();
                    Insert_CM1();
                    Insert_CM2();
                    
                    // find_min(hdr.est_cm.freq, meta.cnt_cm0, meta.cnt_cm1, meta.cnt_cm2);

                    // ****************update h-table************//
                    bit<ID_CELL_SIZE> curID = 0;
                    curID[15:0] = hdr.tcp.srcPort;
                    curID[31:16] = hdr.tcp.dstPort;
                    hdr.id.key_id = curID;
                    choose_stage();
                    // ****************update id************//
                    if(meta.key_idx0 == 1) {
                        read_ID_Table0();
                        if(hdr.id.matched != 0) {
                            if(hdr.id.matched == 2){
                                write_ID_Table0();
                            }
                        }
                    }
                    else if(meta.key_idx1 == 1) {
                        read_ID_Table1();
                        if(hdr.id.matched != 0){
                            if(hdr.id.matched == 2){
                                write_ID_Table1();
                            }
                        }
                    }
                    else{
                        read_ID_Table2();
                        if(hdr.id.matched != 0){
                            if(hdr.id.matched == 2){
                                write_ID_Table2();
                            }
                        }
                    }

                    // ****************update counter************//
                    // read all counter tables to find min
                    read_counter_Table0();
                    if(meta.key_idx0 == 1) {
                        if(hdr.id.matched != 0) {
                            write_counter_Table0();
                        }
                    }
                    read_counter_Table1();
                    if(meta.key_idx1 == 1) {
                        if(hdr.id.matched != 0) {
                            write_counter_Table1();
                        }
                    }
                    read_counter_Table2();
                    if(meta.key_idx2 == 1) {
                        if(hdr.id.matched != 0) {
                            write_counter_Table2();
                        }
                    }
                    
                    // ****************find min cell************// 
                    if(meta.cnt_ht0 < meta.cnt_ht1) {
                        hdr.id.min_cnt_ht = meta.cnt_ht0;
                        hdr.id.min_stage = 0;
                        hdr.id.min_index_ht = meta.index_ht0;
                    } else {
                        hdr.id.min_cnt_ht = meta.cnt_ht1;
                        hdr.id.min_stage = 1;
                        hdr.id.min_index_ht = meta.index_ht1;
                    }

                    if(hdr.id.min_cnt_ht > meta.cnt_ht2) {
                        hdr.id.min_cnt_ht = meta.cnt_ht2;
                        hdr.id.min_stage = 2;
                        hdr.id.min_index_ht = meta.index_ht2;
                    }
                    // if not matched, mark resubmitted and resubmit
                    if(hdr.id.matched == 0) {
                        // TSET: if not matched, we drop the packet
                        // drop();
                        // return;
                        
                        // cannot restore the new resubmit_f when resubmitting
                        // so we set est_cm = 1 to indicate resubmitting
                        // in this way, this value stored in hdr can be maintained when resubmitting
                        hdr.est_cm.freq = 1;
                        meta.resubmit_meta.resubmit_f = 1;
                        resubmit<resub_meta_t>({meta.resubmit_meta.resubmit_f});
                    }
                }
                else{ 
                    // RESUBMIT
                    // TSET
                    // drop();
                    // return;
                    write_count_pkt();
                    // update ID
                    if(hdr.id.min_stage == 0){
                        // if min cell value is 1, we replace the ID
                        if(hdr.id.min_cnt_ht == 1){
                            ht_ID0.write(hdr.id.min_index_ht, hdr.id.key_id);
                        }
                    }
                    else if(hdr.id.min_stage == 1){
                        if(hdr.id.min_cnt_ht == 1){
                            ht_ID1.write(hdr.id.min_index_ht, hdr.id.key_id);
                        }
                    }
                    else{
                        if(hdr.id.min_cnt_ht == 1){
                            ht_ID2.write(hdr.id.min_index_ht, hdr.id.key_id);
                        }
                    }

                    // update counter
                    if(hdr.id.min_stage == 0){
                        // if min cell value is 1, we replace the ID
                        if(hdr.id.min_cnt_ht > 1){
                            ht_counter0.write(hdr.id.min_index_ht, hdr.id.min_cnt_ht-1);
                        }
                    }
                    if(hdr.id.min_stage == 1){
                        // if min cell value is 1, we replace the ID
                        if(hdr.id.min_cnt_ht > 1){
                            ht_counter1.write(hdr.id.min_index_ht, hdr.id.min_cnt_ht-1);
                        }
                    }
                    if(hdr.id.min_stage == 2){
                        // if min cell value is 1, we replace the ID
                        if(hdr.id.min_cnt_ht > 1){
                            ht_counter2.write(hdr.id.min_index_ht, hdr.id.min_cnt_ht-1);
                        }
                    }
                }   
            }
            // ipv4_lpm.apply();     
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