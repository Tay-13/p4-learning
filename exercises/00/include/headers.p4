/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

const bit<16> TYPE_IPV4 = 0x800;

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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
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

struct metadata {
    // meta of CM sketch
    bit<32> index_cm0;
    bit<32> index_cm1;
    bit<32> index_cm2;
    bit<32> cnt_cm0;
    bit<32> cnt_cm1;
    bit<32> cnt_cm2;
    bit<32> min_cnt_cm;

    // meta of H-Table
    // key_index stores hash(Y) to choose one stage
    // key_idxx indicate if choose the-x stage
    // e.g., key_idx0 = 1, (X,Y) choose the index_ht0-th position of th 0-th stage  
    bit<2> index;
    bit<1> key_idx0;
    bit<1> key_idx1;
    bit<1> key_idx2;   
    bit<32> index_ht0;
    bit<32> index_ht1;
    bit<32> index_ht2;
    bit<32> cnt_ht0;
    bit<32> cnt_ht1;
    bit<32> cnt_ht2;
    bit<64> id_ht0;
    bit<64> id_ht1;
    bit<64> id_ht2;
    bit<32> min_cnt_ht;
    bit<64> id;
    bit<2>  matched;  // 0: not matched; 1: matched; 2: empty
}

header flowID_t {
    bit<64> key_id;
}

header estimate_t {
    bit<32>  freq;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    estimate_t   est_cm;
    flowID_t     id;
    // TO DO
    // heavy_tuple  my_tuple;
}

