/*
Copyright (c) 2020-Present UBC-Systopia

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#include <core.p4>
#include <tna.p4>

#include "headers.p4"
#include "config.p4"
#include "pipe1.p4"



#define IP_PROTOCOLS_UDP 17


// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    Checksum<bit<16>>(HashAlgorithm_t.CSUM16) pp_csum;
    state start {
	pkt.extract(ig_intr_md);
	pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        pkt.extract(hdr.ipv4);
	transition select(hdr.ipv4.protocol) {
             IP_PROTOCOLS_UDP : parse_udp;
        }

    }

    state parse_udp {
        pkt.extract(hdr.udp);
	transition select(ig_intr_md.ingress_port) {
            TRAFFIC_GEN1_PORT_NUMBER: split;
            TRAFFIC_GEN2_PORT_NUMBER: split;
            NFSERVER1_PORT_NUMBER: merge;
            NFSERVER2_PORT_NUMBER: merge;
        }
    }

    state split {
        transition select(hdr.udp.hdr_length[15:8]) {
                0  :  length_check;
                default : parse_payload;
        }
    }

    state length_check {
        transition select(hdr.udp.hdr_length[7:0]) {
                0xAF &&& 0xF8 : parse_payload;
                0xBF &&& 0xF0 : parse_payload;
                0xFF &&& 0xC0 : parse_payload;
                default  :  accept;
        }
    }

     state parse_payload {
        hdr.pp.opcode = 0;
        hdr.payload_tag.tag = 0;
        hdr.lamport_clock.clock = 0;
        pkt.extract(hdr.stored_payload_block_0);
        transition accept;
     }

    state merge {
  	pkt.extract(hdr.pp);
        pkt.extract(hdr.payload_tag);
        pkt.extract(hdr.lamport_clock);
	pp_csum.add({
            hdr.pp.crc,
            hdr.payload_tag.tag,
            hdr.lamport_clock.clock});
        ig_md.pp_chksum_err = pp_csum.verify();
	transition accept;
    }


}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
   Checksum<bit<16>>(HashAlgorithm_t.CSUM16) pp_csum; 

    apply {
	if (hdr.pp.isValid()) {
            hdr.pp.crc = pp_csum.update({
                hdr.payload_tag.tag,
                hdr.lamport_clock.clock
                });
            }
	pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.pp);
        pkt.emit(hdr.payload_tag);
        pkt.emit(hdr.lamport_clock);
	pkt.emit(hdr.stored_payload_block_0); 
    }
}


#define MAT_FOR_VALIDATING_BLOCK(i) \
    Register<two_byte_pair, bit<8>>(PAYLOAD_REGISTER_SIZE) payload_reg_block##i; \
    RegisterAction<two_byte_pair, bit<16>, bit<16>>(payload_reg_block##i) store_payload_block##i = { \
           void apply(inout two_byte_pair value, out bit<16> read_value){ \
           value.payload_blk = hdr.stored_payload_block_0.blk0; \
        } \
    }; \
    RegisterAction<two_byte_pair, bit<16>, bit<16>>(payload_reg_block##i) retrieve_payload_block##i = {\
        void apply(inout two_byte_pair value, out bit<16> read_value){ \
            read_value =  value.payload_blk; \
	    value.payload_blk = 0; \ 
        }  \
    }; \
    action save_and_forward_stage##i() { \
        store_payload_block##i.execute(ig_md.table_index); \
        hdr.stored_payload_block_0.setInvalid(); \
    } \
    action merge_and_forward_stage##i() { \
        bit<16> reg_value = retrieve_payload_block##i.execute(ig_md.table_index); \
        hdr.stored_payload_block_0.blk0 =  reg_value; \
        hdr.stored_payload_block_0.setValid(); \
    } \
    table split_merge_operation_stage_##i { \
        key = { \
            hdr.pp.is_enabled : exact; \
	    hdr.pp.opcode : exact; \
        } \
        actions = { \
            save_and_forward_stage##i; \
            merge_and_forward_stage##i; \
        } \
        const entries = { \
            (1, 0) : save_and_forward_stage##i(); \
            (1, 1) : merge_and_forward_stage##i(); \
        } \
        size = 2; \
    } \

#define MAT(i) \
    Register<two_byte_pair, bit<8>>(PAYLOAD_REGISTER_SIZE) payload_reg_block##i; \
    RegisterAction<two_byte_pair, bit<16>, bit<16>>(payload_reg_block##i) store_payload_block##i = { \
        void apply(inout two_byte_pair value, out bit<16> read_value){ \
            value.payload_blk = hdr.stored_payload_block_0.blk##i; \
        } \
    }; \
    RegisterAction<two_byte_pair, bit<16>, bit<16>>(payload_reg_block##i) retrieve_payload_block##i = {\
        void apply(inout two_byte_pair value, out bit<16> read_value){ \
            read_value =  value.payload_blk; \
            value.payload_blk = 0; \
        }  \
    }; \
    action save_and_forward_stage##i() { \
        store_payload_block##i.execute(ig_md.table_index); \
    } \
    action merge_and_forward_stage##i() { \
        bit<16> reg_value = retrieve_payload_block##i.execute(ig_md.table_index); \
        hdr.stored_payload_block_0.blk##i =  reg_value; \
    } \
        table split_merge_operation_stage_##i { \
        key = { \
	    hdr.pp.is_enabled : exact; \
            hdr.pp.opcode : exact; \
        } \
        actions = { \
            save_and_forward_stage##i; \
            merge_and_forward_stage##i; \
        } \
        const entries = { \
            (1, 0) : save_and_forward_stage##i(); \
            (1, 1) : merge_and_forward_stage##i();  \
        } \
        size = 2; \
    } \

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
   MAT_FOR_VALIDATING_BLOCK(0)
   MAT(1)
   MAT(2)
   MAT(3)
   MAT(4)
   MAT(5)
   MAT(6)
   MAT(7)
   MAT(8)
   MAT(9) 
   Register<pointers, bit<16>>(1) table_index;
   Register<lamport_clock, bit<16>>(1, {1}) lamport_clock_reg;
   Register<bitmask, bit<16>>(PAYLOAD_REGISTER_SIZE) control_block;
   

   // Index 0 records number of payload evictions.
   // Index 1 records number of packets when Split was turned-off because table index points
   // to an occupied location in the lookup table.
   Counter<bit<32>, bit<8>>(
        2, CounterType_t.PACKETS) exp_thr_counter;

   // Index 0: number of merges with turned-off enabled flag
   Counter<bit<32>, bit<2>>(
        1, CounterType_t.PACKETS) merge_turned_off_counter;
  
   // Index 0: number of splits
   // Index 1: number of merges
   // Index 2: number of payload evictions
   // Index 3: number of explicit drops 
   Counter<bit<32>, bit<8>>(
        4, CounterType_t.PACKETS) op_counter;

   // Index 0: Num of premature payload evictions
   Counter<bit<32>, bit<1>>(
        1, CounterType_t.PACKETS) premature_evict_counter;


   // Index 0: Disabled split packets when length is less than 160 bytes
   Counter<bit<32>, bit<1>>(
        1, CounterType_t.PACKETS) len_counter;


   RegisterAction<pointers, bit<8>, bit<16>>(table_index) table_index_increment = {
        void apply(inout pointers value, out bit<16> table_index_value) {
            if (value.table_index < MAX_WRITE_PTR_VALUE) {
                value.table_index = value.table_index + 1;
            }
           else {
                value.table_index = 0;
           }
            table_index_value = value.table_index;
        }
    };

    RegisterAction<lamport_clock, bit<8>, bit<16>>(lamport_clock_reg) lamport_clock_increment = {
        void apply(inout lamport_clock value, out bit<16> clock_value) {
            value.clock = value.clock + 1;
            clock_value = value.clock;
        }
    };

   RegisterAction<bitmask, bit<16>, bit<16>>(control_block) is_register_index_occupied = {
        void apply(inout bitmask value, out bit<16> is_split_enabled){
            is_split_enabled = value.exp_threshold;
            if (value.exp_threshold <= 1) {
                value.split_ts = ig_md.lamport_clock;
                value.exp_threshold = TIMER;
            } else {
                value.exp_threshold = value.exp_threshold - 1;
            }
        }
    };

    RegisterAction<bitmask, bit<16>, bit<1>>(control_block) unset_bitmask_in_register = {
        void apply(inout bitmask value, out bit<1> is_merge_enabled){
            if (value.split_ts == ig_md.lamport_clock) {
                value.split_ts = 0;
                value.exp_threshold = 0;
                is_merge_enabled = 1;
            } else {
                is_merge_enabled = 0;
            }
        }
    };

    action update_write_pointer() {
        ig_md.table_index  = table_index_increment.execute(0);
    }

    action extract_tag() {
        ig_md.table_index =  hdr.payload_tag.tag;
    }

    table write_pointer_increment {
         key = {
             hdr.pp.is_enabled : exact;
             ig_intr_md.ingress_port : exact;

        }
        actions = {
            update_write_pointer;
            extract_tag;
        }
        const entries = {
            (1, TRAFFIC_GEN1_PORT_NUMBER) : update_write_pointer();
            (1, TRAFFIC_GEN2_PORT_NUMBER) : update_write_pointer();
            (1, NFSERVER1_PORT_NUMBER) : extract_tag();
            (1, NFSERVER2_PORT_NUMBER) : extract_tag();
        }
        size = 4;
    }


    action forward_to_port(bit<9> port) {
        ig_tm_md.ucast_egress_port = port;
    }
  
    table l2_fwd {
	key = {
	    hdr.pp.is_enabled : exact;
            hdr.ethernet.dst_addr : exact;
        }
        actions = {
		forward_to_port;
        }
        const entries = {
            (1, 0x000000000000) :forward_to_port(PIPE_1_RECIRCULATION_PORT);
            (1, 0xFFFFFFFFFFFF) :forward_to_port(PIPE_1_RECIRCULATION_PORT);
            (0, 0x000000000000) :forward_to_port(2);
            (0, 0xFFFFFFFFFFFF) :forward_to_port(1);
        }
        size = 4;
    }


    action enable_pp_split_flag_action() {
        hdr.pp.is_enabled = 1;
        hdr.pp.opcode = 0;
	hdr.pp.setValid();
    }

    action disable_pp_split_flag_action() {
        hdr.pp.is_enabled = 0;
        hdr.pp.opcode = 0;
        hdr.pp.unused = 0;
	hdr.pp.setValid();
	hdr.payload_tag.tag = 0;
        hdr.payload_tag.setValid();
        hdr.lamport_clock.clock = 0;
        hdr.lamport_clock.setValid();
        ig_tm_md.bypass_egress = true;
        len_counter.count(0);

    }
  
    table enable_pp_flag {
        key = {
            hdr.stored_payload_block_0.isValid(): exact;
            ig_intr_md.ingress_port : exact;
 	    hdr.udp.hdr_length : range;
        }
        actions = {
             enable_pp_split_flag_action;
             disable_pp_split_flag_action;
        }
        const entries = {
                (true, TRAFFIC_GEN1_PORT_NUMBER, 360 .. 65535) : enable_pp_split_flag_action();
                (true, TRAFFIC_GEN2_PORT_NUMBER, 360 .. 65535) : enable_pp_split_flag_action();
                (true, TRAFFIC_GEN1_PORT_NUMBER, 8 .. 360) : disable_pp_split_flag_action();
                (true, TRAFFIC_GEN2_PORT_NUMBER, 8 .. 360) : disable_pp_split_flag_action();
                (false, TRAFFIC_GEN1_PORT_NUMBER, _) : disable_pp_split_flag_action();
                (false, TRAFFIC_GEN2_PORT_NUMBER, _) : disable_pp_split_flag_action();
        }
        size = 8;
    }


    action enable_pp_action() {
	hdr.pp.is_enabled = 1;
	hdr.pp.opcode = 0;
	hdr.pp.unused = 0;
	hdr.pp.crc = 0;
	hdr.pp.setValid();
    }

    action disable_pp_action() {
	hdr.pp.is_enabled = 0;
	hdr.pp.opcode = 0;
        hdr.pp.unused = 0;
        hdr.pp.crc = 0;
	hdr.payload_tag.tag = 0;
        hdr.payload_tag.setValid();
        hdr.lamport_clock.clock = 0;
        hdr.lamport_clock.setValid();
        hdr.pp.setValid();
    }    

    table enable_pp {
	key = {
	    hdr.pp.is_enabled : exact;
	    hdr.pp.opcode : exact;
	    ig_intr_md.ingress_port : exact;
        } 
        actions = {
	     enable_pp_action;
	     disable_pp_action;
        }
	const entries = {
		(1, 0, TRAFFIC_GEN1_PORT_NUMBER) : enable_pp_action();
		(1, 0, TRAFFIC_GEN2_PORT_NUMBER) : enable_pp_action();
		(0, 0, TRAFFIC_GEN1_PORT_NUMBER) : disable_pp_action();
		(0, 0, TRAFFIC_GEN2_PORT_NUMBER) : disable_pp_action();
        }
	size = 4;
    }

    action update_lamport_clock() {
        ig_md.lamport_clock  = lamport_clock_increment.execute(0);
    }

    action extract_clock_tag() {
        ig_md.lamport_clock =  hdr.lamport_clock.clock;
    }

    table lamport_clk_increment {
        key = {
            hdr.pp.is_enabled : exact;
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            update_lamport_clock;
            extract_clock_tag;
        }
        size = 1024;
        const entries = {
            (1, TRAFFIC_GEN1_PORT_NUMBER) : update_lamport_clock();
            (1, TRAFFIC_GEN2_PORT_NUMBER) : update_lamport_clock();
            (1, NFSERVER1_PORT_NUMBER) : extract_clock_tag();
            (1, NFSERVER2_PORT_NUMBER) : extract_clock_tag();
        }
    }

    action check_bitmask() {
        ig_md.current_timer = is_register_index_occupied.execute(ig_md.table_index);
    }

    action unset_bitmask() {
        bit<1> merge_disabled = unset_bitmask_in_register.execute(ig_md.table_index);
        hdr.pp.is_enabled = merge_disabled;
    }

       table change_bitmask {
        key = {
            hdr.pp.is_enabled : exact;
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            check_bitmask;
            unset_bitmask;
        }
        const entries = {
            (1, TRAFFIC_GEN1_PORT_NUMBER) : check_bitmask();
            (1, TRAFFIC_GEN2_PORT_NUMBER) : check_bitmask();
            (1, NFSERVER1_PORT_NUMBER) : unset_bitmask();
            (1, NFSERVER2_PORT_NUMBER) : unset_bitmask();
        }
        size = 4;
    }


    action count_incorrect_pkt_eviction() {
        ig_dprsr_md.drop_ctl = 1;
        premature_evict_counter.count(NUM_INCORRECT_PACKET_EVICTIONS);
    }

    table record_incorrect_pkt_eviction {
        key = {
            hdr.pp.is_enabled : exact;
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            count_incorrect_pkt_eviction;
        }
        const entries = {
            (0,  NFSERVER1_PORT_NUMBER) : count_incorrect_pkt_eviction();
            (0,  NFSERVER2_PORT_NUMBER) : count_incorrect_pkt_eviction();

        }
        size = 24;

    }


    action update_evict_counter() {
        exp_thr_counter.count(0);
        hdr.pp.is_enabled = 1;
        ig_md.is_packet_evicted = 1;
    }

    action update_disabled_split_current_index_full() {
        exp_thr_counter.count(1); 
        hdr.pp.is_enabled = 0;
        ig_md.is_packet_evicted = 0;
    }

    table update_eviction_counter {
        key = {
            ig_md.current_timer : range;
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            update_evict_counter;
            update_disabled_split_current_index_full;
        }
        const entries = {
            (1..1, TRAFFIC_GEN1_PORT_NUMBER) : update_evict_counter();
            (2.. TIMER+ 1, TRAFFIC_GEN1_PORT_NUMBER): update_disabled_split_current_index_full();
            (1..1, TRAFFIC_GEN2_PORT_NUMBER) : update_evict_counter();
            (2.. TIMER + 1, TRAFFIC_GEN2_PORT_NUMBER): update_disabled_split_current_index_full();
        }
        size = 4;
    }

    action forward_to_nf_server() {
        hdr.payload_tag.tag = ig_md.table_index;
        hdr.payload_tag.setValid();
        hdr.lamport_clock.clock = ig_md.lamport_clock;
        hdr.lamport_clock.setValid();
        op_counter.count(NUM_SPLITS_COUNTER_INDEX);
    }

    action forward_to_nf_server_after_eviction() {
        hdr.payload_tag.tag = ig_md.table_index;
        hdr.payload_tag.setValid();
        hdr.lamport_clock.clock = ig_md.lamport_clock;
        hdr.lamport_clock.setValid();
        op_counter.count(NUM_SPLITS_AFTER_EVICTION_INDEX);
    }

    action forward_to_traffic_gen() {
        op_counter.count(NUM_MERGES_COUNTER_INDEX); 
        // To distinguish between Split and Merge requests in the pipeline
        hdr.pp.opcode = 1;
    }

    action disable_split_when_array_full() {
        ig_tm_md.bypass_egress = true;
        hdr.payload_tag.tag = 0;
        hdr.payload_tag.setValid();
        hdr.lamport_clock.clock = 0;
        hdr.lamport_clock.setValid();
    }

    action explicit_drop() {
        ig_dprsr_md.drop_ctl = 1;
        op_counter.count(EXPLICIT_DROP);
    } 
    table forward {
        key = {
            hdr.pp.is_enabled : exact;
            hdr.pp.opcode : exact;
            ig_intr_md.ingress_port : exact;
            ig_md.is_packet_evicted : exact;
        }
        actions = {
	    forward_to_nf_server;
            forward_to_nf_server_after_eviction;
            forward_to_traffic_gen;
            disable_split_when_array_full;
            explicit_drop;
        }
        size = 12;
        const entries = {
	    (1, 0, TRAFFIC_GEN1_PORT_NUMBER, 0) : forward_to_nf_server();
            (1, 0, TRAFFIC_GEN2_PORT_NUMBER, 0) : forward_to_nf_server();
            (1, 0, NFSERVER1_PORT_NUMBER, 0) : forward_to_traffic_gen();
            (1, 0, NFSERVER2_PORT_NUMBER, 0) : forward_to_traffic_gen();
            (0, 0, TRAFFIC_GEN1_PORT_NUMBER, 0) : disable_split_when_array_full();
            (0, 0, TRAFFIC_GEN2_PORT_NUMBER, 0) : disable_split_when_array_full();
            (1, 0, TRAFFIC_GEN1_PORT_NUMBER, 1) : forward_to_nf_server_after_eviction();
            (1, 0, TRAFFIC_GEN2_PORT_NUMBER, 1) : forward_to_nf_server_after_eviction();
            (1, 1, NFSERVER1_PORT_NUMBER, 0) : explicit_drop();
            (1, 1, NFSERVER2_PORT_NUMBER, 0) : explicit_drop();

        }
    }

      action forward_merges_for_disabled_splits_to_traffic_gen() {
        ig_tm_md.bypass_egress = true;
        hdr.pp.setInvalid();
        hdr.lamport_clock.setInvalid();
        hdr.payload_tag.setInvalid();
        merge_turned_off_counter.count(0);
    }


     table forward_merges_for_disabled_splits_table {
        key = {
            hdr.pp.is_enabled : exact;
            hdr.pp.opcode : exact;
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            forward_merges_for_disabled_splits_to_traffic_gen;
        }
        const entries = {
            (0, 0, NFSERVER1_PORT_NUMBER) : forward_merges_for_disabled_splits_to_traffic_gen();
            (0, 0, NFSERVER2_PORT_NUMBER) : forward_merges_for_disabled_splits_to_traffic_gen();
        }
        size = 2;

     }


    apply {
        if (!forward_merges_for_disabled_splits_table.apply().hit) {
	    enable_pp_flag.apply();
	    write_pointer_increment.apply();
	    lamport_clk_increment.apply();	
  	    change_bitmask.apply();
	    update_eviction_counter.apply();
            record_incorrect_pkt_eviction.apply();
	    forward.apply();
            split_merge_operation_stage_0.apply();
	    split_merge_operation_stage_1.apply();
	    split_merge_operation_stage_2.apply();
            split_merge_operation_stage_3.apply();
	    split_merge_operation_stage_4.apply();
            split_merge_operation_stage_5.apply();
	    split_merge_operation_stage_6.apply();
	    split_merge_operation_stage_7.apply();
	    split_merge_operation_stage_8.apply();
            split_merge_operation_stage_9.apply(); 
        }
        l2_fwd.apply();  
    }
    
}



parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
	pkt.extract(eg_intr_md);
	transition parse_ethernet;
    }

   state parse_ethernet {
        pkt.extract(hdr.ethernet);
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
             IP_PROTOCOLS_UDP : parse_udp;
        }
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        pkt.extract(hdr.pp);
        pkt.extract(hdr.payload_tag);
        pkt.extract(hdr.lamport_clock);
        transition select(hdr.pp.opcode)  {
            0: split;
            1: merge;
        }
    }

    state split {
        pkt.extract(hdr.stored_payload_block_2);
        transition accept;
     }

     state merge {
        pkt.extract(hdr.stored_payload_block_0);
	pkt.extract(hdr.stored_payload_block_1);
        transition accept;
    }

}

#define MAT_EGRESS_FOR_VALIDATING_BLOCK(i) \
    Register<pair, bit<8>>(PAYLOAD_REGISTER_SIZE) payload_reg_block##i; \
    RegisterAction<pair, bit<16>, bit<32>>(payload_reg_block##i) store_payload_block##i = { \
        void apply(inout pair value, out bit<32> read_value){ \
            value.payload_blk = hdr.stored_payload_block_2.blk0; \
        } \
    }; \
    RegisterAction<pair, bit<16>, bit<32>>(payload_reg_block##i) retrieve_payload_block##i = {\
        void apply(inout pair value, out bit<32> read_value){ \
            read_value =  value.payload_blk; \
            value.payload_blk = 0; \
        }  \
    }; \
    action save_and_forward_stage##i() { \
        store_payload_block##i.execute(hdr.payload_tag.tag); \
        hdr.stored_payload_block_2.setInvalid(); \
    } \
    action merge_and_forward_stage##i() { \
        bit<32> reg_value = retrieve_payload_block##i.execute(hdr.payload_tag.tag); \
        hdr.stored_payload_block_2.blk0 =  reg_value; \
        hdr.stored_payload_block_2.setValid(); \
    } \
    table split_merge_operation_stage##i { \
        key = { \
	    hdr.pp.is_enabled : exact; \
            hdr.pp.opcode : exact; \
        } \
        actions = { \
            save_and_forward_stage##i; \
            merge_and_forward_stage##i; \
        } \
        const entries = { \
            (1, 0) : save_and_forward_stage##i(); \
            (1, 1) : merge_and_forward_stage##i(); \
        } \
        size = 2; \
    } \

#define MAT_EGRESS(i) \
    Register<pair, bit<8>>(PAYLOAD_REGISTER_SIZE) payload_reg_block##i; \
    RegisterAction<pair, bit<16>, bit<32>>(payload_reg_block##i) store_payload_block##i = { \
        void apply(inout pair value, out bit<32> read_value){ \
            value.payload_blk = hdr.stored_payload_block_2.blk##i; \
        } \
    }; \
    RegisterAction<pair, bit<16>, bit<32>>(payload_reg_block##i) retrieve_payload_block##i = {\
        void apply(inout pair value, out bit<32> read_value){ \
            read_value =  value.payload_blk; \
            value.payload_blk = 0; \
        }  \
    }; \
    action save_and_forward_stage##i() { \
        store_payload_block##i.execute(hdr.payload_tag.tag); \
    } \
    action merge_and_forward_stage##i() { \
        bit<32> reg_value = retrieve_payload_block##i.execute(hdr.payload_tag.tag); \
        hdr.stored_payload_block_2.blk##i =  reg_value; \
    } \
    table split_merge_operation_stage##i { \
        key = { \
	    hdr.pp.is_enabled : exact; \
            hdr.pp.opcode : exact; \
        } \
        actions = { \
            save_and_forward_stage##i; \
            merge_and_forward_stage##i; \
        } \
        const entries = { \
            (1, 0) : save_and_forward_stage##i(); \
            (1, 1) : merge_and_forward_stage##i(); \
        } \
        size = 2; \
    } \

#define MAT_EGRESS_FOR_INVALIDATING_SMP_HEADER(i) \
    Register<pair, bit<8>>(PAYLOAD_REGISTER_SIZE) payload_reg_block##i; \
    RegisterAction<pair, bit<16>, bit<32>>(payload_reg_block##i) store_payload_block##i = { \
        void apply(inout pair value, out bit<32> read_value){ \
            value.payload_blk = hdr.stored_payload_block_2.blk##i; \
        } \
    }; \
    RegisterAction<pair, bit<16>, bit<32>>(payload_reg_block##i) retrieve_payload_block##i = {\
        void apply(inout pair value, out bit<32> read_value){ \
            read_value =  value.payload_blk; \
            value.payload_blk = 0; \
        }  \
    }; \
    action save_and_forward_stage##i() { \
        store_payload_block##i.execute(hdr.payload_tag.tag); \
    } \
    action merge_and_forward_stage##i() { \
        bit<32> reg_value = retrieve_payload_block##i.execute(hdr.payload_tag.tag); \
        hdr.stored_payload_block_2.blk##i =  reg_value; \
	hdr.pp.setInvalid(); \
	hdr.payload_tag.setInvalid(); \
	hdr.lamport_clock.setInvalid(); \
    } \
    table split_merge_operation_stage##i { \
        key = { \
	    hdr.pp.is_enabled : exact; \
            hdr.pp.opcode : exact; \
        } \
        actions = { \
            save_and_forward_stage##i; \
            merge_and_forward_stage##i; \
        } \
        const entries = { \
            (1, 0) : save_and_forward_stage##i(); \
            (1, 1) : merge_and_forward_stage##i(); \
        } \
        size = 2; \
    } \


control SwitchEgress(
        inout header_t hdr,
        inout metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    MAT_EGRESS_FOR_VALIDATING_BLOCK(0)
    MAT_EGRESS(1)
    MAT_EGRESS(2)
    MAT_EGRESS(3)
    MAT_EGRESS(4)
    MAT_EGRESS(5)
    MAT_EGRESS(6)
    MAT_EGRESS(7)
    MAT_EGRESS(8)
    MAT_EGRESS(9)
    MAT_EGRESS(10)
    MAT_EGRESS(11)
    MAT_EGRESS(12)
    MAT_EGRESS(13)
    MAT_EGRESS(14)
    MAT_EGRESS(15)
    MAT_EGRESS(16)
    MAT_EGRESS(17)
    MAT_EGRESS(18)
    MAT_EGRESS(19)
    MAT_EGRESS(20)
    MAT_EGRESS(21)
    MAT_EGRESS(22)
    MAT_EGRESS(23)
    MAT_EGRESS(24)
    MAT_EGRESS(25)
    MAT_EGRESS(26)
    MAT_EGRESS(27)
    MAT_EGRESS(28)
    MAT_EGRESS(29)
    MAT_EGRESS(30)
    MAT_EGRESS(31)
    MAT_EGRESS(32) 
    MAT_EGRESS(33)
    MAT_EGRESS_FOR_INVALIDATING_SMP_HEADER(34)
    apply {
	split_merge_operation_stage0.apply();
	split_merge_operation_stage1.apply();
        split_merge_operation_stage2.apply();
        split_merge_operation_stage3.apply();
        split_merge_operation_stage4.apply();
        split_merge_operation_stage5.apply();
        split_merge_operation_stage6.apply();
        split_merge_operation_stage7.apply();
        split_merge_operation_stage8.apply();
        split_merge_operation_stage9.apply();
	split_merge_operation_stage10.apply();
        split_merge_operation_stage11.apply();
        split_merge_operation_stage12.apply();
        split_merge_operation_stage13.apply();
        split_merge_operation_stage14.apply();
        split_merge_operation_stage15.apply();
        split_merge_operation_stage16.apply();
        split_merge_operation_stage17.apply();
        split_merge_operation_stage18.apply();
        split_merge_operation_stage19.apply();
	split_merge_operation_stage20.apply();
        split_merge_operation_stage21.apply();
        split_merge_operation_stage22.apply();
        split_merge_operation_stage23.apply();
        split_merge_operation_stage24.apply();
        split_merge_operation_stage25.apply();
        split_merge_operation_stage26.apply();
        split_merge_operation_stage27.apply(); 
        split_merge_operation_stage28.apply();
        split_merge_operation_stage29.apply();
        split_merge_operation_stage30.apply();
	split_merge_operation_stage31.apply();
        split_merge_operation_stage32.apply();
	split_merge_operation_stage33.apply();
        split_merge_operation_stage34.apply();

    }
}

control SwitchEgressDeparser<H, M>(
        packet_out pkt,
        inout header_t hdr,
        in M eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    Checksum<bit<16>>(HashAlgorithm_t.CSUM16) tcp_csum;

    apply {
	pkt.emit(hdr.ethernet);
	pkt.emit(hdr.ipv4);
	pkt.emit(hdr.udp);
        pkt.emit(hdr.pp);
        pkt.emit(hdr.payload_tag);
        pkt.emit(hdr.lamport_clock);
        pkt.emit(hdr.stored_payload_block_0);
        pkt.emit(hdr.stored_payload_block_1);
        pkt.emit(hdr.stored_payload_block_2);
    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser<header_t, metadata_t>()) pipe;

Pipeline(SwitchIngressParser_1(),
         SwitchIngress_1(),
         SwitchIngressDeparser_1(),
         SwitchEgressParser_1(),
         SwitchEgress_1(),
         SwitchEgressDeparser_1<header_t, metadata_t>()) pipe1;


Switch(pipe, pipe1) main;
