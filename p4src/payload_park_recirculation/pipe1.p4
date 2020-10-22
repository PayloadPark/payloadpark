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

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser_1(
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
	pkt.extract(hdr.pp);
        pkt.extract(hdr.payload_tag);
        pkt.extract(hdr.lamport_clock);
	transition select(hdr.pp.opcode) {
            0: split;
            1: merge;
        }
    }

    state split {
	pkt.extract(hdr.stored_payload_block_1);
	transition accept;
    }

    state merge {
	pkt.extract(hdr.stored_payload_block_0);
	transition accept;
    }


}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser_1(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    apply {
	pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.pp);
        pkt.emit(hdr.payload_tag);
        pkt.emit(hdr.lamport_clock);
	pkt.emit(hdr.stored_payload_block_0);
        pkt.emit(hdr.stored_payload_block_1);
    }
}

#define MAT_FOR_VALIDATING_BLOCK_1(i) \
        Register<pair, bit<8>>(PAYLOAD_REGISTER_SIZE) payload_reg_block##i; \
           RegisterAction<pair, bit<16>, bit<32>>(payload_reg_block##i) store_payload_block##i = { \
               void apply(inout pair value, out bit<32> read_value){ \
                  value.payload_blk = hdr.stored_payload_block_1.blk0; \
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
        hdr.stored_payload_block_1.setInvalid(); \
    } \
    action merge_and_forward_stage##i() { \
        bit<32> reg_value = retrieve_payload_block##i.execute(hdr.payload_tag.tag); \
        hdr.stored_payload_block_1.blk0 =  reg_value; \
        hdr.stored_payload_block_1.setValid(); \
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


#define MAT_1(i) \
        Register<pair, bit<8>>(PAYLOAD_REGISTER_SIZE) payload_reg_block##i; \
           RegisterAction<pair, bit<16>, bit<32>>(payload_reg_block##i) store_payload_block##i = { \
               void apply(inout pair value, out bit<32> read_value){ \
                  value.payload_blk = hdr.stored_payload_block_1.blk##i; \
            } \
        }; \
    RegisterAction<pair, bit<16>, bit<32>>(payload_reg_block##i) retrieve_payload_block##i = {\
        void apply(inout pair value, out bit<32> read_value){ \
            read_value =  value.payload_blk; \
            value.payload_blk = 0; \
        }  \
    }; \
    action save_and_forward_stage##i() { \
        store_payload_block##i.execute(ig_md.table_index); \
    } \
    action merge_and_forward_stage##i() { \
        bit<32> reg_value = retrieve_payload_block##i.execute(ig_md.table_index); \
        hdr.stored_payload_block_1.blk##i =  reg_value; \
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


#define MAT_2(i) \
        Register<one_byte_pair, bit<8>>(PAYLOAD_REGISTER_SIZE) payload_reg_block##i; \
           RegisterAction<one_byte_pair, bit<16>, bit<8>>(payload_reg_block##i) store_payload_block##i = { \
               void apply(inout two_byte_pair value, out bit<16> read_value){ \
                  value.payload_blk = hdr.stored_payload_block_1.blk##i; \
            } \
        }; \
    RegisterAction<one_byte_pair, bit<16>, bit<8>>(payload_reg_block##i) retrieve_payload_block##i = {\
        void apply(inout one_byte_pair value, out bit<8> read_value){ \
            read_value =  value.payload_blk; \
            value.payload_blk = 0; \
        }  \
    }; \
    action save_and_forward_stage##i() { \
        store_payload_block##i.execute(ig_md.table_index); \
    } \
    action merge_and_forward_stage##i() { \
        bit<8> reg_value = retrieve_payload_block##i.execute(ig_md.table_index); \
        hdr.stored_payload_block_1.blk##i =  reg_value; \
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

control SwitchIngress_1(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    MAT_FOR_VALIDATING_BLOCK_1(0)
    MAT_1(1)
    MAT_1(2)
    MAT_1(3)
    MAT_1(4)
    MAT_1(5)
    MAT_1(6)
    MAT_1(7)    
    MAT_1(8)
    MAT_1(9)    
    MAT_1(10)
    MAT_1(11)
    MAT_1(12)
    MAT_1(13)
    MAT_1(14)
    MAT_1(15)
    MAT_1(16)
    MAT_1(17)
    MAT_1(18)
    MAT_1(19)
    MAT_1(20)
    MAT_1(21)
    MAT_1(22)
    MAT_1(23)
    MAT_1(24)
    MAT_1(25)
    MAT_1(26)
    MAT_1(27)
    MAT_1(28)
    MAT_1(29)
    MAT_1(30)
    MAT_1(31)
    MAT_1(32)
    MAT_1(33)
    MAT_1(34)
    MAT_1(35)
    MAT_1(36)
    MAT_1(37)
    MAT_1(38)
    MAT_1(39)
    MAT_1(40)
    MAT_1(41)
    MAT_1(42)
    MAT_1(43)
    MAT_1(44)
    MAT_1(45)
    MAT_1(46)
    MAT_1(47)  
   
    action forward_to_port(bit<9> port) {
        ig_tm_md.ucast_egress_port = port;
    }

    table forward_dst {
        key = {
            hdr.pp.is_enabled : exact;
            hdr.ethernet.dst_addr : exact;
        }
        actions = {
                forward_to_port;
        }
        const entries = {
            (1, 0x000000000000) :forward_to_port(2);
            (1, 0xFFFFFFFFFFFF) :forward_to_port(1);

        }
        size = 2;
    }



    apply {
	forward_dst.apply();
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
        split_merge_operation_stage_10.apply();
        split_merge_operation_stage_11.apply();
        split_merge_operation_stage_12.apply();
        split_merge_operation_stage_13.apply();
        split_merge_operation_stage_14.apply();
        split_merge_operation_stage_15.apply();
        split_merge_operation_stage_16.apply();
        split_merge_operation_stage_17.apply();
        split_merge_operation_stage_18.apply();
        split_merge_operation_stage_19.apply();
        split_merge_operation_stage_20.apply();
        split_merge_operation_stage_21.apply();
        split_merge_operation_stage_22.apply();
        split_merge_operation_stage_23.apply();
        split_merge_operation_stage_24.apply();
        split_merge_operation_stage_25.apply();
        split_merge_operation_stage_26.apply();
        split_merge_operation_stage_27.apply();
        split_merge_operation_stage_28.apply();
        split_merge_operation_stage_29.apply();
        split_merge_operation_stage_30.apply();
        split_merge_operation_stage_31.apply();
        split_merge_operation_stage_32.apply();
        split_merge_operation_stage_33.apply();
        split_merge_operation_stage_34.apply();
        split_merge_operation_stage_35.apply();
        split_merge_operation_stage_36.apply();
        split_merge_operation_stage_37.apply();
        split_merge_operation_stage_38.apply();
        split_merge_operation_stage_39.apply();
        split_merge_operation_stage_40.apply();
        split_merge_operation_stage_41.apply();
        split_merge_operation_stage_42.apply();
        split_merge_operation_stage_43.apply();
        split_merge_operation_stage_44.apply();
        split_merge_operation_stage_45.apply();
        split_merge_operation_stage_46.apply();
        split_merge_operation_stage_47.apply(); 

     }  
    
}



parser SwitchEgressParser_1(
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
        transition accept;
     }

     state merge {
        pkt.extract(hdr.stored_payload_block_0);
        transition accept;
    }

}


control SwitchEgress_1(
        inout header_t hdr,
        inout metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
	apply {
        }
}

control SwitchEgressDeparser_1<H, M>(
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
    }
}
