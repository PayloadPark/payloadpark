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

#ifndef _HEADERS_
#define _HEADERS_


header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}


// Header for SMP packet processing
header pp_h {
    bit<1> is_enabled;
    bit<1> opcode;
    bit<6> unused;
    bit<16> crc;
}

header payload_t_block_0 {
    bit<16> blk0;
    bit<16> blk1;
    bit<16> blk2;
    bit<16> blk3;
    bit<16> blk4;
    bit<16> blk5;
    bit<16> blk6;
    bit<16> blk7;
    bit<16> blk8;
    bit<16> blk9; 
}


header payload_t_block_1 {
    bit<32> blk0;
    bit<32> blk1;
    bit<32> blk2;
    bit<32> blk3;
    bit<32> blk4;
    bit<32> blk5;
    bit<32> blk6;
    bit<32> blk7;
    bit<32> blk8;
    bit<32> blk9;
    bit<32> blk10;
    bit<32> blk11;
    bit<32> blk12;
    bit<32> blk13;
    bit<32> blk14;
    bit<32> blk15;
    bit<32> blk16;
    bit<32> blk17;
    bit<32> blk18;
    bit<32> blk19;
    bit<32> blk20;
    bit<32> blk21;
    bit<32> blk22;
    bit<32> blk23;
    bit<32> blk24;
    bit<32> blk25;
    bit<32> blk26;
    bit<32> blk27; 
    bit<32> blk28;
    bit<32> blk29;
    bit<32> blk30;
    bit<32> blk31;
    bit<32> blk32;
    bit<32> blk33;
    bit<32> blk34;
    bit<32> blk35;

}

header payload_t_tag {
    bit<16> tag;
}

header lamport_t_clock {
    bit<16> clock;
}

struct header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    udp_h udp;

    // Add more headers here.
    pp_h pp; 
    payload_t_tag payload_tag;
    lamport_t_clock lamport_clock;
    payload_t_block_0 stored_payload_block_0;
    payload_t_block_1 stored_payload_block_1;
}

#endif /* _HEADERS_ */
