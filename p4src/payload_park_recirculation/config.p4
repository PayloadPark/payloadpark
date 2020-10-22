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

#ifndef _CONFIG_
#define _CONFIG_


struct metadata_t {
    
    bit<16> table_index;
    bit<16> lamport_clock;
    bit<16> current_timer;
    bit<1> is_packet_evicted;
    bool pp_chksum_err;
}

struct pair {
    bit<32>     payload_blk;
}

struct two_byte_pair {
    bit<16>     payload_blk;
}

struct one_byte_pair {
    bit<8>     payload_blk;
}

struct pointers {
    bit<16> table_index;
}

struct lamport_clock {
    bit<16> clock;
}

struct bitmask {
    bit<16>  split_ts;
    bit<16>  exp_threshold;
}

    #define NUM_SPLITS_COUNTER_INDEX 0
    #define NUM_MERGES_COUNTER_INDEX 1
    #define NUM_SPLITS_AFTER_EVICTION_INDEX 2
    #define EXPLICIT_DROP 3   

    const bit<9> SPLIT_EGRESS_PORT = 2;
    const bit<9> MERGE_EGRESS_PORT = 1;
    // Use correct recirculation port
    const bit<9> PIPE_1_RECIRCULATION_PORT = 1;
    const bit<8> SPLIT_ACTION = 4;
    const bit<8> IGNORE_SPLIT_ACTION = 0;
    const bit<8> MERGE_ACTION = 5;
    const bit<8> IGNORE_MERGE_ACTION = 1;
    const bit<3> DROP_ACTION = 6;

    // Artificial value for now, for disabling Split functionality
    const bit<16> MAX_WRITE_PTR_VALUE = 4;

    const bit<8> SPLIT_ACTION_COUNTER_INDEX = 0;
    const bit<8> MERGE_ACTION_COUNTER_INDEX = 0;
    const bit<8> DROP_ACTION_COUNTER_INDEX = 0;
    const bit<8> IGNORE_SPLIT_ACTION_COUNTER_INDEX = 0;
    const bit<8> INCORRECT_EVICTION_ACTION_COUNTER_INDEX = 0;

    #define NUM_INCORRECT_PACKET_EVICTIONS 0

    const bit<1> NUM_CORRECT_CHECKSUM  = 0;
    const bit<1> NUM_INCORRECT_CHECKSUM = 1;

    #define NUM_SPLITS_AFTER_EVICTION_INDEX 2

    #define PAYLOAD_REGISTER_SIZE 32w5
    //#define PAYLOAD_REGISTER_SIZE 32w40
    #define TIMER 3

    #define TRAFFIC_GEN1_PORT_NUMBER 3
    #define TRAFFIC_GEN2_PORT_NUMBER 4
    #define NFSERVER1_PORT_NUMBER 1
    #define NFSERVER2_PORT_NUMBER 2

#endif /* _UTIL */
