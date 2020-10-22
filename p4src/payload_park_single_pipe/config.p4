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

#ifndef CONFIG_INIT
    #define CONFIG_INIT 1

    const bit<1> SPLIT_ACTION = 0;
    const bit<1> MERGE_ACTION = 1;	

    #define DISABLED_SPLIT_PACKET_TOO_SHORT_COUNTER_INDEX 0
    #define NUM_SPLITS_COUNTER_INDEX 0
    #define NUM_MERGES_COUNTER_INDEX 1
    #define NUM_SPLITS_AFTER_EVICTION_INDEX 2
    #define NUM_DROPS_COUNTER_INDEX 3

    #define TOTAL_DISABLED_SPLIT 3
    #define EXPLICIT_DROP 3

    #define NUM_INCORRECT_PACKET_EVICTIONS 0

    const bit<16> MAX_WRITE_PTR_VALUE = 4;

    #define NFSERVER1_PORT_NUMBER 1
    #define NFSERVER2_PORT_NUMBER 2
    #define TRAFFIC_GEN1_PORT_NUMBER 3
    #define TRAFFIC_GEN2_PORT_NUMBER 4
    #define PAYLOAD_REGISTER_SIZE 32w5

    #define EXP_THRESHOLD 3
#endif
