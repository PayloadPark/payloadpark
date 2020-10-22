The repository includes P4 16 code for PayloadPark and code changes to OpenNetVM
for enabling explicit payload evictions.

P4 Code: We built the code using the Tofino switch.
(a) Change the port numbers for the NF server and the traffic generator
in the config.p4 file.
(b) If you are using recirculation, please change the recirculation port number
accordingly. 
(c) Add forwarding rules to the l2_fwd table to forward packets between the traffic
generator and NF server.
(d) You can then use the bf-p4c compiler to generate the binary.


OpenNetVM: The code is taken from their github repository: https://github.com/sdnfv/openNetVM
Code change for enabling explicit payload evictions is in onvm_nflib/onvm_pkt_common.c
file.
