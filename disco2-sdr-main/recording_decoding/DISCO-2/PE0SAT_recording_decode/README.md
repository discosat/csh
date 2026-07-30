# PE0SAT Recordings Decoding

In April 2026, Jan from PE0SAT contacted the DISCO-2 team to ask about the decoding documentation as well as provide very useful data and recordings which ultimately helped set up this pipeline and revamp the documentation. Thanks Jan for reaching out and providing the recordings!

The Gnuradio Companion's file `.grc` is anotated and expects the following packages to be installed in your environment:

- disco_gnuradio
- gr-satellies

To download the `sdrpp_baseband_437075000Hz_2026-04-30T151430.wav` file needed for the GNURadio fileblock, and to see information about the hardware used for recording, you can visit's this [PE0SAT's directory listing](https://pe0sat.vgnet.nl/download/DISCO-2/). 

The expected terminal output is as follows:

```
***** VERBOSE PDU DEBUG PRINT ******
((rs_errors . 0))
pdu length =         74 bytes
pdu vector contents = 
0000: 90 03 54 b1 92 81 06 80 cd 18 40 00 00 ca 42 1a 
0010: e5 2e cd 19 00 ca c3 06 ca fd cd 1a 00 ce 00 40 
0020: 12 c5 cd 1b 00 ce 00 04 95 8a cd 1c 00 ce 00 b8 
0030: 57 c9 cd 1e 00 ca 48 fa e3 1a cd 1f 00 ca 43 40 
0040: 66 66 f9 9a 54 cf 81 7d 4f c3 
************************************
***** VERBOSE PDU DEBUG PRINT ******
((rs_errors . 5))
pdu length =         74 bytes
pdu vector contents = 
0000: 90 03 54 b1 c2 81 06 80 cd 18 40 00 00 ca 42 1a 
0010: e5 2e cd 19 00 ca c3 06 ca fd cd 1a 00 ce 00 40 
0020: 26 4d cd 1b 00 ce 00 04 95 8a cd 1c 00 ce 00 b8 
0030: 57 c9 cd 1e 00 ca 48 fa e3 1a cd 1f 00 ca 43 40 
0040: 66 66 5f 2a 9a 45 8d ee 02 aa 
************************************
***** VERBOSE PDU DEBUG PRINT ******
((rs_errors . 0))
pdu length =         74 bytes
pdu vector contents = 
0000: 90 03 54 b2 22 81 06 80 cd 18 40 00 00 ca 42 1a 
0010: e5 2e cd 19 00 ca c3 06 ca fd cd 1a 00 ce 00 40 
0020: 4d 5d cd 1b 00 ce 00 04 95 8a cd 1c 00 ce 00 b8 
0030: 57 c9 cd 1e 00 ca 48 fa e3 1a cd 1f 00 ca 43 40 
0040: 66 66 a9 1c 3d 18 f3 ed 58 4d 
************************************
***** VERBOSE PDU DEBUG PRINT ******
((rs_errors . 0))
pdu length =         74 bytes
pdu vector contents = 
0000: 90 03 54 b1 42 81 06 80 cd 18 40 00 00 ca 42 1a 
0010: e5 2e cd 19 00 ca c3 06 ca fd cd 1a 00 ce 00 40 
0020: 74 6d cd 1b 00 ce 00 04 95 8a cd 1c 00 ce 00 b8 
0030: 57 c9 cd 1e 00 ca 48 fa e3 1a cd 1f 00 ca 43 40 
0040: 66 66 e7 7f 55 54 d7 0d 59 c9 
************************************
***** VERBOSE PDU DEBUG PRINT ******
((rs_errors . 0))
pdu length =         74 bytes
pdu vector contents = 
0000: 90 03 54 b1 a2 81 06 80 cd 18 40 00 00 ca 42 1a 
0010: e5 2e cd 19 00 ca c3 06 ca fd cd 1a 00 ce 00 40 
0020: 9f 65 cd 1b 00 ce 00 04 95 8a cd 1c 00 ce 00 b8 
0030: 57 c9 cd 1e 00 ca 48 fa e3 1a cd 1f 00 ca 43 40 
0040: 66 66 d5 7d f7 b9 54 9c ed 0d 
************************************
***** VERBOSE PDU DEBUG PRINT ******
((rs_errors . 0))
pdu length =         74 bytes
pdu vector contents = 
0000: 90 03 54 b2 02 81 06 80 cd 18 40 00 00 ca 42 1a 
0010: e5 2e cd 19 00 ca c3 06 ca fd cd 1a 00 ce 00 40 
0020: c6 75 cd 1b 00 ce 00 04 95 8a cd 1c 00 ce 00 b8 
0030: 57 c9 cd 1e 00 ca 48 fa e3 1a cd 1f 00 ca 43 40 
0040: 66 66 c0 18 37 fe 39 99 fc 37 
************************************
***** VERBOSE PDU DEBUG PRINT ******
((rs_errors . 0))
pdu length =         74 bytes
pdu vector contents = 
0000: 90 03 54 b1 22 81 06 80 cd 18 40 00 00 ca 42 1a 
0010: e5 2e cd 19 00 ca c3 06 ca fd cd 1a 00 ce 00 40 
0020: f1 6d cd 1b 00 ce 00 04 95 8a cd 1c 00 ce 00 b8 
0030: 57 c9 cd 1e 00 ca 48 fa e3 1a cd 1f 00 ca 43 40 
0040: 66 66 c8 5f 29 df a0 3e b6 5c 
************************************
***** VERBOSE PDU DEBUG PRINT ******
((rs_errors . 0))
pdu length =         74 bytes
pdu vector contents = 
0000: 90 03 54 b1 b2 81 06 80 cd 18 40 00 00 ca 42 1a 
0010: e5 2e cd 19 00 ca c3 06 ca fd cd 1a 00 ce 00 41 
0020: 2f ed cd 1b 00 ce 00 04 95 8a cd 1c 00 ce 00 b8 
0030: 57 c9 cd 1e 00 ca 48 fa e3 1a cd 1f 00 ca 43 40 
0040: 66 66 03 df 58 4a ff c3 1f 65 
************************************
***** VERBOSE PDU DEBUG PRINT ******
((rs_errors . 0))
pdu length =         74 bytes
pdu vector contents = 
0000: 90 03 54 b1 e2 81 06 80 cd 18 40 00 00 ca 42 1a 
0010: e5 2e cd 19 00 ca c3 06 ca fd cd 1a 00 ce 00 41 
0020: 43 75 cd 1b 00 ce 00 04 95 8a cd 1c 00 ce 00 b8 
0030: 57 c9 cd 1e 00 ca 48 fa e3 1a cd 1f 00 ca 43 40 
0040: 66 66 ce fe dd 56 b8 ef 89 a3 
************************************
***** VERBOSE PDU DEBUG PRINT ******
((rs_errors . 0))
pdu length =         74 bytes
pdu vector contents = 
0000: 90 03 54 b2 42 81 06 80 cd 18 40 00 00 ca 42 1a 
0010: e5 2e cd 19 00 ca c3 06 ca fd cd 1a 00 ce 00 41 
0020: 6e 6d cd 1b 00 ce 00 04 95 8a cd 1c 00 ce 00 b8 
0030: 57 c9 cd 1e 00 ca 48 fa e3 1a cd 1f 00 ca 43 40 
0040: 66 66 34 0d ec 89 56 cb 26 a0 
************************************
```
