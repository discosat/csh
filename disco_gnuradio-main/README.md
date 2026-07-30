# disco_gnuradio


## Introduction
This repo has been created by Thomas Hansen at SDU, and contains flowgraphs which can transmit (TX) or receive (RX) csp packets with framing and modulation compatible with DISCO1, which again is loosely based upon the CCSDS TM recommandation.

Right now, the TX flowgraph transmits a CSP ping every five seconds, which can be demodulated, deframed and decoded with the RX flowgraph.

## Dependencies
GNU Radio 3.10.x

gr-satellites, url: https://github.com/daniestevez/gr-satellites (just pull the main branch)
gr-predict-doppler, url: https://github.com/ghostop14/gr-gpredict-doppler (for Doppler correction on TX - just disable the block if not needed)

Note: most of the custom blocks are embedded python blocks, which means that no other out-of-tree modules (OOT) are nessescary. The source code for each block can be viewed and modified by opening the block in GRC.

# Usage
As of now, the flowgraphs have only been tested using SDR <--> SDR links, which means the waveform is potentially incompatible with SpaceInventor RF equipment, we will have to test this. Best result have been achieved with HackRF for RX and bladeRF for TX.

## RX
A number of SDRs can be used as the source block for the RX flowgraph (.grc). Note that the center frequency should be at 437.5 MHz in order to avoid DC offsets from e.g., the HackRF. The sampling rate is currently configured to 8Msps, which means the RTL-SDR cannot be used in the current configuration. To configure for the RTL-SDR, the sampling frequency should be set appropiately (no less than 1msps), and adjust the decimation in the Xlating block, such that the Quadrature Demodulator gets 80ksps, which it expects. The RTL-SDR support is ready for in the RX flowgraph if the source and xlating blocks are enabled. Note however that it is recommended to use the HackRF as it is a superior instrument compared to the RTL-SDR.

Decoded csp data from any valid csp packet will be displayed in the terminal along with corrected RS errors.

## TX
The TX flowgraph (.grc) is set up to 1.2Msps, which should be adequate for most TX capable SDRs. The only thing that really needs to be adjusted by the user for now is the Message strobe block, which is set up to send a ping from the ground station to the satellite radio. Both parameters can easily be changed. The TX blocks can be adjusted an enabled (E) for either the HackRF and BladeRF. both have been tested, with the bladeRF giving the best results. 

## CSP packet data
use the following csp data to transmit depending on the test case:

Ping GS --> DISC01 Radio: 0x80,0x81,0x02,0xC8,0x15,0x41,0x00,0x00,0x00,0x00

Ping DISCO1 Radio --> GS: 0x80,0xB2,0x02,0x05,0x50,0x41,0x00,0x00,0x00,0x00

These packets have been extracted from a recorded ping correspondence between the GS and DISC01 prior to launch. Both are preconfigured in the TX flowgraph and can be enabled/disabled by selecting the block and pressing E or D. 

## A Brief Note on Burst Transmission with SDRs
The TX flowgraph does not generate any IQ samples between CSP packet bursts. This behavior can leave an SDR in an undefined state where the internal DAC get locked and will possibly transmit an unmodulated carrier. Please beware of this and modify the flowgraph to the needs of your SDR. The current setup is made for BladeRF, which relies on tags to start and stop burst transmissions. For other SDRs additional zeros (0+j0) can be appended to the burst if a continuous stream is needed. This is done in the Burst shaper block by adjusting the post padding length.

 
