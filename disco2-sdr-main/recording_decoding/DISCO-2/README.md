# DISCO 2 SDR Decoding Documentation

This folder contains different examples of working decoding pipelines for the DISCO-2 recordings.

> [!NOTE]
> The pipeline remains incomplete until a ZMQ block is added and then connected to a running CSH instance, however, the decoding itself is working and I am working on implementing the final part.


## Decoding Pipeline 

I am no FM or signal expert, far from it in fact! However, I will do my best to explain the current working UHF decoding pipeline through the `.grc` file example in the `ITUGS_recording_decode` folder. 

While it is beginner friendly, it assumes some previous knowledge of GNURadio, for that I really recommend the [tutorial section of the GNURadio Wiki](https://wiki.gnuradio.org/index.php/Tutorials).

Here I mainly focus on the blocs that need input from the user.

All folders in this section contain examples of decoding of the following:

- DISCO-2's ping recorded in the Aarhus University
- DISCO-2's pass recorded by PE0SAT
- DISCO-2's pass recorded by ITU Ground Stations (ITUGS)

## Info on DISCO-2's transmission and ITUGS Recordings 

### DISCO-2's Transmissions

The satellite transmits at 437.075 MHz using GFSK at 4800 baud.

Each frame starts with a 40-bit syncword, followed by an HDLC-framed payload.

This payload is scrambled via an CCSDS additive and protected by shortened ReedSolomon encoding (255,223).

### ITUGS Recordings 

Currently, the ITUGS is doing recordings with the following set-up and settings:

- Yagi antenna with LNA and Rotor
- `Roctl`
- USRP B205mini-i
- GQRX for recording and GPredict for Doppler correction and rotor control 
- 437.075 Mhz base band
- 500.000 Mhz sample rate

## Pipeline 

The current pipeline loads a `.raw` file recorded via gqrx via the `File Source` block. The first step is to doppler correct this recording

### Doppler Correction 

The [`Doppler Correction`](https://destevez.net/2022/07/real-time-doppler-correction-with-gnu-radio/) bloc by Daniel Estevez requires two parameters:

- A `doppler.txt` 
    - **Without TLE**: This file can be generated without a TLE with the `generate_doppler.py` script in the helper scripts folder 
    - **With TLE**: Here is [an example by Estevez](https://github.com/daniestevez/gr-satellites/blob/main/examples/doppler_correction/tle_to_doppler_file.py)
- A `Start Time`
    - This field should be filled in with the first value timestamp value of the `doppler.txt` file, it must be in UNIX format.

> The `samp_rate` at this point is the same as the original file, using the ITUGS recording, this would be 500.000 Mhz

### Decimation and Filtering

Once the recording has been doppler corrected, we then decimate and apply filter it to focus only in the bandwidth relevant to the transmission.

For this we use the `Frequency Xlating FIR Filter`(https://wiki.gnuradio.org/index.php/Frequency_Xlating_FIR_Filter). In combination with the `filter_bw` GUI Range bloc, you can see how the filter affects the corrected recording in the cascade.

After decimation, the `samp_rate` changes. In the [DISCO-1 documentation, we are told that the _"adjust the decimation in the Xlating block, such that the `Quadrature Demodulator` gets 80ksps"_](https://github.com/discosat/disco_gnuradio), and while this remains true, the `Quadrature Demodulator` does not actually require 80ksps according to my testing.

When setting decimation, the only requirement is that the resulting `samp_rate` after decimation stays above 9600 Mhz in line with the Nyquist-Shannon sampling theorem. In my testing, any decimation that leads to a `samp_rate` below that treshold has either been impossible to decode or threw way more errors.

> [!NOTE]
> Prior to using the doppler correction, I used frequency centering to make sure the recording was on baseband. However, it seems the doppler correction block already aligns the signal to baseband which is why the `center_offset` variable is disabled in the ITUGS recordings decoder.

> The `samp_rate` at this point is reduced due to decimation, following the ITUGS example, the samp_rate is now 50.000 Mhz

### Squelch and AGC 

The `Simple Squelch` bloc allows for blocking any sample that does not meet it's assigned magnitude treshold. 

In my testing, the squelch was quite a hindrance when the signal quality is bad, so it was set to -120dB which effectively disables it (could also be bypassed in GNURadio).

However, in better recordings one can see a marginal upgrade if used at -90dB or -80dB. Whether this is important I still don't know...

The `AGC` bloc was left with the same settings from DISCO-1. I still can't fully explain it

> `samp_rate` stays at 50.000 Mhz

### Quadrature FM demodulatioin

The [`Quadrature demod`](https://wiki.gnuradio.org/index.php/Quadrature_Demod) bloc in GNURadio converts the FM-modulated IQ into real-valued baseband signal.

Still need a bit of learning from my side, my understanding is that the output is directly proportional to the instantaneous frequency deviation which is around 2400Hz for DISCO-2's GFSK... though again not sure what this means

The wiki has a formula for calculating it, in my testing most results of the formula led to a value ~5, so in the end it was harcoded to 5.

> At the end of this block, the pipeline continues through a [`Virtual sink`](https://wiki.gnuradio.org/index.php?title=Virtual_Sink) and the `samp_rate` stays at 50.000 Mhz

### FSK Demodulator 

The [`FSK Demodulator bloc`](https://gr-satellites.readthedocs.io/en/v4.1.0/components.html) demodulates and clock syncs the signal for soft bit output.

This bloc requires two inputs:

- `Baud Rate`: Set to 4800 baud as DISCO-2 transmits on that setting
- `Sample Rate` which should be the sample_rate at _this_ point of the pipeline
    - In the example this is automatically calculated via the `samp_rate/decimation` expression

### Sync and Create PDU (Protocol Data Unit)

This is the final bloc which requires input from the user. To find DISCO-2 packets, the correlator find matches to the `syncword`.

The `syncword` consists of an alternating 01 preamble (28 bits) followed by a unique word `0111111010101010` (12 bits). All together, the `syncword` becomes: `0101010101010101010101010111111010101010`.

The sliding correlator finds matches (with a variable threshold which I recommend up to 2) and then grabs the next `packet length` value in bits as the raw frame.

> [!NOTE]
> In the terrestrial recording of the DISCO-2 and 1 pings, the `packet length` was the same as in the DISCO-1 documentation 689. This was sufficient to decode the ping. However, this value never led to any succesful decoding from the pass recordings of DISCO-2.
>
> When experimenting, I ~doubled it to 1200, which then started generating succesful decodes. If anyone knows the real or maybe a more exact value for this it is greatly appreciated

### The rest of the pipeline 

Most of these are the `epy_block*.py` files generated after runnign the `.grc` file. So the source code can be read there as well.

#### HDLC deframe

The HDLC deframer finds the closing HDLC flag `01111110` within the `packet length`-bit window and returns everything before it.  

The opening flag was already consumed by the sync word detector.

#### Bit de-stuffing

HDLC inserts a 0-bit after every run of five consecutive 1s to prevent data from accidentally containing the flag pattern. The de-stuffer removes these inserted zeros, recovering the original bit sequence.

#### CCSDS additive descramble

Help appreciated here

#### Pack 8 bits → bytes

Groups the unpacked 8 bit array into bytes.

#### Reed-Solomon(255,223) decode

- The received codeword is typically shorter than 255 bytes, so it is zero-padded on the left to form a full 255-byte codeword before decoding.

- After decoding, the padding and 32 parity bytes are stripped, leaving only the corrected payload.

- Can correct up to 16 symbol errors per codeword.
