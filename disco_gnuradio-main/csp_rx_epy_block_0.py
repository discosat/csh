"""
Embedded Python Blocks:

Each time this file is saved, GRC will instantiate the first class it finds
to get ports and parameters of your block. The arguments to __init__  will
be the parameters. All of them are required to have default values!
"""

import numpy as np
from gnuradio import gr
import pmt


class blk(gr.sync_block):  # other base classes are basic_block, decim_block, interp_block
    """
    This block srcrambles an input PDU consisting of unpacked bytes.
    The Additive scrambling is compliant with the 255-bit pseudo-randomizer
    desribed in section 10 in CCSDS 131.0-B-5 (TM Blue Book)

    Note: as the scrambler is additive, applying it twice will return
    the original message. 

    PDU_in:  unpacked bits
    PDU_out: scrambled unpacked bits
    """

    def __init__(self):  # only default arguments here
        """arguments to this function show up as parameters in GRC"""
        gr.sync_block.__init__(
            self,
            name='CCSDS Additive Scrambler',   # will show up in GRC
            in_sig=None,
            out_sig=None
        )

        self.pn_lut = np.zeros(255, dtype=np.uint8)
        self.generate_pn_lut()

        self.message_port_register_in(pmt.intern('PDU_in'))
        self.message_port_register_out(pmt.intern('PDU_out'))
        self.set_msg_handler(pmt.intern('PDU_in'), self.handle_msg)


    def handle_msg(self, msg):
        bitstream = np.array(pmt.to_python(pmt.cdr(msg)))
        scr_bitstream = np.zeros(len(bitstream), dtype=np.uint8) 
        for i in range(len(bitstream)):
            scr_bitstream[i] = np.uint8(bitstream[i]) ^ np.uint8(self.pn_lut[i%255])

        #Convert the scrambled bitstream to PDU
        outgoing_msg = pmt.init_u8vector(len(scr_bitstream),(scr_bitstream))
        pdu = pmt.cons(pmt.make_dict(), outgoing_msg)

        self.message_port_pub(pmt.intern('PDU_out'), pdu)
    
    def generate_pn_lut(self):

        #Define shift register
        sr = 0b11111111
        
        #Update shift register
        for i in range(255):
            self.pn_lut[i] = sr & 1
            nb = self.pn_xor(sr)
            sr = sr >> 1
            sr = sr | (nb << 7)
            
            
    def pn_xor(self, sr):
        return (((sr & 0b01) >> 0) ^ ((sr & 0b00001000) >> 3) ^ ((sr & 0b0010000) >> 4) ^ ((sr & 0b10000000) >> 7)) & 1
