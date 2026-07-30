"""
Embedded Python Blocks:

Each time this file is saved, GRC will instantiate the first class it finds
to get ports and parameters of your block. The arguments to __init__  will
be the parameters. All of them are required to have default values!
"""

import numpy as np
from gnuradio import gr
import pmt


class blk(gr.basic_block):  # other base classes are basic_block, decim_block, interp_block
    """
    This block takes packed bits and looks for 5 consequitive 1 bits,
    which upon discovy a 0 bit it inserted right after the 5 consequitive bits. 

    PDU_in: unpacked RS-FEC and scrambled bits
    PDU_out: unpacked bits ready to be transmitted
    """

    def __init__(self):  # only default arguments here
        """arguments to this function show up as parameters in GRC"""
        gr.basic_block.__init__(
            self,
            name='DISCO HDLC Framer',   # will show up in GRC
            in_sig=None,
            out_sig=None,
        )
        # if an attribute with the same name as a parameter is found,
        # a callback is registered (properties work, too).
        self.message_port_register_in(pmt.intern('PDU_in'))
        self.message_port_register_out(pmt.intern('PDU_out'))
        self.set_msg_handler(pmt.intern('PDU_in'), self.handle_msg)

    def handle_msg(self, msg):
        #Get bytestream from PDU
        bitstream = np.array(pmt.to_python(pmt.cdr(msg))) 

        #Define various sequences and flags
        preamble = np.array([1,0,1,0,1,0,1,0]) #34 times in the beginning
        HDLC_flag = np.array([0,1,1,1,1,1,1,0]) #2 times, once before and after msg
        post_HDLC_preamble = preamble
        postamble1 = np.array([0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1])
        postamble2 = np.array([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,1,1])

        total_preamble = np.array([])

        for i in range(34):
            total_preamble = np.append(total_preamble,preamble)

        bits_to_be_transmitted = np.concatenate((total_preamble[:-1],HDLC_flag,post_HDLC_preamble,bitstream,HDLC_flag,postamble1,postamble2))
        
        #Convert the stuffed bitstream to PDU
        outgoing_msg = pmt.init_u8vector(len(bits_to_be_transmitted),(bits_to_be_transmitted.astype(np.uint8)))
        pdu = pmt.cons(pmt.make_dict(), outgoing_msg)

        self.message_port_pub(pmt.intern('PDU_out'), pdu)




