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
    PDU_in: 1,0,1,0,1,0,1,0 (ex)
    PDU_out: 0xAA
    """

    def __init__(self):  # only default arguments here
        """arguments to this function show up as parameters in GRC"""
        gr.sync_block.__init__(
            self,
            name='Pack 8 bits',   # will show up in GRC
            in_sig=None,
            out_sig=None
        )
        
        self.message_port_register_in(pmt.intern('PDU_in'))
        self.message_port_register_out(pmt.intern('PDU_out'))
        self.set_msg_handler(pmt.intern('PDU_in'), self.handle_msg)


    def handle_msg(self, msg):
        bitstream = np.array(pmt.to_python(pmt.cdr(msg)))
        bytestream = np.packbits(bitstream)


        #Convert the bytestream to PDU
        outgoing_msg = pmt.init_u8vector(len(bytestream),(bytestream))
        pdu = pmt.cons(pmt.make_dict(), outgoing_msg)

        self.message_port_pub(pmt.intern('PDU_out'), pdu)