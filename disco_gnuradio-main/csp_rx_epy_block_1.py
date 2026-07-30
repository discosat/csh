"""
Embedded Python Blocks:

Each time this file is saved, GRC will instantiate the first class it finds
to get ports and parameters of your block. The arguments to __init__  will
be the parameters. All of them are required to have default values!
"""

from gnuradio import gr
import numpy as np
import pmt
 
class msg_block(gr.basic_block):
    '''
    Gets a message with the front HDLC flag removed by the
    'sync and create PDU block' and this block then removes
    the last HDLC flag and sends the prior bitstream
    '''
    def __init__(self):
        gr.basic_block.__init__(
            self,
            name="HDLC Deframer",
            in_sig=None,
            out_sig=None)


        self.message_port_register_in(pmt.intern('msg_in'))
        self.message_port_register_out(pmt.intern('msg_out'))
        self.set_msg_handler(pmt.intern('msg_in'), self.handle_msg)

    def handle_msg(self, msg):
        #Get bitstream from message
        bitstream = np.array(pmt.to_python(pmt.cdr(msg))) 


        hdlc_flag = np.array([0,1,1,1,1,1,1,0])
        hdlc_index = 0
        
        #Find HDLC in bitstream
        for i in range(len(bitstream)-len(hdlc_flag)):
            bitstream_snippet = bitstream[i:i+len(hdlc_flag)]
            if (np.array_equal(bitstream_snippet,hdlc_flag)):
                hdlc_index = i
                break
        
        #localize HDLC frame
        hdlc_frame = bitstream[0:hdlc_index]


        #Convert HDLC frame to PMT
        outgoing_msg = pmt.to_pmt(hdlc_frame)

        self.message_port_pub(pmt.intern('msg_out'), outgoing_msg)