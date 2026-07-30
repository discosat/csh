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
    Remove stuffed bits from a message i.e, the bits followed by 
    five consequitive ones. 
    '''
    def __init__(self):
        gr.basic_block.__init__(
            self,
            name="Bit de-stuffer",
            in_sig=None,
            out_sig=None)


        self.message_port_register_in(pmt.intern('msg_in'))
        self.message_port_register_out(pmt.intern('pdu_out'))
        self.set_msg_handler(pmt.intern('msg_in'), self.handle_msg)

    def handle_msg(self, msg):
        #Get bitstream from message
        bitstream = np.array(pmt.to_python(msg)) 
        

        """Remove one bit preceded by five consequitive ones"""
        compare_array = np.array([1,1,1,1,1])


        for i in range(len(bitstream)-5):
            if np.array_equal(bitstream[i:i+5],compare_array):
                #Mark stuffed bits such that they can be removed later
                #If they are removed now, the for loop will delete all
                #consequtive bits if 1111101 is received
                bitstream[i+5] = 2


        bitstream_destuffed = np.delete(bitstream, np.where(bitstream == 2))

        #Convert destuffed frame to PMT
        outgoing_msg = pmt.init_u8vector(len(bitstream_destuffed),(bitstream_destuffed))
        pdu = pmt.cons(pmt.make_dict(), outgoing_msg)

        self.message_port_pub(pmt.intern('pdu_out'), pdu)