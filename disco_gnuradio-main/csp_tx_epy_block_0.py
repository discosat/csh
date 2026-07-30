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

    PDU_in: packed bits (bytes)
    PDU_out: unpacked bits
    """

    def __init__(self):  # only default arguments here
        """arguments to this function show up as parameters in GRC"""
        gr.basic_block.__init__(
            self,
            name='Bit stuffer',   # will show up in GRC
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
        bytestream = np.array(pmt.to_python(pmt.cdr(msg))) 

        #Convert from bytestream to bitstream
        bitstream = self.bytes_to_bits(bytestream)

        #Stuff the bitstream
        stuffed_bitstream = self.bit_stuffing(bitstream)
        
        #Convert the stuffed bitstream to PDU
        outgoing_msg = pmt.init_u8vector(len(stuffed_bitstream),(stuffed_bitstream))
        pdu = pmt.cons(pmt.make_dict(), outgoing_msg)

        self.message_port_pub(pmt.intern('PDU_out'), pdu)

    def bytes_to_bits(self, byte_array):
        
        #Create empty list to hold the binary values
        binary_list = []

        #Loop over the byte array to extract the bits from each byte
        for byte in byte_array:
            #remove the 0b formatting by using the slice function
            binary_str = bin(byte)[2:] 

            #insert zero padding in order to verify leading zeros are present
            binary_str = binary_str.zfill(8)

            #Insert bits into the binary list one at a time
            binary_list.extend([int(bit) for bit in binary_str])
        
        #Convert list to numpy array
        binary_array = np.array(binary_list)

        return binary_array
    
    def bit_stuffing(self, non_stuffed_array, max_consecutive_ones=5, stuff_bit=0):
        #create stuffed array to hold the new bitstream
        stuffed_array = []

        consecutive_ones_counter = 0

        #loop over the non stuffed array
        for bit in non_stuffed_array:
            if bit == 1:
                consecutive_ones_counter += 1
                if consecutive_ones_counter == max_consecutive_ones:
                    stuffed_array.extend([bit])
                    stuffed_array.extend([int(stuff_bit)])
                    consecutive_ones_counter = 0
                else:
                    stuffed_array.extend([bit])
            else:
                stuffed_array.extend([bit])
                consecutive_ones_counter = 0

        return np.array(stuffed_array)


