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
    """This block adds tx_sob and tx_eob tags based
        on a length tag on the input stream. This 
        block is intended for BladeRF and the osmocom
        sink
    """

    def __init__(self,):  # only default arguments here
        """arguments to this function show up as parameters in GRC"""
        gr.sync_block.__init__(
            self,
            name='Burst_tagger',   # will show up in GRC
            in_sig=[np.complex64],
            out_sig=[np.complex64]
        )

    def work(self, input_items, output_items):
        
        #copy input stream to output stream
        output_items[0][:] = input_items[0]

        #Get tags in current window
        tags = self.get_tags_in_window(0, 0, len(input_items[0]))

        # loop through all 'detect' tags and store their relative offset
        for tag in tags:
            if (pmt.to_python(tag.key) == 'packet_len'):

                #Add SOB tag
                self.add_item_tag(0, # Write to output port 0
                    tag.offset+1, # Index of the tag in absolute terms
                    pmt.intern("tx_sob"), # Key of the tag
                    pmt.from_bool(True)# Value of the tag                
                )
                        
                #Add EOB tag
                self.add_item_tag(0, # Write to output port 0
                    tag.offset + pmt.to_python(tag.value), # Index of the tag in absolute terms
                    pmt.intern("tx_eob"), # Key of the tag
                    pmt.from_bool(True)# Value of the tag
                )
    
        


        return len(output_items[0])
