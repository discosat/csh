#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024 Thomas Hansen, SDU.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#


import numpy as np
from gnuradio import gr
import pmt
import zmq

class ZMQ_sink(gr.basic_block):
    """
    docstring for block ZMQ_sink
    """
    def __init__(self, connection_str):
        gr.basic_block.__init__(self,
            name="ZMQ_sink",
            in_sig=None,
            out_sig=None)
        
        self.message_port_register_in(pmt.intern('PDU_in'))
        self.set_msg_handler(pmt.intern('PDU_in'), self.handle_msg)

        #Set up ZMQ publisher
        context = zmq.Context()
        self.publisher = context.socket(zmq.PUB)
        self.publisher.bind(connection_str)


    def handle_msg(self, msg):
        unpacked_pdu = np.array(pmt.to_python(pmt.cdr(msg)))
        self.publisher.send(unpacked_pdu.tobytes())

    #### ----------- NOT USED ----------- ####
    def forecast(self, noutput_items, ninputs):
        # ninputs is the number of input connections
        # setup size of input_items[i] for work call
        # the required number of input items is returned
        #   in a list where each element represents the
        #   number of required items for each input
        ninput_items_required = [noutput_items] * ninputs
        return ninput_items_required

    #### ----------- NOT USED ----------- ####
    def general_work(self, input_items, output_items):
        # For this sample code, the general block is made to behave like a sync block
        ninput_items = min([len(items) for items in input_items])
        noutput_items = min(len(output_items[0]), ninput_items)
        output_items[0][:noutput_items] = input_items[0][:noutput_items]
        self.consume_each(noutput_items)
        return noutput_items

