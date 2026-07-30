import numpy as np
from gnuradio import gr
import pmt
import zmq
import threading

class ZMQ_source(gr.basic_block):
    """
    A ZeroMQ SUB source block that receives data from a specified ZeroMQ endpoint.
    """
    def __init__(self, connection_str):
        gr.basic_block.__init__(self,
            name="ZMQ_source",
            in_sig=None,
            out_sig=None)
        
        self.message_port_register_out(pmt.intern('PDU_out'))  # Register an output message port
        self.running = threading.Event()
        self.running.set()

        self.context = zmq.Context()
        self.subscriber = self.context.socket(zmq.SUB)
        self.subscriber.bind(connection_str)
        self.subscriber.setsockopt(zmq.SUBSCRIBE, b"")
        self.subscriber.setsockopt(zmq.LINGER, 0)

        self.thread = threading.Thread(target=self.receive_msg)
        self.thread.daemon = True
        self.thread.start()

    def receive_msg(self):
        while self.running.is_set():
            try:
                message = self.subscriber.recv()
                pdu = pmt.init_u8vector(len(message), np.frombuffer(message, dtype=np.uint8))
                self.message_port_pub(pmt.intern('PDU_out'), pmt.cons(pmt.PMT_NIL, pdu))
            except zmq.error.ContextTerminated:
                break

    def stop(self):
        self.running.clear()
        self.subscriber.close()
        self.context.term()
        self.thread.join()
        return True
