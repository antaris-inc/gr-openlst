#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023 Robert Zimmerman.
# Copyright 2024 Antaris Inc.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

import pmt
import numpy as np
import logging as logger
from gnuradio import gr

from satcom.openlst import client_packet_lib
from satcom.openlst import space_packet_lib
from satcom.openlst.fec import encode_fec
from satcom.openlst.whitening import whiten


class openlst_mod_tagged(gr.sync_block):
    """
    OpenLST Encoder/Framer (Tagged Stream)

    This block accepts Gnuradio Messages containing complete OpenLST client
    frames. It translates each frame into a corresponding space frame, 
    applies whitening/FEC, adds preamble/sync words, and outputs it as 
    a tagged stream.

    Burst Handling:
    - A length tag (default: "packet_len") is added to the first item of 
      each packet.
    - The tag value is scaled to match the expected number of SAMPLES at 
      the USRP sink.
    - Zero-byte padding is appended to the end of the packet to flush 
      downstream filters.
    
    NOTE: This block assumes the output buffer provided by the scheduler 
    is large enough to hold the entire encoded packet at once.
    """
    def __init__(
            self,
            client_format,
            fec=True,
            whitening=True,
            length_tag_name="packet_len",
            samples_per_symbol=2,
            resample_ratio=1.0,
            padding_bytes=2
        ):
        gr.sync_block.__init__(
            self,
            name="OpenLST Encode (Tagged)",
            in_sig=None,
            out_sig=[np.uint8],
        )
        
        # Messages arrive in raw form without a length or CRC
        self.message_port_register_in(pmt.intern('message'))
        self.set_msg_handler(pmt.intern('message'), self.handle_msg)

        self.fec = fec
        self.whitening = whitening
        self.client_format = client_format
        
        # Tagging setup
        self.length_tag_key = pmt.intern(length_tag_name)
        
        # Flush/Padding setup
        self.padding_bytes = padding_bytes
        
        # Output Scaling Calculation:
        self.output_scaling = 8.0 * samples_per_symbol / resample_ratio

        self._msg_buffer = []

    def handle_msg(self, msg):
        input_b = bytes(pmt.to_python(msg))

        if self.client_format == 'CLIENT_PACKET':
            try:
                cp = client_packet_lib.ClientPacket.from_bytes(input_b)
            except Exception:
                logger.exception('failed parsing client packet from input message, discarding')
                return

            if cp.err():
                logger.error(f'ClientPacket validation error: {cp.err()}')
                return

            sp = space_packet_lib.SpacePacket(
                header=space_packet_lib.SpacePacketHeader(
                    sequence_number=cp.header.sequence_number,
                    destination=cp.header.destination,
                    command_number=cp.header.command_number
                ),
                data=cp.data,
                footer=space_packet_lib.SpacePacketFooter(
                    hardware_id=cp.header.hardware_id,
                ),
            )

        elif self.client_format == 'RAW':
            sp = space_packet_lib.SpacePacket(
                data=input_b,
            )
        else:
            raise ValueError('invalid client_format')

        output_b = sp.to_bytes()

        # Apply Physical Layer processing
        if self.whitening:
            output_b = whiten(output_b)
        if self.fec:
            output_b = encode_fec(output_b)

        # Prepend Preamble and Sync Word (ASM)
        output_b = space_packet_lib.SPACE_PACKET_PREAMBLE + space_packet_lib.SPACE_PACKET_ASM + output_b
        
        # Append Padding (Flush downstream filters)
        if self.padding_bytes > 0:
            output_b += bytes([0] * self.padding_bytes)

        # Queue encoded message
        self._msg_buffer.append(list(output_b))

    def work(self, input_items, output_items):
        if len(self._msg_buffer) > 0:
            msg = self._msg_buffer[0]
            
            # --- TAGGING ---
            nwritten = self.nitems_written(0)
            
            # Calculate the burst length in SAMPLES for the USRP
            final_length_samples = int(np.ceil(len(msg) * self.output_scaling))
            
            self.add_item_tag(
                0, 
                nwritten, 
                self.length_tag_key, 
                pmt.from_long(final_length_samples)
            )

            # --- WRITING ---
            # Safety check: ensure we don't overflow the buffer provided by GR
            # (Assumes buffer is large enough for the full packet as requested)
            n_out = min(len(output_items[0]), len(msg))
            
            output_items[0][:n_out] = msg[:n_out]

            # --- CLEANUP ---
            # Remove the message from the queue immediately
            self._msg_buffer.pop(0)

            return n_out
            
        return 0
