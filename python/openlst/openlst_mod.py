#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023 Robert Zimmerman.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

import pmt
import time
import numpy as np
import logging as logger
from gnuradio import gr

from satcom.openlst import client_packet_lib
from satcom.openlst import space_packet_lib
from satcom.openlst.fec import encode_fec
from satcom.openlst.whitening import whiten


class openlst_mod(gr.sync_block):
    """
    OpenLST Encoder/Framer

    This block accepts Gnuradio Messages containing complete
    OpenLST client frames. It then translates each client frame
    into a corresponding space frame, and applies any configured
    whitening/FEC.

    Please see github.com/antaris-inc/python-satcom for documentation
    as well as the library used to work with various OpenLST messages.

    It supports throttling of the output data rate for low bitrates. This avoids filling up the
    (very large) buffer of the downstream blocks and inducing a lot of latency.

    Null/zero bytes are written to the output of this Gnuradio block at the
    configured bitrate.

    """
    def __init__(
            self,
            fec=True,
            whitening=True,
            bitrate=7415.77,
            max_latency=0.1,
        ):
        gr.sync_block.__init__(
            self,
            name="OpenLST Encode and Frame",
            in_sig=None,
            out_sig=[np.uint8],
        )
        # Messages arrive in raw form without a length or CRC
        self.message_port_register_in(pmt.intern('message'))
        self.set_msg_handler(pmt.intern('message'), self.handle_msg)

        self.fec = fec
        self.whitening = whitening

        self._msg_buffer = []
        self._partial = False

        self.bitrate = bitrate
        if self.bitrate != 0:
            # Attempt to set the output buffer to about 1 packet
            # this will be rounded to the nearest system page size, however,
            # which can be 4KB or 16KB and may produce a warning
            self.set_max_output_buffer(0, 255)

        self.max_latency = max_latency
        self._bytes_sent = 0
        self._last_buff_check = None

    def handle_msg(self, msg):
        input_b = bytes(pmt.to_python(msg))

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

        # NOTE(bcwaldon): explicitly skipping checking sp.err as we assume
        # that the client packet will result in valid input to space packet.

        output_b = sp.to_bytes()

        if self.whitening:
            output_b = whiten(output_b)
        if self.fec:
            output_b = encode_fec(output_b)

        output_b = space_packet_lib.SPACE_PACKET_PREAMBLE + space_packet_lib.SPACE_PACKET_ASM + output_b

        # Queue encoded message for transmission
        self._msg_buffer.append((time.time(), list(output_b)))

    def work(self, input_items, output_items):
        if self._last_buff_check is None:
            self._bytes_sent = 0
            self._last_buff_check = time.time()

        if len(self._msg_buffer) > 0:
            recv_time, msg = self._msg_buffer[0]
            # Try to send the whole message, but send a chunk for now
            # if the output buffer is too small (unlikely given our message size)
            bytes_out = min(len(msg), len(output_items[0]))
            # Write the bytes
            output_items[0][:bytes_out] = msg[:bytes_out]

            # Save the rest for next iteration
            remaining = msg[bytes_out:]
            if len(remaining) > 0:
                self._partial = True
                self._msg_buffer[0] = (recv_time, remaining)
            else:
                # Message complete
                self._partial = False
                self._msg_buffer.pop(0)

            # Keep track of bytes sent so we can estimate bitrate
            self._bytes_sent += bytes_out
            return bytes_out
        elif self.bitrate:
            # If the user has set a target bitrate, try not to exceed it
            # by more than a little bit
            dt = max(time.time() - self._last_buff_check, 0.001)

            # Decide how much fill is missing to reach the target bitrate
            expected_bytes = int(self.bitrate * dt // 8)
            latency_buff_bytes = int(self.bitrate * self.max_latency // 8)
            fill = expected_bytes + latency_buff_bytes - self._bytes_sent
            if fill < 0:
                # Try to fill the buffer to catch up
                bytes_out = min(len(output_items[0]), fill)
            else:
                # Just send one byte, but wait a little and throttle the flow
                # so we don't just fill the buffer one byte at a time
                time.sleep(1.02 * 8.0 / self.bitrate)
                bytes_out = 1

            output_items[0][:bytes_out] = 0
            self._bytes_sent += bytes_out
            return bytes_out
        else:
            # Return fill data without throttle
            output_items[0][0] = 0
            self._bytes_sent += 1
            return 1
