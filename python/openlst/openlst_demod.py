#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023 Robert Zimmerman.
# Copyright 2024 Antaris Inc.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

import logging

import pmt
import numpy as np
from gnuradio import gr

from satcom.openlst import client_packet_lib
from satcom.openlst import space_packet_lib
from satcom.openlst.fec import decode_fec_chunk
from satcom.openlst.whitening import pn9, whiten


logger = logging.getLogger()


class openlst_demod(gr.sync_block):
    """
    OpenLST Decoder/Deframer

    This block accepts bytes containing complete OpenLST space frames.
    It translates each space frame into a corresponding client frame,
    after removing any whitening/FEC.

    Please see github.com/antaris-inc/python-satcom for documentation
    as well as the library used to work with various OpenLST messages.

    The preamble_quality flag controls how many preamble bits must match
    before attempting to decode a space packet.

    """
    def __init__(
        self,
        preamble_quality=30,
        fec=True,
        whitening=True,
    ):
        gr.sync_block.__init__(
            self,
            name='OpenLST Decode and Deframe',
            in_sig=[np.uint8],
            out_sig=None,
        )
        self.message_port_register_out(pmt.intern('message'))

        self.preamble_quality = preamble_quality
        self.fec = fec
        self.whitening = whitening

        # map the preamble into a list of integers representing each bit
        self.preamble_bits = [int(i) for i in ''.join([bin(byt)[2:] for byt in space_packet_lib.SPACE_PACKET_PREAMBLE])]

        self._socket = None
        self._buff = []
        self._mode = 'search'
        self._length = 0
        self._sync_bits_len = len(space_packet_lib.SPACE_PACKET_ASM) * 8

    def work(self, input_items, output_items):
        # Each input byte is actually one LSB-encoded bit
        self._buff.extend(input_items[0])

        # Work through as much of the buffer as possible, stopping
        # when it is clear no forward progress is being made
        while True:
            startN = len(self._buff)
            self.loop()
            endN = len(self._buff)
            if startN == endN:
                break

        return len(input_items[0])

    def loop(self):
        # Search through buffer until viable preamble and full sync pattern is found
        if self._mode == 'search':
            # first check for preamble
            while len(self._buff) >= len(self.preamble_bits):
                # identify number of preamble bits that match expected pattern
                matched = sum(ex == ac for ex, ac in zip(self.preamble_bits, self._buff))

                # indicates a preamble match of required quality or better
                if self._buff[0] == 1 and matched >= self.preamble_quality:
                    break

                # continue searching through buffer
                else:
                    self._buff.pop(0)

            # reaching this point means we have matched enough of a preamble to check for sync words

            syncbuff = self._buff[len(self.preamble_bits):]
            if len(syncbuff) >= self._sync_bits_len:
                sw = bytes([
                    bitcast(syncbuff[i:i + 8]) for i in range(0, self._sync_bits_len, 8)
                ])
                if sw == space_packet_lib.SPACE_PACKET_ASM:
                    if self.fec:
                        self._mode = 'lengthfec'
                    else:
                        self._mode = 'length'
                    self._buff = syncbuff[self._sync_bits_len:]

                # no direct match, so will retrigger search process
                else:
                    self._buff.pop(0)

        # Wait for the length byte (potentially whitened)
        elif self._mode == 'length':
            if len(self._buff) >= 8:
                length_byte = bitcast(self._buff[:8])
                if self.whitening:
                    self._pngen = pn9()
                    length_byte = length_byte ^ next(self._pngen)
                self._length = length_byte
                self._mode = 'data'
                self._buff = self._buff[8:]

        # Wait for two chunks of FECed content to decode the length byte
        elif self._mode == 'lengthfec':
            if len(self._buff) >= 64:
                # Variable length mode + FEC is techincally not supported by
                # the CC1110. The OpenLST uses it anyway and it does work with
                # potential caveats around very short messages, probably less than
                # two FEC chunks (8 bytes). These don't come up given that the
                # OpenLST minimum message length is
                # HWID + seqnum + subsys + command + CRC, which is 9 bytes

                # To decode the length byte, wait for two chunks of FEC data
                chunk0 = bytes([bitcast(self._buff[i:i + 8]) for i in range(0, 32, 8)])
                chunk1 = bytes([bitcast(self._buff[i:i + 8]) for i in range(32, 64, 8)])

                # Create the decoder for this packet
                self._decoder = decode_fec_chunk()
                self._decoder.send(None)
                # Decode two chunks
                b = self._decoder.send(chunk0)
                b += self._decoder.send(chunk1)

                # Per the CC1110 datasheet, FEC is done on the whitened data, even
                # though that seems counterintuitive
                if self.whitening:
                    self._pngen = pn9()
                    b = whiten(b, self._pngen)

                # Read the length
                self._length = b[0]
                # Put the rest of the decoded chunks in the buffer
                self._fecbuff = b[1:]
                self._mode = 'datafec'
                self._buff = self._buff[64:]

        elif self._mode == 'data':
            # In non-FEC mode we just decode one byte at a time
            if len(self._buff) >= self._length * 8:
                data = bytes([bitcast(self._buff[i:i + 8]) for i in range(0, self._length * 8, 8)])
                # Remove whitening if necessary
                if self.whitening:
                    data = whiten(data, self._pngen)

                try:
                    self.handle_space_packet(data)
                except Exception:
                    logger.exception('failed handling SpacePacket, discarding')

                # All done - save any extra bits in the buffer and start looking
                # for a new packet
                self._mode = 'search'
                self._buff = self._buff[self._length * 8:]

        elif self._mode == 'datafec':
            # In FEC mode we wait for FEC chunks (4 bytes) and decode them as
            # they arrive until we have enough bytes
            while len(self._buff) >= 32 and len(self._fecbuff) < self._length:
                chunk = bytes([bitcast(self._buff[i:i + 8]) for i in range(0, 32, 8)])
                self._buff = self._buff[32:]

                # Handle FEC (and error correct)
                chunk_defec = self._decoder.send(chunk)

                # Per the CC1110 datasheet, FEC is done on the whitened data, even
                # though that seems counterintuitive
                if self.whitening:
                    chunk_defec = whiten(chunk_defec, self._pngen)
                self._fecbuff += chunk_defec

            if len(self._fecbuff) >= self._length:
                # Full packet is here
                data = self._fecbuff[:self._length]
                try:
                    self.handle_space_packet(data)
                except Exception as exc:
                    logger.exception('failed handling SpacePacket, discarding')

                self._mode = 'search'

    def handle_space_packet(self, data: bytearray):
        sp = space_packet_lib.SpacePacket.from_bytes(bytes([self._length]) + data)
        if sp.err():
            raise ValueError(f'SpacePacket validation error: {sp.err()}')

        cp = client_packet_lib.ClientPacket(
            header=client_packet_lib.ClientPacketHeader(
                sequence_number=sp.header.sequence_number,
                destination=sp.header.destination,
                command_number=sp.header.command_number,
                hardware_id=sp.footer.hardware_id,
            ),
            data=sp.data,
        )
        output_b = cp.to_bytes()

        output_pmt = pmt.init_u8vector(len(output_b), list(output_b))
        self.message_port_pub(pmt.intern('message'), output_pmt)


def bitcast(bitlist):
    """convert a list of bits to a byte/bytes"""
    out = 0
    for bit in bitlist:
        out = (out << 1) | bit
    return out
