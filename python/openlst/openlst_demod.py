#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023 Robert Zimmerman.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

import pmt
import numpy as np
from gnuradio import gr

from libopenlst import frame

from .fec import decode_fec_chunk
from .whitening import pn9, whiten
from .crc import crc16

class openlst_demod(gr.sync_block):
    """
    OpenLST Decoder/Deframer

    This block decodes a raw RF packet in the form:


    To an RF message:

        | Preamble | Sync Word(s) | Data Section |

    Where "Data Section" contains:

        | Length (1 byte) | Flags (1 byte) | Seqnum (2 bytes) | Data (N bytes) | HWID (2 bytes) | CRC (2 bytes)

    Into a message in the form:

        | HWID (2 bytes) | Seqnum (2 bytes) | Data (N bytes) |

    The Data Section may be 2:1 Forward-Error Correction (FEC) encoded, in which
    case bit errors can be corrected. PN-9 decoding is also supported.

    flags_mask and flags can be used to filter out messages, for example
    to exclude messages from the ground transmitter in half-duplex mode.
    """
    def __init__(
        self,
        preamble_bytes=4,
        preamble_quality=30,
        sync_byte1=0xd3,
        sync_byte0=0x91,
        sync_words=2,
        flags_mask=0x80,
        flags=0,
        fec=True,
        whitening=True,
    ):
        gr.sync_block.__init__(
            self,
            name='CC1110 Decode and Deframe',
            in_sig=[np.uint8],
            out_sig=None,
        )
        # Messages are sent in raw form without a length or CRC
        self.message_port_register_out(pmt.intern('message'))

        self.preamble = [int(i) for i in "10101010" * preamble_bytes]
        self.preamble_quality = preamble_quality
        self.sync_word = bytes([sync_byte1, sync_byte0] * sync_words)
        self.flags_mask = flags_mask
        self.flags = flags
        self.fec = fec
        self.whitening = whitening
        self._socket = None

        self._buff = []
        self._mode = 'search'
        self._length = 0
        self._sync_bits = len(self.sync_word) * 8

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
            while len(self._buff) >= len(self.preamble):
                # identify number of preamble bits that match expected pattern
                matched = sum(ex == ac for ex, ac in zip(self.preamble, self._buff))

                # indicates a preamble match of required quality or better
                if self._buff[0] == 1 and matched >= self.preamble_quality:
                    break

                # continue searching through buffer
                else:
                    self._buff.pop(0)

            # reaching this point means we have matched enough of a preamble to check for sync words

            syncbuff = self._buff[len(self.preamble):]
            if len(syncbuff) >= self._sync_bits:
                sw = bytes([
                    bitcast(syncbuff[i:i + 8]) for i in range(0, self._sync_bits, 8)
                ])
                if sw == self.sync_word:
                    if self.fec:
                        self._mode = 'lengthfec'
                    else:
                        self._mode = 'length'
                    self._buff = syncbuff[self._sync_bits:]

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
                    cf, flags = parse_client_frame(data)
                except CRCError as c:
                    pass
                else:
                    if flags & self.flags_mask == self.flags:
                        self.send(cf)

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
                    cf, flags = parse_client_frame(data)
                except CRCError as c:
                    pass
                else:
                    if flags & self.flags_mask == self.flags:
                        self.send(cf)
                self._mode = 'search'

    def send(self, frm: frame.ClientFrame):
        pkt = frm.to_bytearray()
        pkt_pmt = pmt.init_u8vector(len(pkt), list(pkt))
        self.message_port_pub(pmt.intern('message'), pkt_pmt)


class CRCError(Exception):
    def __init__(self, expected, actual):
        self.expected = expected
        self.actual = actual

    def __str__(self):
        return f"CRCError: Expected {self.expected:04x} got {self.actual:04x}"


def parse_client_frame(raw: bytes):
    """Convert an OpenLST space frame (sans length field) to a client frame"""
    want_checksum = crc16(bytes([len(raw)]) + raw[:-2])

    buf = bytearray(raw)
    flags, buf = buf[0], buf[1:]

    cf = frame.ClientFrame()
    cf.sequence_number = frame.pop_short(buf)
    cf.destination = frame.pop_uchar(buf)
    cf.command_number = frame.pop_uchar(buf)
    cf.message, buf = buf[:len(buf) - 4], buf[-4:]
    cf.hardware_id = frame.pop_short(buf)

    got_checksum = frame.pop_short(buf)
    if got_checksum != want_checksum:
        raise CRCError(want_checksum, got_checksum)

    return cf, flags

def bitcast(bitlist):
    """convert a list of bits to a byte/bytes"""
    out = 0
    for bit in bitlist:
        out = (out << 1) | bit
    return out
