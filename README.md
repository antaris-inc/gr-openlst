# GNURadio OpenLST Module

This repo contains GNURadio blocks for [GNURadio](https://www.gnuradio.org) that can be used to send and receive packets to an [OpenLST](https://github.com/OpenLST/openlst) device. It includes a GNURadio "Out of Tree (OOT)" Module for the OpenLST as well as an example gnuradio-companion project that can talk to the baseline OpenLST board with cheap SDRs.

This has been tested with an Ettus B200 (RX/TX) and a Nooelec v5 NESDR (RX). Other SDRs have not been tested but should work.

## Installation

Installing gnuradio, SDR drivers, and these modules can be quite an experience. See the [Install Guide](./INSTALL.md) for tips.

## GNURadio Blocks

This module contains two blocks, one for encoding and one for decoding.

These blocks do the bulk of the work converting a message from a client into an RF frame that matches the CC1110's over-the-air format, as well as the reverse. There are several configuration options. The defaults should match the the OpenLST defaults.

**Enable FEC**: If enabled, the output data is encoded with Forward-Error Correction (FEC). See the FEC section below. The default is True, matching the OpenLST's default mode. The OpenLST's ranging mode does not use FEC.

**Enable data whitening**: If enabled, output data is "whitened" to avoid bias in the signal. See the Whitening section below. The OpenLST's modes use whitening.

For the encoder, there are additional parameters:

**Target bitrate**: If this is set, the block will attempt to throttle the output data to match the desired bitrate. If set to 0, there will be no throttling and the block will produce unlimited fill data (0s) if there are no packets to encode.

But why though?

Probably a fundamental misunderstanding of gnuradio principles by the author! But this addresses a real problem. The OpenLST bitrates can be fairly low. The default mode is 7415.77bps. GNURadio flowgraphs work by trying to fill input buffers from downstream blocks. The *minimum* size for a buffer is the system memory block size. On many Linux systems this is 4KB. On an M1 Mac, this is 16KB. If this buffer is full when a new packet message arrives, this can be 4-16 seconds(!) of latency before the encoded packet arrives downstream. When the target bitrate is set, the block will throttle fill data to attempt to keep the downstream buffer close to empty without stalling the pipeline.

So what should I do?

If the bitrate is low (<150kbps), it's probably best to set this parameter to match. For high bitrates, it's probably better to set to 0 to avoid underruns.

**Target latency (s)**: If the target bitrate is set (not 0) this parameter determines how much of the downstream buffer to fill. It attempts to keep about the latency target worth of fill in the downstream buffer.

For the decoder, there are additional parameters:

**Minimum preamble bits**: Similar to the `MDMCFG2` register on the CC1110, this sets the minimum number of preamble bits that need to match for the decoder to detect the start of the packet. The default is 30, so 30 out of 32 bits must match the preamble sequence at the start of a packet.

## Example Flowgraph

A sample flowgraph will be included in a future update.

## Forward-Error Correction (FEC)

2:1 Viterbi encoding is supported by the CC1110. Additionally, when FEC is enabled, the data is interleaved to avoid bursty errors. The OpenLST uses this encoding mode for its default radio mode. Ranging modes do **not** use FEC. FEC effectively halves the data rate by roughly doubling the packet size.

Only the data segment (length, data, HWID, and CRC) of the packet are encoded. The preamble and sync words are not encoded.

There is a note in the CC1110 datasheet that the chip does not support variable length packets with FEC enabled. In practice this does not appear to be an issue. It's likely that the CC1110 would fail to receive any FEC-encoded packets with a length less than one or two FEC blocks (4-8 bytes). OpenLST messages are all at least 9 bytes.

This module contains both an encoder and decoder, ported to Python from the CC1110 application notes.

## Whitening

A PN9 code can be applied to reduce DC bias in the output signal. This encoding is symmetric (encode == decode). OpenLST modes use whitening.

Only the data segment (length, data, HWID, and CRC) of the packet are encoded. The preamble and sync words are not encoded.

Counterintuitively, FEC is done *after* whitening per the CC1110 spec. This is probably not ideal, but it is the way the CC1110 works.

# Copyrights and Licensing

The original codebase here was released by Robert Zimmerman through
https://github.com/rzimmerman/gr-openlst, and carries this copyright:

```
Copyright (C) 2023  Robert Zimmerman

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
``

Further modifications have been made by the team at Antaris, Inc and
are released under the same GPL-3.0 License.
