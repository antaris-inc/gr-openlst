# Copyright 2024 Antaris Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import struct

from pydantic import BaseModel


HEADER_LEN = 7

class ClientFrame(BaseModel):
    hardware_id: int = 0
    sequence_number: int = 0
    destination: int = 0
    command_number: int = 0
    message: bytes = None

    @property
    def length(self) -> int:
        return HEADER_LEN + len(self.message)

    @classmethod
    def from_bytearray(cls, dat: bytearray):
        frm = cls()
        _length = pop_uchar(dat)
        frm.hardware_id = pop_short(dat)
        frm.sequence_number = pop_short(dat)
        frm.destination = pop_uchar(dat)
        frm.command_number = pop_uchar(dat)
        frm.message = bytes(dat)

        if len(frm.message) != _length - HEADER_LEN:
            raise ValueError('length field mismatch')

        return frm

    def to_bytearray(self) -> bytearray:
        frm = bytearray()
        append_uchar(frm, self.length)
        append_short(frm, self.hardware_id)
        append_short(frm, self.sequence_number)
        append_uchar(frm, self.destination)
        append_uchar(frm, self.command_number)
        frm += self.message

        return frm


def append_uchar(dat, val):
    dat += struct.pack('<B', val)

def pop_uchar(dat):
    val = struct.unpack('<B', dat[0:1])[0]
    del dat[0:1]
    return val

def append_short(dat, val):
    dat += struct.pack('<h', val)

def pop_short(dat):
    val = struct.unpack('<h', dat[0:2])[0]
    del dat[0:2]
    return val


