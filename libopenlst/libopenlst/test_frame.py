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

import unittest

from libopenlst import frame


class TestClientFrame(unittest.TestCase):
    def test_to_bytearray(self):
        frm = frame.ClientFrame()
        frm.hardware_id = 1023
        frm.sequence_number = 1
        frm.destination = 253
        frm.command_number = 56
        frm.message = bytes(b'\x0a\x0b\x0c\x0d')

        want = bytearray(b'\x0b\xff\x03\x01\x00\xfd\x38\x0a\x0b\x0c\x0d')
        got = frm.to_bytearray()

        self.assertEqual(want, got)

    def test_from_bytearray(self):
        arg = bytearray(b'\x0d\xff\x03\x04\x00\xfd\x38\x01\x02\x03\x04\x05\x06')

        want = frame.ClientFrame(
            hardware_id = 1023,
            sequence_number = 4,
            destination = 253,
            command_number = 56,
            message = bytes(b'\x01\x02\x03\x04\x05\x06'),
        )

        got = frame.ClientFrame.from_bytearray(arg)
        self.assertEqual(want, got)
