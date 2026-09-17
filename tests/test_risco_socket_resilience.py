"""RiscoSocket: command ids, dead links, disconnects and reconnect pacing.

These tests cover command ownership, framing and session recovery.
"""

import asyncio
import os
import subprocess
import sys
import time
import unittest
import unittest.mock

from helpers_local import (
    LOOP_TIMEOUT,
    CommunicationError,
    FakeWriter,
    FeedReader,
    connected_socket,
    drain,
    patch_timing,
    reset_reconnect_history,
    scripted_reader,
    serve,
    settle,
)
from pyrisco.common import CannotConnectError, OperationError
from pyrisco.local.risco_crypt import RiscoCrypt
from pyrisco.local import risco_socket
from pyrisco.local.risco_socket import MAX_CMD_ID, RiscoSocket




class LateReplyTest(unittest.IsolatedAsyncioTestCase):
  """A reply for a command that already gave up must be dropped quietly."""












  def test_a_plaintext_frame_does_not_turn_encryption_off(self):
    """Keep encryption enabled after a stray plaintext frame so the next command stays encrypted."""
    crypt = RiscoCrypt()
    crypt.set_panel_id(0x15)
    encrypted = bytes(crypt.encode(1, 'ACK', force_crypt=True))
    plain = bytes(RiscoCrypt().encode(2, 'ACK'))

    crypt.decode(encrypted)
    crypt.decode(plain)

    self.assertTrue(crypt.encrypted_panel)

  def test_decoding_an_encrypted_frame_without_the_panel_id_is_unreadable(self):
    crypt = RiscoCrypt()
    crypt.set_panel_id(0x15)
    frame = bytes(crypt.encode(1, 'RID=0015', force_crypt=True))

    self.assertEqual(RiscoCrypt().decode(frame), [None, '', False])



  async def test_a_frame_that_does_not_parse_is_unreadable_not_an_error(self):
    sock = RiscoSocket('host', 1, '1234')
    sock._crypt = RiscoCrypt()
    sock._reader = asyncio.StreamReader()
    sock._reader.feed_data(b'\x02garbage\x03')
    sock._reader.feed_eof()

    self.assertEqual(await asyncio.wait_for(sock._read_command(), LOOP_TIMEOUT), [None, '', False])









class FramingTest(unittest.IsolatedAsyncioTestCase):
  """Frames must be split where they end, whatever bytes they carry."""

  PANEL_ID = 0x15

  def _crypt(self):
    from pyrisco.local.risco_crypt import RiscoCrypt
    crypt = RiscoCrypt()
    crypt.set_panel_id(self.PANEL_ID)
    return crypt

  def _panel_frames(self):
    """Every reply shape a panel sends in a session, under every command id."""
    crypt = self._crypt()
    bodies = ['ACK', 'CLOCK=16/09/2026 12:00', 'N05', 'ZSTT*7=O---', 'ZLBL*12=Front door']
    return [(cmd_id, body, bytes(crypt.encode(cmd_id, body, force_crypt=True)))
            for cmd_id in range(1, MAX_CMD_ID + 1) for body in bodies]

  async def _read_all(self, data, count):
    sock = RiscoSocket('host', 1, '1234')
    sock._crypt = self._crypt()
    sock._reader = asyncio.StreamReader()
    sock._reader.feed_data(data)
    sock._reader.feed_eof()
    return [await asyncio.wait_for(sock._read_command(), LOOP_TIMEOUT) for _ in range(count)]

  async def test_the_trap_this_guards_against_actually_occurs(self):
    """Without real frames ending in DLE DLE END the next test proves nothing."""
    from pyrisco.local.risco_crypt import DLE, END
    trapped = [f for _, _, f in self._panel_frames() if f.endswith(DLE + DLE + END)]
    self.assertTrue(trapped, 'Include a frame ending in an escaped DLE to exercise the boundary.')

  async def test_back_to_back_frames_are_each_read_whole(self):
    """Before, a frame ending in an escaped DLE swallowed the frame after it."""
    frames = self._panel_frames()
    follow = bytes(self._crypt().encode(49, 'ACK', force_crypt=True))

    for cmd_id, body, frame in frames:
      with self.subTest(cmd_id=cmd_id, body=body):
        first, second = await self._read_all(frame + follow, 2)
        self.assertEqual(first[:2], [cmd_id, body])
        self.assertTrue(first[2], 'Preserve the frame boundary so its CRC remains valid.')
        self.assertEqual(second[:2], [49, 'ACK'])


  # Frames from risco-lan-bridge's test suite (test/crypto.test.ts), recorded
  # from panels, not produced by this encoder.
  CAPTURED = [
      ('risco-mqtt-local issue 20', 1, 'utf-8', 3,
       'CUSTLST=0EN;0IT;0IL;0HU;0UK;0SP;0PL;0GR;0BR;0RU;0NL;0FR;0CN;0DK;0CZ;0AU;0TH',
       [2,17,50,54,72,66,124,10,241,41,160,213,224,228,12,190,59,95,121,97,133,34,154,150,106,
        252,61,235,145,22,204,52,47,108,46,198,203,167,163,228,143,56,173,196,206,190,171,201,
        213,152,192,16,16,102,226,20,139,80,135,209,61,60,90,124,95,248,212,107,122,178,70,81,
        44,31,30,235,70,202,161,162,194,154,22,239,16,16,3]),
      ('range query', 1, 'utf-8', 34, 'ZTYPE*17:24= 0\t 5\t 5\t 5\t 5\t 5\t 5\t 5',
       [2,17,49,49,81,67,118,14,248,80,197,223,234,147,118,184,43,38,36,122,128,98,246,152,
        83,148,93,217,129,118,142,47,42,54,94,200,242,215,218,200,137,71,206,203,3]),
      ('risco-lan-bridge issue 4', 1, 'utf-8', 3, 'N05',
       [2,17,50,54,69,39,26,73,132,76,192,217,3]),
      ('latin-1 label', 1, 'latin1', 5, 'SYSLBL=Syst\xe8me S\xe9curit\xe9',
       [2,17,50,48,88,78,124,18,255,54,201,187,169,210,54,109,102,115,13,9,92,8,163,223,51,192,
        129,199,150,119,197,75,3]),
      ('unencrypted', 0, 'utf-8', 2, 'ACK', [2,48,50,65,67,75,23,51,57,65,70,3]),
  ]

  async def test_a_real_panel_frame_does_end_in_an_escaped_dle(self):
    """The framing bug is not hypothetical: issue 20's frame ends DLE DLE END."""
    from pyrisco.local.risco_crypt import DLE, END
    frame = bytes(self.CAPTURED[0][5])
    self.assertTrue(frame.endswith(DLE + DLE + END))

  async def test_frames_captured_from_real_panels_are_read_whole(self):
    from pyrisco.local.risco_crypt import RiscoCrypt
    for name, panel_id, encoding, cmd_id, body, raw in self.CAPTURED:
      with self.subTest(name):
        follow = bytes(RiscoCrypt(encoding).encode(49, 'ACK'))
        sock = RiscoSocket('host', 1, '1234')
        sock._crypt = RiscoCrypt(encoding)
        sock._crypt.set_panel_id(panel_id)
        sock._reader = asyncio.StreamReader()
        sock._reader.feed_data(bytes(raw) + follow)
        sock._reader.feed_eof()

        first = await asyncio.wait_for(sock._read_command(), LOOP_TIMEOUT)
        self.assertEqual(first, [cmd_id, body, True])
        second = await asyncio.wait_for(sock._read_command(), LOOP_TIMEOUT)
        self.assertEqual(second[:2], [49, 'ACK'])

  def test_a_label_in_another_encoding_keeps_its_frame_valid(self):
    """Validate CRC on the received bytes before decoding a label.

    A label that the configured encoding cannot decode must not invalidate
    an otherwise intact frame.
    """
    for name, panel_id, encoding, cmd_id, body, raw in self.CAPTURED:
      if encoding != 'latin1':
        continue
      crypt = RiscoCrypt()  # default encoding
      crypt.set_panel_id(panel_id)

      got_id, text, valid = crypt.decode(bytes(raw))

      self.assertTrue(valid, name)
      self.assertEqual(got_id, cmd_id)
      self.assertEqual(text, body.encode('latin1').decode('utf-8', errors='replace'))

  def test_the_crc_matches_an_independent_crc16_modbus(self):
    """Check the table-driven CRC against an independent bitwise implementation."""
    from pyrisco.local.risco_crypt import RiscoCrypt

    def crc16_modbus(data):
      crc = 0xFFFF
      for byte in data:
        crc ^= byte
        for _ in range(8):
          crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
      return f'{crc:04X}'

    crypt = RiscoCrypt()
    for text in ['01RID\x17', '12ZLBL*7=Front door\x17', '49ACK\x17', 'N05\x17', '']:
      with self.subTest(text=text):
        self.assertEqual(crypt._get_crc(text), crc16_modbus(text.encode()))


def _feed(sock, data):
  """Give the socket a real reader holding `data`, then end of stream."""
  sock._reader = asyncio.StreamReader()
  sock._reader.feed_data(data)
  sock._reader.feed_eof()










def _production_timing():
  return patch_timing(RECONNECT_DELAY=5, STABLE_SESSION=120, MAX_RECONNECT_DELAY=300)




if __name__ == '__main__':
  unittest.main()
