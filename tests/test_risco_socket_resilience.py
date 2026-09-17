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

  async def test_reply_for_an_empty_slot_is_ignored(self):
    sock = connected_socket()
    scripted_reader(sock, [(1, 'ACK', True)])

    await asyncio.wait_for(sock._listen(), LOOP_TIMEOUT)

    reported = drain(sock._queue)
    self.assertEqual(len(reported), 1, f'late reply was not ignored: {reported}')
    self.assertIsInstance(reported[0], ConnectionResetError)

  async def test_reply_for_an_already_resolved_future_is_ignored(self):
    sock = connected_socket()
    done = asyncio.get_running_loop().create_future()
    done.set_result('ACK')
    sock._futures[0] = done
    scripted_reader(sock, [(1, 'ACK', True)])

    await asyncio.wait_for(sock._listen(), LOOP_TIMEOUT)

    reported = drain(sock._queue)
    self.assertEqual(len(reported), 1, f'late reply was not ignored: {reported}')


  async def test_panel_refusal_is_a_plain_operation_error(self):
    """Discovery depends on telling a refusal apart from a lost answer."""
    sock = connected_socket()
    pending = asyncio.get_running_loop().create_future()
    sock._futures[0] = pending
    scripted_reader(sock, [(1, 'N05', True)])

    await asyncio.wait_for(sock._listen(), LOOP_TIMEOUT)

    error = pending.exception()
    self.assertIsInstance(error, OperationError)
    self.assertNotIsInstance(error, CommunicationError)


  async def test_a_corrupted_push_is_not_acknowledged(self):
    """Nothing in a corrupted frame can be trusted, not even its id; not
    acknowledging it lets the panel send it again (as risco-lan-bridge does)."""
    sock = connected_socket()
    scripted_reader(sock, [(55, 'ZSTT1=O---', False)])

    await asyncio.wait_for(sock._listen(), LOOP_TIMEOUT)

    self.assertEqual(sock.sent, [])
    reported = drain(sock._queue)
    self.assertIsInstance(reported[0], CommunicationError)
    self.assertNotIn('ZSTT1=O---', reported, 'Discard a corrupted push instead of delivering its status.')






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


  async def test_an_empty_reply_answers_its_command(self):
    """Deliver an empty reply to its caller instead of losing the future and timing out."""
    sock = connected_socket()
    reader = FeedReader(sock)
    listener = asyncio.create_task(sock._listen())
    sock._listen_task = listener
    self.addCleanup(listener.cancel)

    task = asyncio.create_task(sock.send_result_command('PNLCNF'))
    await settle()
    reader.push(1, '')

    with self.assertRaises(CommunicationError) as caught:
      await asyncio.wait_for(task, LOOP_TIMEOUT)
    self.assertIn('Unexpected reply', str(caught.exception))
    self.assertEqual(drain(sock._queue), [])

  async def test_a_frame_that_does_not_parse_is_unreadable_not_an_error(self):
    sock = RiscoSocket('host', 1, '1234')
    sock._crypt = RiscoCrypt()
    sock._reader = asyncio.StreamReader()
    sock._reader.feed_data(b'\x02garbage\x03')
    sock._reader.feed_eof()

    self.assertEqual(await asyncio.wait_for(sock._read_command(), LOOP_TIMEOUT), [None, '', False])

  async def test_a_good_push_is_acknowledged_and_queued(self):
    sock = connected_socket()

    await sock._handle_incoming(55, 'ZSTT1=O---', sock._queue)

    self.assertEqual(sock.sent, [(55, 'ACK')])
    self.assertEqual(drain(sock._queue), ['ZSTT1=O---'])


class SendCommandTest(unittest.IsolatedAsyncioTestCase):

  async def test_timeout_clears_the_slot_and_keeps_its_message(self):
    """HA matches on 'Timeout in command: CLOCK' to downgrade the log line."""
    sock = connected_socket(concurrency=1)
    with patch_timing(COMMAND_TIMEOUT=0.05):
      with self.assertRaises(CommunicationError) as caught:
        await asyncio.wait_for(sock.send_command('CLOCK'), LOOP_TIMEOUT)

    self.assertIn('Timeout in command: CLOCK', str(caught.exception))
    self.assertTrue(all(f is None for f in sock._futures),
                    'A timed-out command must not leave its future in the slot.')

  async def test_a_login_timeout_does_not_expose_the_access_code(self):
    """Redact the login code in timeout errors because consumers may log them."""
    sock = connected_socket(concurrency=1)
    with patch_timing(COMMAND_TIMEOUT=0.05):
      with self.assertRaises(CommunicationError) as caught:
        await asyncio.wait_for(sock.send_ack_command('RMT=5678'), LOOP_TIMEOUT)

    self.assertNotIn('5678', str(caught.exception))
    self.assertIn('RMT=<code>', str(caught.exception))

  async def test_a_reply_without_a_value_is_a_communication_error(self):
    """Report a malformed result as a communication failure rather than an indexing error."""
    sock = connected_socket()
    reader = FeedReader(sock)
    listener = asyncio.create_task(sock._listen())
    sock._listen_task = listener
    self.addCleanup(listener.cancel)

    task = asyncio.create_task(sock.send_result_command('CLOCK'))
    await settle()
    reader.push(1, 'ACK')

    with self.assertRaises(CommunicationError):
      await asyncio.wait_for(task, LOOP_TIMEOUT)

  async def test_a_value_containing_an_equals_sign_is_returned_whole(self):
    sock = connected_socket()
    reader = FeedReader(sock)
    listener = asyncio.create_task(sock._listen())
    sock._listen_task = listener
    self.addCleanup(listener.cancel)

    task = asyncio.create_task(sock.send_result_command('ZLBL*3?'))
    await settle()
    reader.push(1, 'ZLBL*3=A=B')

    self.assertEqual(await asyncio.wait_for(task, LOOP_TIMEOUT), 'A=B')

  async def test_debug_logging_does_not_expose_the_access_code(self):
    sock = connected_socket(concurrency=1)
    sock._crypt = RiscoCrypt()
    del sock._write_command  # the real one, which logs
    with self.assertLogs('pyrisco.local.risco_socket', 'DEBUG') as logs:
      with patch_timing(COMMAND_TIMEOUT=0.05):
        with self.assertRaises(CommunicationError):
          await asyncio.wait_for(sock.send_ack_command('RMT=5678'), LOOP_TIMEOUT)

    self.assertTrue(any('RMT=<code>' in line for line in logs.output), logs.output)
    self.assertFalse(any('5678' in line for line in logs.output), logs.output)

  async def test_not_connected_fails_at_once(self):
    sock = RiscoSocket('host', 1, '1234')

    with self.assertRaises(CommunicationError):
      await asyncio.wait_for(sock.send_command('CLOCK'), LOOP_TIMEOUT)

  async def test_a_dead_listener_fails_at_once_instead_of_timing_out(self):
    sock = connected_socket()
    sock._listen_task = asyncio.create_task(asyncio.sleep(0))
    await settle(3)

    started = time.monotonic()
    with self.assertRaises(CommunicationError):
      await asyncio.wait_for(sock.send_command('ZTYPE*1?'), LOOP_TIMEOUT)
    self.assertLess(time.monotonic() - started, 0.5)
    self.assertEqual(sock.sent, [], 'Reject the command before writing to a dead socket.')

  async def test_a_closing_transport_fails_at_once(self):
    sock = connected_socket()
    sock._writer.transport.closing = True

    with self.assertRaises(CommunicationError):
      await asyncio.wait_for(sock.send_command('ZTYPE*1?'), LOOP_TIMEOUT)

  async def test_connection_loss_fails_every_waiting_command(self):
    sock = connected_socket(concurrency=4)
    reader = FeedReader(sock)
    listener = asyncio.create_task(sock._listen())
    sock._listen_task = listener

    waiting = [asyncio.create_task(sock.send_command(f'ZSTT*{i}?')) for i in (1, 2, 3)]
    await settle()
    reader.fail(asyncio.IncompleteReadError(b'', None))
    results = await asyncio.wait_for(
        asyncio.gather(*waiting, return_exceptions=True), LOOP_TIMEOUT)

    self.assertTrue(all(isinstance(r, CommunicationError) for r in results), results)




class DisconnectTest(unittest.IsolatedAsyncioTestCase):

  async def test_a_dead_listener_skips_the_dcn_handshake(self):
    sock = connected_socket()
    sock._listen_task = asyncio.create_task(asyncio.sleep(0))
    await settle(3)

    await asyncio.wait_for(sock.disconnect(), LOOP_TIMEOUT)

    self.assertEqual(sock.sent, [], 'Skip DCN when no listener can receive its acknowledgement.')
    self.assertIsNone(sock._writer)

  async def test_an_unanswered_dcn_does_not_hold_up_disconnect(self):
    sock = connected_socket()
    sock._listen_task = asyncio.create_task(asyncio.sleep(3600))
    self.addCleanup(sock._listen_task.cancel)

    started = time.monotonic()
    with patch_timing(DISCONNECT_TIMEOUT=0.05):
      await asyncio.wait_for(sock.disconnect(), LOOP_TIMEOUT)

    self.assertLess(time.monotonic() - started, 0.5)
    self.assertEqual([c for _, c in sock.sent], ['DCN'])
    self.assertIsNone(sock._writer)

  async def test_disconnect_is_bounded_even_when_every_command_slot_is_busy(self):
    """Include command-slot waiting in the DCN deadline so busy commands cannot delay shutdown."""
    sock = connected_socket(concurrency=1)
    sock._listen_task = asyncio.create_task(asyncio.sleep(3600))
    busy = asyncio.create_task(sock.send_command('ZLBL*1?'))
    await settle()

    started = time.monotonic()
    with patch_timing(DISCONNECT_TIMEOUT=0.05):
      await asyncio.wait_for(sock.disconnect(), LOOP_TIMEOUT)

    self.assertLess(time.monotonic() - started, 0.5)
    with self.assertRaises(CommunicationError):
      await busy

  async def test_the_panel_closing_after_dcn_is_not_a_lost_session(self):
    """The panel may close its end once it acknowledges DCN."""
    sock = connected_socket()
    sock._closing = True
    scripted_reader(sock, [asyncio.IncompleteReadError(b'', None)])

    await asyncio.wait_for(sock._listen(), LOOP_TIMEOUT)

    self.assertFalse(sock._lost)
    self.assertEqual(drain(sock._queue), [],
                     'Do not report deliberate disconnect as an unexpected loss.')

  async def test_the_panel_closing_unasked_is_a_lost_session(self):
    sock = connected_socket()
    scripted_reader(sock, [asyncio.IncompleteReadError(b'', None)])

    await asyncio.wait_for(sock._listen(), LOOP_TIMEOUT)

    self.assertTrue(sock._lost)

  async def test_a_hanging_close_does_not_hold_up_disconnect(self):
    sock = connected_socket()
    sock._writer.wait_closed_hangs = True

    with patch_timing(DISCONNECT_TIMEOUT=0.05):
      await asyncio.wait_for(sock.disconnect(), LOOP_TIMEOUT)

    self.assertIsNone(sock._writer)

  async def test_a_second_disconnect_waits_for_the_first(self):
    """Otherwise the caller reconnects over a session still being closed."""
    sock = connected_socket()
    sock._listen_task = asyncio.create_task(asyncio.sleep(3600))
    self.addCleanup(sock._listen_task.cancel)
    writer = sock._writer

    with patch_timing(DISCONNECT_TIMEOUT=0.2):
      first = asyncio.create_task(sock.disconnect())
      await settle(5)
      self.assertEqual([c for _, c in sock.sent], ['DCN'])
      second = asyncio.create_task(sock.disconnect())
      await settle(5)
      self.assertFalse(second.done(), 'Wait for the first disconnect before completing the second.')
      await asyncio.wait_for(asyncio.gather(first, second), LOOP_TIMEOUT)

    self.assertTrue(writer.transport.closed)
    self.assertEqual([c for _, c in sock.sent], ['DCN'], 'Send DCN only once for concurrent disconnect calls.')

  async def test_abort_closes_without_awaiting(self):
    sock = connected_socket()
    listener = asyncio.create_task(asyncio.sleep(3600))
    sock._listen_task = listener
    writer = sock._writer
    pending = asyncio.get_running_loop().create_future()
    sock._futures[4] = pending

    sock.abort()
    await settle(2)

    self.assertTrue(writer.transport.closed)
    self.assertTrue(listener.cancelled())
    self.assertIsInstance(pending.exception(), CommunicationError)
    self.assertIsNone(sock._writer)


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


class ReadFailureTest(unittest.TestCase):
  """Reader errors that re-raise without waiting must not spin the loop.

  Run in a subprocess with a watchdog: a regression here freezes the event
  loop, which no in-process timeout can interrupt.
  """

  PROBE = "\nimport asyncio, os, sys, threading\nsys.path.insert(0, sys.argv[1])\nfrom pyrisco.local.risco_socket import RiscoSocket\nfrom pyrisco.local.risco_crypt import RiscoCrypt\n\nasync def main(kind):\n  watchdog = threading.Timer(5, lambda: os._exit(3))\n  watchdog.start()\n  sock = RiscoSocket('host', 1, '1234')\n  sock._queue = asyncio.Queue()\n  sock._crypt = RiscoCrypt()\n  if kind == 'timeout':\n    sock._reader = asyncio.StreamReader()\n    sock._reader.set_exception(TimeoutError(110, 'Connection timed out'))\n  elif kind == 'overrun':\n    sock._reader = asyncio.StreamReader(limit=16)\n    sock._reader.feed_data(b'x' * 64)\n  else:\n    async def _read():\n      raise RuntimeError('raised without waiting')\n    sock._read_command = _read\n  listener = asyncio.create_task(sock._listen())\n  ticked = asyncio.Event()\n  async def tick():\n    await asyncio.sleep(0.05)\n    ticked.set()\n  asyncio.create_task(tick())\n  await asyncio.wait_for(ticked.wait(), 2)\n  if kind == 'other':\n    listener.cancel()\n    print('loop kept turning')\n  else:\n    await asyncio.wait_for(listener, 2)\n    print(type(sock._queue.get_nowait()).__name__)\n  watchdog.cancel()\n\nasyncio.run(main(sys.argv[2]))\n"

  def _probe(self, kind):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    result = subprocess.run([sys.executable, '-c', self.PROBE, root, kind],
                            capture_output=True, text=True, timeout=30)
    self.assertNotEqual(result.returncode, 3, f'{kind}: the event loop froze')
    self.assertEqual(result.returncode, 0, result.stderr)
    return result.stdout.strip()

  def test_a_socket_timeout_ends_the_listener(self):
    """ETIMEDOUT arrives as TimeoutError, an OSError but not a ConnectionError."""
    self.assertEqual(self._probe('timeout'), 'TimeoutError')

  def test_an_oversized_frame_ends_the_listener(self):
    """More than the stream limit without an END: readuntil raises every time."""
    self.assertEqual(self._probe('overrun'), 'LimitOverrunError')

  def test_any_other_error_still_lets_the_loop_turn(self):
    self.assertEqual(self._probe('other'), 'loop kept turning')


class ConnectTest(unittest.IsolatedAsyncioTestCase):

  def setUp(self):
    reset_reconnect_history()
    self.addCleanup(reset_reconnect_history)

  async def _serve(self, handler):
    return await serve(self, handler)

  async def test_cancelled_connect_closes_the_socket(self):
    closed = asyncio.Event()

    async def _silent(reader, writer):
      await reader.read()
      closed.set()

    port = await self._serve(_silent)
    sock = RiscoSocket('127.0.0.1', port, '1234')

    task = asyncio.create_task(sock.connect())
    await asyncio.sleep(0.1)  # connected, waiting on the RID reply
    task.cancel()
    with self.assertRaises(asyncio.CancelledError):
      await task

    await asyncio.wait_for(closed.wait(), LOOP_TIMEOUT)
    self.assertIsNone(sock._writer)
    self.assertIsNone(sock._listen_task)

  async def test_a_failed_handshake_closes_and_raises_cannot_connect(self):
    closed = asyncio.Event()

    async def _silent(reader, writer):
      await reader.read()
      closed.set()

    port = await self._serve(_silent)
    sock = RiscoSocket('127.0.0.1', port, '1234')

    with patch_timing(COMMAND_TIMEOUT=0.05):
      with self.assertRaises(CannotConnectError):
        await asyncio.wait_for(sock.connect(), LOOP_TIMEOUT)

    await asyncio.wait_for(closed.wait(), LOOP_TIMEOUT)
    self.assertIsNone(sock._writer)


class ConnectTimeoutTest(unittest.IsolatedAsyncioTestCase):

  def setUp(self):
    reset_reconnect_history()
    self.addCleanup(reset_reconnect_history)

  async def test_a_connect_that_never_completes_times_out(self):
    """Bound TCP connection setup when a dropped SYN would otherwise wait for the OS timeout."""
    async def _never(host, port):
      await asyncio.sleep(3600)

    sock = RiscoSocket('192.0.2.1', 1000, '1234')
    with unittest.mock.patch.object(risco_socket.asyncio, 'open_connection', _never):
      with patch_timing(CONNECT_TIMEOUT=0.05):
        with self.assertRaises(CannotConnectError) as caught:
          await asyncio.wait_for(sock.connect(), LOOP_TIMEOUT)

    self.assertIn('192.0.2.1', str(caught.exception))
    self.assertIsNone(sock._writer)


class ConnectWaitTest(unittest.IsolatedAsyncioTestCase):

  def setUp(self):
    reset_reconnect_history()
    self.addCleanup(reset_reconnect_history)

  async def test_disconnect_while_connect_waits_leaves_no_session(self):
    """Prevent a waiting connect() from opening a session after disconnect() returns."""
    connections = []

    async def _server(reader, writer):
      connections.append(writer)
      await reader.read()

    port = await serve(self, _server)
    sock = RiscoSocket('127.0.0.1', port, '1234')
    risco_socket._panel_history[('127.0.0.1', port)] = {
        'closed_at': time.monotonic(), 'losses': 0}

    with patch_timing(RECONNECT_DELAY=0.3):
      connecting = asyncio.create_task(sock.connect())
      await asyncio.sleep(0.05)
      await asyncio.wait_for(sock.disconnect(), LOOP_TIMEOUT)
      with self.assertRaises(CannotConnectError) as caught:
        await asyncio.wait_for(connecting, LOOP_TIMEOUT)

    self.assertIn('disconnect()', str(caught.exception))
    await asyncio.sleep(0.1)
    self.assertEqual(connections, [], 'Prevent the pending connect from opening a session after disconnect.')
    self.assertIsNone(sock._writer)


  async def test_disconnect_during_the_login_fails_the_connect(self):
    """Fail connect() if disconnect() starts during login so a closing session cannot report success."""
    local = None

    async def _panel(reader, writer):
      from pyrisco.local.risco_crypt import RiscoCrypt
      crypt = RiscoCrypt()
      buffer = b''
      while True:
        try:
          chunk = await reader.read(1024)
        except ConnectionError:  # the client may abort the session
          return
        if not chunk:
          return
        buffer += chunk
        while b'\x03' in buffer:
          frame, buffer = buffer.split(b'\x03', 1)
          cmd_id, command, _ = crypt.decode(frame + b'\x03')
          if command == 'RID':
            writer.write(bytes(crypt.encode(cmd_id, 'RID=0000')))
          elif command == 'LCL':
            writer.write(bytes(crypt.encode(cmd_id, 'ACK')))
          elif command.startswith('RMT='):
            # disconnect() starts while the login is being answered
            disconnecting.append(asyncio.create_task(sock.disconnect()))
            await asyncio.sleep(0)
            writer.write(bytes(crypt.encode(cmd_id, 'ACK')))
          elif command == 'DCN':
            writer.write(bytes(crypt.encode(cmd_id, 'ACK')))

    disconnecting = []
    port = await serve(self, _panel)
    sock = RiscoSocket('127.0.0.1', port, '1234')

    with self.assertRaises(CannotConnectError):
      await asyncio.wait_for(sock.connect(), LOOP_TIMEOUT)
    await asyncio.wait_for(asyncio.gather(*disconnecting), LOOP_TIMEOUT)

    self.assertIsNone(sock._writer)
    self.assertIsNone(sock._keep_alive_task)

  async def test_connecting_a_connected_socket_closes_the_old_session(self):
    """Close the existing socket and keep-alive before opening a replacement session."""
    sessions = []

    async def _panel(reader, writer):
      from pyrisco.local.risco_crypt import RiscoCrypt
      crypt = RiscoCrypt()
      sessions.append(writer)
      buffer = b''
      while True:
        try:
          chunk = await reader.read(1024)
        except ConnectionError:  # the client may abort the session
          chunk = b''
        if not chunk:
          sessions.remove(writer)
          return
        buffer += chunk
        while b'\x03' in buffer:
          frame, buffer = buffer.split(b'\x03', 1)
          cmd_id, command, _ = crypt.decode(frame + b'\x03')
          reply = 'RID=0000' if command == 'RID' else 'CLOCK=x' if command == 'CLOCK' else 'ACK'
          writer.write(bytes(crypt.encode(cmd_id, reply)))

    port = await serve(self, _panel)
    sock = RiscoSocket('127.0.0.1', port, '1234')
    self.addAsyncCleanup(sock.disconnect)
    with patch_timing(RECONNECT_DELAY=0.05):
      await asyncio.wait_for(sock.connect(), LOOP_TIMEOUT)
      await asyncio.wait_for(sock.connect(), LOOP_TIMEOUT)
    await asyncio.sleep(0.1)

    self.assertEqual(len(sessions), 1)

  async def test_a_short_wait_is_slept_out(self):
    sock = RiscoSocket('127.0.0.1', 9, '1234')
    risco_socket._panel_history[('127.0.0.1', 9)] = {
        'closed_at': time.monotonic(), 'losses': 0}

    started = time.monotonic()
    with patch_timing(RECONNECT_DELAY=0.1):
      await asyncio.wait_for(sock._wait_before_reconnect(), LOOP_TIMEOUT)

    self.assertGreaterEqual(time.monotonic() - started, 0.1 - 0.02)

  async def test_cancelled_while_waiting_to_reconnect_returns_at_once(self):
    """HA cancels setup at shutdown, possibly while connect() waits out the
    short gap after the previous session."""
    sock = RiscoSocket('127.0.0.1', 9, '1234')
    risco_socket._panel_history[('127.0.0.1', 9)] = {
        'closed_at': time.monotonic(), 'losses': 0}

    with patch_timing(RECONNECT_DELAY=5, MAX_RECONNECT_DELAY=300):
      task = asyncio.create_task(sock.connect())
      await asyncio.sleep(0.05)
      started = time.monotonic()
      task.cancel()
      with self.assertRaises(asyncio.CancelledError):
        await task

    self.assertLess(time.monotonic() - started, 0.5)
    self.assertIsNone(sock._writer)


def _production_timing():
  return patch_timing(RECONNECT_DELAY=5, STABLE_SESSION=120, MAX_RECONNECT_DELAY=300)




if __name__ == '__main__':
  unittest.main()
