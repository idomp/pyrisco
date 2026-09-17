"""End to end: RiscoLocal against a scripted panel over real TCP.

Each test reproduces a failure seen in the field or in live fault injection,
with the socket's timing constants shrunk so the whole file runs in seconds.
The one invariant checked throughout is the panel's: it must never see two
sessions open at once, and never a new session sooner than RECONNECT_DELAY
after the previous one closed.
"""

import asyncio
import random
import sys
import time
import unittest

from helpers_local import (
    CommunicationError,
    ConnectionLostError,
    patch_timing,
    reset_reconnect_history,
)
from pyrisco.common import CannotConnectError, OperationError, UnauthorizedError
from pyrisco.local.risco_local import RiscoLocal
from scripted_panel import (
    CLOSE,
    LATE_REFUSE,
    REFUSE,
    EXECUTE_NO_REPLY,
    REFUSE_NO_ID,
    SILENT,
    ScriptedPanel,
    Supervisor,
)

# Matches helpers_local.patch_timing().
RECONNECT_DELAY = 0.2
MAX_RECONNECT_DELAY = 1.6
# Scheduling slack allowed when comparing wall-clock gaps.
SLACK = 0.05
WAIT = 5


def _losses(supervisor):
  """What ended each lost connection the supervisor was told of."""
  return [e.__cause__ if isinstance(e, ConnectionLostError) else e for e in supervisor.errors]


async def _until(predicate, timeout=WAIT, what='condition'):
  deadline = time.monotonic() + timeout
  while not predicate():
    if time.monotonic() > deadline:
      raise AssertionError(f'timed out waiting for {what}')
    await asyncio.sleep(0.01)


async def _wait(predicate, timeout=10):
  deadline = time.monotonic() + timeout
  while not predicate():
    if time.monotonic() > deadline:
      raise AssertionError('timed out')
    await asyncio.sleep(0.01)


def _discovery_tasks():
  return [t for t in asyncio.all_tasks() if not t.done()
          and t.get_coro().__qualname__.startswith('RiscoLocal._get_objects')]


class ScriptedPanelTestCase(unittest.IsolatedAsyncioTestCase):

  async def asyncSetUp(self):
    reset_reconnect_history()
    self.addCleanup(reset_reconnect_history)
    timing = patch_timing()
    timing.start()
    self.addCleanup(timing.stop)
    self.panel = await ScriptedPanel().start()
    self.addAsyncCleanup(self.panel.stop)

  def supervisor(self, **kwargs):
    supervisor = Supervisor(RiscoLocal, self.panel.port, **kwargs)
    self.addAsyncCleanup(supervisor.stop)
    return supervisor

  def assert_one_session_at_a_time(self):
    sessions = self.panel.sessions
    for before, after in zip(sessions, sessions[1:]):
      self.assertIsNotNone(before.closed_at, 'Close each earlier session before starting the next one.')
      self.assertLessEqual(
          before.closed_at, after.opened_at + SLACK,
          'Keep at most one panel session open at a time.')

  def reconnect_gaps(self):
    sessions = self.panel.sessions
    return [after.opened_at - before.closed_at
            for before, after in zip(sessions, sessions[1:])]


class ConnectTest(ScriptedPanelTestCase):

  async def test_reads_the_whole_panel_over_the_encrypted_link(self):
    self.panel.zones = {1, 2, 7}
    self.panel.partitions = {1, 3}
    local = RiscoLocal('127.0.0.1', self.panel.port, '1234')

    await asyncio.wait_for(local.connect(), WAIT)
    self.addAsyncCleanup(local.disconnect)

    self.assertEqual(sorted(local.zones), [1, 2, 7])
    self.assertEqual(local.zones[7].name, 'Zone 7')
    self.assertEqual(sorted(local.partitions), [1, 3])
    self.assertEqual(local.system.name, 'Home')
    self.assertTrue(self.panel.sessions[0].encrypted)

  async def test_pushed_status_reaches_the_zone_handler(self):
    local = RiscoLocal('127.0.0.1', self.panel.port, '1234')
    await asyncio.wait_for(local.connect(), WAIT)
    self.addAsyncCleanup(local.disconnect)
    seen = []

    async def _zone(zone_id, zone):
      seen.append((zone_id, zone.triggered))

    local.add_zone_handler(_zone)
    self.panel.push('ZSTT2=O---')
    await _until(lambda: seen, what='zone update')

    self.assertEqual(seen, [(2, True)])
    await _until(lambda: 'ACK' in self.panel.sessions[0].received, what='push ACK')

  async def test_refused_fsver_closes_the_session(self):
    """A refusal during connect() must not leave the session open.

    A session left open makes the panel refuse new connections.
    """
    self.panel.rules['FSVER?'] = REFUSE
    local = RiscoLocal('127.0.0.1', self.panel.port, '1234')

    with self.assertRaises(CannotConnectError) as caught:
      await asyncio.wait_for(local.connect(), WAIT)

    self.assertIn('N05', str(caught.exception))
    await _until(lambda: not self.panel.open_sessions, timeout=1,
                 what='the panel to see the session closed')






  async def test_bypassing_a_zone_is_acknowledged_and_pushed(self):
    local = RiscoLocal('127.0.0.1', self.panel.port, '1234')
    await asyncio.wait_for(local.connect(), WAIT)
    self.addAsyncCleanup(local.disconnect)
    seen = []

    async def _zone(zone_id, zone):
      seen.append((zone_id, zone.bypassed))

    local.add_zone_handler(_zone)
    await asyncio.wait_for(local.zones[2].bypass(True), WAIT)
    await _until(lambda: seen, what='the pushed status')
    await asyncio.wait_for(local.zones[2].bypass(False), WAIT)
    await _until(lambda: len(seen) == 2, what='the second pushed status')

    self.assertEqual(seen, [(2, True), (2, False)])

  async def test_every_frame_the_client_sends_has_a_valid_crc(self):
    """Check outbound frames with the scripted panel's independent CRC implementation."""
    local = RiscoLocal('127.0.0.1', self.panel.port, '1234')
    await asyncio.wait_for(local.connect(), WAIT)
    await asyncio.wait_for(local.arm(1), WAIT)
    await asyncio.wait_for(local.disconnect(), WAIT)

    session = self.panel.sessions[0]
    self.assertGreater(len(session.received), 50)
    self.assertEqual(session.bad_crc, 0)

  async def test_the_panel_rejects_a_frame_with_a_bad_crc(self):
    from pyrisco.local.risco_crypt import RiscoCrypt
    reader, writer = await asyncio.open_connection('127.0.0.1', self.panel.port)
    self.addAsyncCleanup(writer.wait_closed)
    self.addCleanup(writer.close)

    writer.write(b'\x0201RID\x170000\x03')
    reply = await asyncio.wait_for(reader.readuntil(b'\x03'), WAIT)

    # Without an id: the id in a corrupted frame cannot be trusted.
    self.assertEqual(RiscoCrypt().decode(reply)[:2], [None, 'N04'])
    await _until(lambda: self.panel.sessions and self.panel.sessions[0].bad_crc == 1,
                 timeout=1, what='the count')

  async def test_a_panel_still_encrypting_fails_the_connect_at_once(self):
    """Fail promptly when the panel encrypts RID before the client knows its panel ID."""
    self.panel.encrypt_from_start = True
    local = RiscoLocal('127.0.0.1', self.panel.port, '1234')

    started = time.monotonic()
    with patch_timing(COMMAND_TIMEOUT=5.0):
      with self.assertRaises(CannotConnectError) as caught:
        await asyncio.wait_for(local.connect(), WAIT)

    self.assertLess(time.monotonic() - started, 1.0)
    # Preserve the shutdown reason rather than reporting only "Not connected".
    self.assertIn('still encrypting', str(caught.exception))

  async def test_a_push_right_behind_the_rid_reply_does_not_fail_the_connect(self):
    """Allow a push beside RID before connect() has stored the panel ID without rejecting setup."""
    self.panel.push_after_rid = 'CLOCK=17/09/2026 04:13'
    local = RiscoLocal('127.0.0.1', self.panel.port, '1234')

    await asyncio.wait_for(local.connect(), WAIT)
    self.addAsyncCleanup(local.disconnect)

    self.assertEqual(sorted(local.zones), sorted(self.panel.zones))

  async def test_an_unanswered_login_is_a_connection_failure(self):
    """No answer says nothing about the code, so it must stay retryable."""
    self.panel.rules['RMT=1234'] = SILENT
    local = RiscoLocal('127.0.0.1', self.panel.port, '1234')

    with self.assertRaises(CannotConnectError):
      await asyncio.wait_for(local.connect(), WAIT)

  async def test_communication_delay_is_honoured(self):
    local = RiscoLocal('127.0.0.1', self.panel.port, '1234', communication_delay=0.3)

    started = time.monotonic()
    await asyncio.wait_for(local.connect(), WAIT)
    self.addAsyncCleanup(local.disconnect)

    self.assertGreaterEqual(time.monotonic() - started, 0.3)

  async def test_deliberate_reconnects_wait_only_the_panel_cooldown(self):
    """Apply only the panel cooldown to deliberate reconnects such as configuration checks."""
    for _ in range(4):
      local = RiscoLocal('127.0.0.1', self.panel.port, '1234')
      await asyncio.wait_for(local.connect(), WAIT)
      await asyncio.wait_for(local.disconnect(), WAIT)

    gaps = self.reconnect_gaps()
    self.assertEqual(len(gaps), 3)
    for gap in gaps:
      self.assertGreaterEqual(gap, RECONNECT_DELAY - SLACK, gaps)
      self.assertLess(gap, 2 * RECONNECT_DELAY - SLACK, f'escalated: {gaps}')

  async def test_cancelled_setup_closes_the_session(self):
    """HA cancels a slow setup at shutdown; the panel must not keep a session."""
    self.panel.rules['PNLSERD'] = SILENT
    local = RiscoLocal('127.0.0.1', self.panel.port, '1234')

    task = asyncio.create_task(local.connect())
    await _until(lambda: 'PNLSERD' in (self.panel.sessions[0].received
                                       if self.panel.sessions else []),
                 what='setup to reach PNLSERD')
    task.cancel()
    with self.assertRaises(asyncio.CancelledError):
      await task

    await _until(lambda: not self.panel.open_sessions, timeout=1,
                 what='the panel to see the session closed')

  async def test_refused_connection_fails_fast(self):
    await self.panel.stop()
    local = RiscoLocal('127.0.0.1', self.panel.port, '1234')

    started = time.monotonic()
    with self.assertRaises(CannotConnectError):
      await asyncio.wait_for(local.connect(), WAIT)
    # Windows retries a refused localhost connect for about 2s by itself.
    self.assertLess(time.monotonic() - started, 4)

  async def test_unanswered_dcn_does_not_hold_up_disconnect(self):
    self.panel.rules['DCN'] = SILENT
    local = RiscoLocal('127.0.0.1', self.panel.port, '1234')
    await asyncio.wait_for(local.connect(), WAIT)

    started = time.monotonic()
    await asyncio.wait_for(local.disconnect(), WAIT)

    self.assertLess(time.monotonic() - started, 1)
    await _until(lambda: not self.panel.open_sessions, timeout=1,
                 what='the panel to see the session closed')


class DiscoveryTest(ScriptedPanelTestCase):




  async def test_connecting_a_connected_panel_again_leaves_nothing_running(self):
    """End the previous listener and session when connecting an already connected object."""
    local = RiscoLocal('127.0.0.1', self.panel.port, '1234')
    await asyncio.wait_for(local.connect(), WAIT)
    first = local._listen_task

    await asyncio.wait_for(local.connect(), WAIT)
    second = local._listen_task
    await asyncio.wait_for(local.disconnect(), WAIT)
    await _wait(lambda: not self.panel.open_sessions)

    await _wait(lambda: first.done() and second.done())
    self.assertEqual(len(self.panel.sessions), 2)
    self.assertIn('DCN', self.panel.sessions[0].received)
    self.assert_one_session_at_a_time()







  async def test_a_label_in_another_encoding_does_not_lose_the_zone(self):
    """Keep a zone with an undecodable label by replacing invalid characters in its name.

    Captured panel frames include Latin-1 labels, while a consumer may use UTF-8.
    """
    self.panel.zones = {1, 2, 3}
    self.panel.encoding = 'latin-1'
    self.panel.labels = {2: 'Entr\xe9e'}
    local = RiscoLocal('127.0.0.1', self.panel.port, '1234')

    await asyncio.wait_for(local.connect(), WAIT)
    self.addAsyncCleanup(local.disconnect)

    self.assertEqual(sorted(local.zones), [1, 2, 3])
    self.assertEqual(local.zones[2].name, 'Entr\ufffde')





class RecoveryTest(ScriptedPanelTestCase):
  """A lost session must come back on its own, one session at a time."""

  async def _connected_supervisor(self, **kwargs):
    supervisor = self.supervisor(**kwargs)
    await asyncio.wait_for(supervisor.start(), WAIT)
    return supervisor

  async def _recovered(self, supervisor, sessions):
    await _until(lambda: len(self.panel.sessions) >= sessions and supervisor.ready.is_set(),
                 what=f'recovery to session {sessions}')

  async def test_a_link_that_goes_silent_is_given_up_and_reconnected(self):
    """A connection whose packets are silently dropped must be given up on."""
    supervisor = await self._connected_supervisor()

    self.panel.go_silent()
    await self._recovered(supervisor, 2)

    self.assertEqual(supervisor.reloads, 1)
    self.assertTrue(any('closing the connection' in str(e) for e in supervisor.errors))
    self.assert_one_session_at_a_time()

  async def test_the_panel_closing_the_connection_reconnects(self):
    """A graceful FIN surfaces as IncompleteReadError, never seen live."""
    supervisor = await self._connected_supervisor()

    self.panel.close_sessions()
    await self._recovered(supervisor, 2)

    self.assertTrue(any(isinstance(e, asyncio.IncompleteReadError) for e in _losses(supervisor)),
                    supervisor.errors)
    self.assert_one_session_at_a_time()

  async def test_the_panel_resetting_the_connection_reconnects(self):
    supervisor = await self._connected_supervisor()

    self.panel.reset_sessions()
    await self._recovered(supervisor, 2)

    self.assert_one_session_at_a_time()

  async def test_arming_after_a_reconnect_reaches_the_panel(self):
    supervisor = await self._connected_supervisor()
    self.panel.close_sessions()
    await self._recovered(supervisor, 2)

    self.assertTrue(await asyncio.wait_for(supervisor.panel.arm(1), WAIT))
    await _until(lambda: supervisor.panel.partitions[1].armed, timeout=1,
                 what='the pushed armed status')
    self.assertIn('ARM=1', self.panel.sessions[1].received)

  async def test_concurrency_1_connects_keeps_alive_and_recovers(self):
    """Keep discovery, keep-alive and recovery working with one command slot."""
    supervisor = await self._connected_supervisor(concurrency=1)
    await asyncio.sleep(0.5)  # several keep-alives

    self.panel.go_silent()
    await self._recovered(supervisor, 2)

    self.assertEqual(supervisor.reloads, 1)
    self.assert_one_session_at_a_time()

  async def test_a_consumer_that_reloads_only_on_a_reset_still_recovers(self):
    """Deliver connection losses to consumers that reconnect only on ConnectionResetError."""
    supervisor = await self._connected_supervisor(lost=ConnectionResetError)

    self.panel.close_sessions()
    await self._recovered(supervisor, 2)

    self.assertEqual(supervisor.reloads, 1)

  async def test_a_desynced_session_is_given_up_quickly(self):
    """Close a session with unreadable frames before waiting for three keep-alive timeouts."""
    supervisor = await self._connected_supervisor()

    # Long enough that the keep-alive cannot be what gives up on it.
    with patch_timing(COMMAND_TIMEOUT=5.0, KEEP_ALIVE_INTERVAL=5.0):
      self.panel.desync_sessions()
      self.panel.push('ZSTT1=O---')
      self.panel.push('ZSTT1=----')
      await self._recovered(supervisor, 2)

    self.assertTrue(any('unreadable frames in a row' in str(e) for e in supervisor.errors),
                    supervisor.errors)
    self.assert_one_session_at_a_time()

  @unittest.skipIf(sys.platform == 'win32',
                   "asyncio's proactor transport shuts a socket down (FIN) before "
                   "closing it, so a reset cannot be forced from the server side")
  async def test_a_tcp_reset_is_observed_as_a_reset(self):
    """Verify the scripted reset reaches the client as a TCP reset rather than a graceful close."""
    supervisor = await self._connected_supervisor()

    self.panel.reset_sessions()
    await self._recovered(supervisor, 2)

    self.assertTrue(any(isinstance(e, ConnectionResetError) for e in _losses(supervisor)),
                    f'no reset was observed: {supervisor.errors}')

  async def test_a_panel_dropping_the_socket_during_disconnect_is_not_a_loss(self):
    """Treat a panel close during DCN as deliberate so consumers do not reload during shutdown."""
    self.panel.rules['DCN'] = CLOSE
    supervisor = await self._connected_supervisor()
    local = supervisor.panel

    await asyncio.wait_for(local.disconnect(), WAIT)
    await asyncio.sleep(0.5)

    self.assertEqual(supervisor.reloads, 0)
    self.assertFalse(any(isinstance(e, (ConnectionLostError, OSError, EOFError))
                         for e in supervisor.errors), supervisor.errors)
    supervisor.panel = None


  async def test_clock_refusals_with_a_command_id_keep_the_session(self):
    """The panel is answering - for example in programming mode - so the
    keep-alive must not tear the session down and re-initialise it."""
    self.panel.rules['CLOCK'] = REFUSE
    supervisor = await self._connected_supervisor()

    await asyncio.sleep(1.0)

    self.assertGreater(self.panel.sessions[0].received.count('CLOCK'), 5)
    self.assertEqual(len(self.panel.sessions), 1)
    self.assertEqual(supervisor.reloads, 0)

  async def test_reconnect_leaves_the_panel_time_to_reset(self):
    supervisor = await self._connected_supervisor()

    self.panel.close_sessions()
    await self._recovered(supervisor, 2)

    gap, = self.reconnect_gaps()
    self.assertGreaterEqual(gap, RECONNECT_DELAY - SLACK)




if __name__ == '__main__':
  unittest.main()
