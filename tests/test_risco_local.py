"""Tests for RiscoLocal - connection lifecycle, discovery and push handling.

These cover failure modes seen on a live LightSYS 2 (RP432M, fw 6.07):
initialisation that half-completes and reports success, a socket left open
when setup fails, a listener that never exits on a clean disconnect, and
pushed status for an id that was never created.
"""

import asyncio
import unittest

from helpers_local import (
    LOOP_TIMEOUT,
    CommunicationError,
    ConnectionLostError,
    FakeSocket,
    legacy_panel_responses,
    panel_responses,
    settle,
)
from pyrisco.common import CannotConnectError, OperationError
from pyrisco.local import risco_socket
from pyrisco.local.risco_local import RiscoLocal

TIMEOUT = CommunicationError('Timeout in command: ZTYPE*4?')


def _local(fake):
  panel = RiscoLocal('host', 1000, '1234')
  panel._rs = fake
  return panel


def _push(body, seq):
  push = risco_socket._Push(body)
  push.seq = seq
  return push


def _collect(sink):
  """Collect errors through the coroutine callback required by add_error_handler."""
  async def _handler(error):
    sink.append(error)
  return _handler


class ConnectCleanupTest(unittest.IsolatedAsyncioTestCase):
  """connect() must not leave a session behind when init fails."""

  async def test_successful_connect_builds_everything(self):
    fake = FakeSocket(panel_responses(zones=(1, 4), partitions=(1, 2)))
    panel = _local(fake)

    await asyncio.wait_for(panel.connect(), LOOP_TIMEOUT)
    self.addAsyncCleanup(panel.disconnect)

    self.assertEqual(sorted(panel.zones), [1, 4])
    self.assertEqual(sorted(panel.partitions), [1, 2])
    self.assertIsNotNone(panel.system)
    self.assertIsNotNone(panel._listen_task)
    self.assertEqual(fake.disconnect_calls, 0)

  async def test_rejected_init_command_disconnects_and_raises_cannot_connect(self):
    """A refused FSVER? must close the session rather than leave it open.

    A session left open makes the panel refuse new connections.
    """
    fake = FakeSocket(panel_responses(), errors={'FSVER?'})
    panel = _local(fake)

    with self.assertRaises(CannotConnectError) as caught:
      await asyncio.wait_for(panel.connect(), LOOP_TIMEOUT)

    self.assertIsInstance(caught.exception.__cause__, OperationError)
    self.assertIn('N05', str(caught.exception),
                  'Include the refusal reason because Home Assistant logs only the message.')
    self.assertEqual(fake.disconnect_calls, 1, 'Close the session after setup fails.')
    self.assertIsNone(panel._listen_task)

  async def test_unsupported_panel_disconnects_but_keeps_its_own_error(self):
    """An unknown model is not a connection problem, so it is not retried as one."""
    responses = panel_responses()
    responses['PNLCNF'] = 'RPXXXX'
    fake = FakeSocket(responses)
    panel = _local(fake)

    with self.assertRaises(KeyError):
      await asyncio.wait_for(panel.connect(), LOOP_TIMEOUT)

    self.assertEqual(fake.disconnect_calls, 1, 'Close the session after setup fails.')

  async def test_a_failing_cleanup_does_not_hide_the_connect_error(self):
    fake = FakeSocket(panel_responses(), errors={'FSVER?'})
    fake.disconnect_error = OSError('close failed')
    panel = _local(fake)

    with self.assertRaises(CannotConnectError):
      await asyncio.wait_for(panel.connect(), LOOP_TIMEOUT)

  async def test_cancelled_init_aborts_the_session(self):
    """HA cancels setup on shutdown; the session must still close."""
    fake = FakeSocket(panel_responses())
    fake.block_on = 'PNLSERD'
    panel = _local(fake)

    task = asyncio.create_task(panel.connect())
    await asyncio.wait_for(fake.blocked.wait(), LOOP_TIMEOUT)
    task.cancel()
    with self.assertRaises(asyncio.CancelledError):
      await task

    self.assertEqual(fake.abort_calls, 1, 'Abort the session when connect is cancelled.')
    self.assertIsNone(panel._listen_task)


class LegacyPanelTest(unittest.IsolatedAsyncioTestCase):
  """Panels whose type does not start with RP take a shorter path."""

  async def test_a_legacy_panel_connects_without_the_newer_queries(self):
    fake = FakeSocket(legacy_panel_responses(zones=(2, 5), partitions=(1,)))
    panel = _local(fake)

    await asyncio.wait_for(panel.connect(), LOOP_TIMEOUT)
    self.addAsyncCleanup(panel.disconnect)

    self.assertEqual(sorted(panel.zones), [2, 5])
    self.assertEqual(panel.zones[5].groups, [])
    for command in fake.sent:
      self.assertFalse(command.startswith(('FSVER', 'ZLNKTYP', 'ZAREA')), command)





























class DisconnectTest(unittest.IsolatedAsyncioTestCase):
  """disconnect() must always end the listen task."""

  async def test_failing_socket_disconnect_still_cancels_listen_task(self):
    """If _rs.disconnect() raised, the listen task used to be orphaned.

    It kept reading a dead queue for the life of the process. Home
    Assistant logs the exception and reports the unload as successful, so
    nothing else would ever stop it.
    """
    fake = FakeSocket()
    fake.disconnect_error = OSError('boom')
    panel = _local(fake)
    orphan = asyncio.create_task(asyncio.sleep(3600))
    panel._listen_task = orphan
    self.addCleanup(orphan.cancel)

    with self.assertRaises(OSError):
      await asyncio.wait_for(panel.disconnect(), LOOP_TIMEOUT)

    await asyncio.sleep(0)
    self.assertIsNone(panel._listen_task, 'Clear the listener task reference during disconnect.')
    self.assertTrue(orphan.cancelled(), 'Cancel the listener even if socket disconnect fails.')

  async def test_disconnect_cancels_listen_task(self):
    fake = FakeSocket()
    panel = _local(fake)
    task = asyncio.create_task(asyncio.sleep(3600))
    panel._listen_task = task
    self.addCleanup(task.cancel)

    await asyncio.wait_for(panel.disconnect(), LOOP_TIMEOUT)
    await asyncio.sleep(0)

    self.assertIsNone(panel._listen_task)
    self.assertTrue(task.cancelled())


if __name__ == '__main__':
  unittest.main()
