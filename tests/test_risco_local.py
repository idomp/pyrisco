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




class DiscoveryTest(unittest.IsolatedAsyncioTestCase):
  """A refused query means "not there"; a lost answer means "don't know"."""















  async def test_connecting_a_connected_panel_does_not_leave_its_listener(self):
    """Stop the previous listener before reconnecting so it cannot remain blocked on the old queue."""
    fake = FakeSocket(panel_responses(zones=(1,)))
    panel = _local(fake)
    await asyncio.wait_for(panel.connect(), LOOP_TIMEOUT)
    first = panel._listen_task

    await asyncio.wait_for(panel.connect(), LOOP_TIMEOUT)
    await asyncio.wait_for(panel.disconnect(), LOOP_TIMEOUT)
    await settle()

    self.assertTrue(first.done())
    self.assertEqual(fake.disconnect_calls, 2)












class SetupErrorTest(unittest.IsolatedAsyncioTestCase):
  """Errors raised while connect() ran are not delivered once it succeeds."""


  async def test_a_loss_after_the_library_gave_up_says_why(self):
    """Report the library's shutdown reason instead of only the EOF caused by closing the socket."""
    fake = FakeSocket(panel_responses(zones=(1,)))
    panel = _local(fake)
    errors = []
    panel.add_error_handler(_collect(errors))
    await asyncio.wait_for(panel.connect(), LOOP_TIMEOUT)

    fake.close_reason = 'Keep-alive failed 3 times in a row'
    fake.queue.put_nowait(asyncio.IncompleteReadError(b'', None))
    await settle()

    self.assertEqual(str(errors[-1]), 'Connection lost: Keep-alive failed 3 times in a row')
    self.assertIsInstance(errors[-1].__cause__, asyncio.IncompleteReadError)

  async def test_a_lost_connection_is_also_a_connection_reset(self):
    """Preserve ConnectionResetError compatibility so existing consumers still reconnect on loss."""
    self.assertTrue(issubclass(ConnectionLostError, ConnectionResetError))
    self.assertTrue(issubclass(ConnectionLostError, CommunicationError))
    self.assertEqual(str(ConnectionLostError('Connection lost: EOFError')),
                     'Connection lost: EOFError')







class HandlerErrorTest(unittest.IsolatedAsyncioTestCase):
  """Log handler failures and keep delivering events to the other handlers."""

  async def test_a_handler_that_raises_is_logged(self):
    panel = _local(FakeSocket())

    async def _broken(error):
      raise RuntimeError('handler bug')

    panel.add_error_handler(_broken)
    with self.assertLogs('pyrisco.local.risco_local', 'ERROR') as logs:
      panel._error(OperationError('N05'))
      await settle()

    self.assertIn('handler bug', '\n'.join(logs.output))

  async def test_a_handler_that_is_not_a_coroutine_is_logged(self):
    panel = _local(FakeSocket())
    panel.add_error_handler(lambda error: None)

    with self.assertLogs('pyrisco.local.risco_local', 'ERROR'):
      panel._error(OperationError('N05'))
      await settle()

  async def test_other_handlers_still_run(self):
    panel = _local(FakeSocket())
    seen = []

    async def _broken(error):
      raise RuntimeError('handler bug')

    panel.add_error_handler(_broken)
    panel.add_error_handler(_collect(seen))
    with self.assertLogs('pyrisco.local.risco_local', 'ERROR'):
      panel._error(OperationError('N05'))
      await settle()

    self.assertEqual(len(seen), 1)


class UndeliveredErrorTest(unittest.IsolatedAsyncioTestCase):

  async def test_a_loss_before_any_handler_is_added_reaches_the_first_one(self):
    """Retain a loss until the first error handler is registered.

    The listener may process it between connect() finishing and the caller
    adding a handler; dropping it would leave the consumer unaware of the loss.
    """
    fake = FakeSocket(panel_responses(zones=(1,)))
    panel = _local(fake)
    await asyncio.wait_for(asyncio.create_task(panel.connect()), LOOP_TIMEOUT)
    fake.queue.put_nowait(ConnectionResetError())
    await settle()
    self.assertEqual(fake.disconnect_calls, 1)

    errors = []
    panel.add_error_handler(_collect(errors))
    await settle()

    self.assertEqual(len(errors), 1, errors)
    self.assertIsInstance(errors[0], ConnectionLostError)

  async def test_undelivered_errors_are_bounded(self):
    panel = _local(FakeSocket())
    for n in range(30):
      panel._error(OperationError(f'N05 #{n}'))

    errors = []
    panel.add_error_handler(_collect(errors))
    await settle()

    self.assertEqual(len(errors), 20)
    self.assertEqual(str(errors[-1]), 'N05 #29')

  async def test_errors_go_straight_to_a_registered_handler(self):
    panel = _local(FakeSocket())
    errors = []
    panel.add_error_handler(_collect(errors))

    panel._error(OperationError('N05'))
    await settle()

    self.assertEqual(len(errors), 1)
    self.assertEqual(len(panel._undelivered), 0)

  async def test_retained_errors_reach_only_the_handler_that_was_added(self):
    """A handler registered later did not miss the retained errors.

    Delivery runs in its own task, so a second handler added in the same
    moment must not receive the backlog of the first.
    """
    panel = _local(FakeSocket())
    panel._error(OperationError('N05'))

    first = []
    second = []
    panel.add_error_handler(_collect(first))
    panel.add_error_handler(_collect(second))
    await settle()

    self.assertEqual(len(first), 1)
    self.assertEqual(second, [])

  async def test_retained_errors_survive_removing_the_handler(self):
    """Removing the handler before the delivery runs must not discard them."""
    panel = _local(FakeSocket())
    panel._error(OperationError('N05'))

    errors = []
    remove = panel.add_error_handler(_collect(errors))
    remove()
    await settle()

    self.assertEqual(len(errors), 1)


class ListenerShutdownTest(unittest.IsolatedAsyncioTestCase):
  """A dead connection must end the listener, not spin on it."""

  async def _listener_exits_on(self, error):
    fake = FakeSocket()
    panel = _local(fake)
    errors = []
    panel.add_error_handler(_collect(errors))
    queue = asyncio.Queue()
    queue.put_nowait(error)
    task = asyncio.create_task(panel._listen(queue))
    panel._listen_task = task

    await asyncio.wait_for(task, LOOP_TIMEOUT)
    await settle()

    self.assertFalse(task.cancelled(), 'Let the listener exit normally after reporting the loss.')
    self.assertEqual(fake.disconnect_calls, 1, 'Disconnect when the listener receives a terminal read error.')
    # Normalize every terminal read to one loss type so consumers do not
    # need their own tuple of asyncio and OS exceptions.
    self.assertEqual(len(errors), 1, errors)
    self.assertIsInstance(errors[0], ConnectionLostError)
    self.assertIs(errors[0].__cause__, error)
    self.assertIn(type(error).__name__, str(errors[0]))

  async def test_graceful_eof_exits_listener(self):
    """A clean close - by the panel, or by the keep-alive - is IncompleteReadError."""
    await self._listener_exits_on(asyncio.IncompleteReadError(b'', None))

  async def test_connection_reset_exits_listener(self):
    await self._listener_exits_on(ConnectionResetError())

  async def test_broken_pipe_exits_listener(self):
    await self._listener_exits_on(BrokenPipeError())

  async def test_a_socket_timeout_exits_listener(self):
    """ETIMEDOUT: an OSError, but not a ConnectionError."""
    await self._listener_exits_on(TimeoutError(110, 'Connection timed out'))

  async def test_an_unreadable_stream_exits_listener(self):
    await self._listener_exits_on(asyncio.LimitOverrunError('frame too long', 64))

  async def _listener_survives(self, error):
    fake = FakeSocket()
    panel = _local(fake)
    queue = asyncio.Queue()
    queue.put_nowait(error)
    task = asyncio.create_task(panel._listen(queue))
    panel._listen_task = task
    self.addCleanup(task.cancel)

    await settle(20)

    self.assertFalse(task.done(), f'listener exited on {error!r}')
    self.assertEqual(fake.disconnect_calls, 0)

  async def test_a_refused_command_does_not_exit_listener(self):
    await self._listener_survives(OperationError('Risco error: N05'))

  async def test_a_keep_alive_timeout_does_not_exit_listener(self):
    await self._listener_survives(CommunicationError('Timeout in command: CLOCK'))


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
