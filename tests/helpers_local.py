"""Shared helpers for the local (socket) tests.

These helpers deliberately avoid `unittest.mock.AsyncMock` for the reader:
an AsyncMock whose side_effect is an exception raises *without ever yielding
to the event loop*, so a buggy `while True` listener spins in a tight loop
that `asyncio.wait_for` can never interrupt - the whole test run hangs
instead of failing. Every fake below yields at least once per call, so a
test that exposes a spin bug fails on its timeout instead of wedging the
runner.
"""

import asyncio
import unittest.mock

from pyrisco.common import OperationError
from pyrisco.local import risco_socket

# pyrisco.common.CommunicationError does not exist before this change; fall
# back so the tests can still be run against the old code for comparison.
from pyrisco import common as _common
CommunicationError = getattr(_common, 'CommunicationError', OperationError)
ConnectionLostError = getattr(_common, 'ConnectionLostError', CommunicationError)

# Every test that drives a `while True` loop must be wrapped in this.
LOOP_TIMEOUT = 1


def scripted_reader(sock, frames):
  """Make `sock._read_command()` return `frames` in order.

  An element that is an exception instance is raised instead of returned.
  Once the script is exhausted the reader raises ConnectionResetError, which
  terminates the listener.
  """
  items = iter(frames)

  async def _read():
    await asyncio.sleep(0)
    try:
      item = next(items)
    except StopIteration:
      raise ConnectionResetError from None
    if isinstance(item, BaseException):
      raise item
    return item

  sock._read_command = _read


class FeedReader:
  """A reader the test feeds one decoded frame at a time.

  Unlike scripted_reader it never runs out: the listener waits on it until
  the test pushes the next frame, so a test can interleave replies with
  commands that are still being sent.
  """

  def __init__(self, sock):
    self._frames = asyncio.Queue()
    sock._read_command = self._read

  def push(self, cmd_id, command, crc=True):
    self._frames.put_nowait((cmd_id, command, crc))

  def fail(self, error):
    self._frames.put_nowait(error)

  async def _read(self):
    item = await self._frames.get()
    if isinstance(item, BaseException):
      raise item
    return item


class FakeTransport:
  def __init__(self):
    self.closing = False
    self.closed = False
    self.aborted = False
    self.buffered = 0

  def is_closing(self):
    return self.closing

  def get_write_buffer_size(self):
    return self.buffered

  def close(self):
    self.closing = True
    self.closed = True

  def abort(self):
    self.closing = True
    self.aborted = True


class FakeWriter:
  """Records what RiscoSocket writes, as (cmd_id, command) pairs."""

  def __init__(self):
    self.transport = FakeTransport()
    self.written = []
    self.wait_closed_calls = 0
    self.wait_closed_hangs = False

  def write(self, data):
    self.written.append(data)

  def close(self):
    self.transport.close()

  async def wait_closed(self):
    self.wait_closed_calls += 1
    if self.wait_closed_hangs:
      await asyncio.sleep(3600)


def connected_socket(concurrency=4, **kwargs):
  """A RiscoSocket that looks connected, with no network underneath.

  Commands written are captured on `sock.sent` as (cmd_id, command).
  """
  sock = risco_socket.RiscoSocket('host', 1, '1234', concurrency=concurrency, **kwargs)
  sock._queue = asyncio.Queue()
  sock._futures = [None] * risco_socket.MAX_CMD_ID
  sock._cmd_id = 0
  sock._semaphore = asyncio.Semaphore(concurrency)
  sock._writer = FakeWriter()
  sock.sent = []

  def _write(cmd_id, command, force_encryption=False):
    sock.sent.append((cmd_id, command))

  sock._write_command = _write
  return sock


def drain(queue):
  """Return everything currently on an asyncio.Queue, without blocking."""
  items = []
  while True:
    try:
      items.append(queue.get_nowait())
    except asyncio.QueueEmpty:
      return items


async def settle(rounds=40):
  """Let background tasks and handler callbacks run."""
  for _ in range(rounds):
    await asyncio.sleep(0)


async def serve(test, handler):
  """Run `handler` as a TCP server on 127.0.0.1 for one test; return the port.

  The server side of every connection is closed when the handler returns.
  Without that, Server.wait_closed() (3.12+) waits forever for connections
  the handler abandoned.
  """
  async def _handle(reader, writer):
    try:
      await handler(reader, writer)
    finally:
      writer.close()

  server = await asyncio.start_server(_handle, '127.0.0.1', 0)

  async def _stop():
    server.close()
    try:
      await asyncio.wait_for(server.wait_closed(), LOOP_TIMEOUT)
    except asyncio.TimeoutError:
      pass

  test.addAsyncCleanup(_stop)
  return server.sockets[0].getsockname()[1]


def reset_reconnect_history():
  """Reconnect pacing is process-wide; tests must not leak it into each other."""
  reset = getattr(risco_socket, 'reset_reconnect_history', None)
  if reset is not None:
    reset()
  elif getattr(risco_socket, '_panel_history', None) is not None:
    risco_socket._panel_history.clear()  # versions before the public reset


def patch_timing(**overrides):
  """Shrink the socket's timing constants so real-time tests run fast."""
  values = dict(
      COMMAND_TIMEOUT=0.2,
      DISCONNECT_TIMEOUT=0.2,
      KEEP_ALIVE_INTERVAL=0.05,
      RECONNECT_DELAY=0.2,
      STABLE_SESSION=2.0,
      MAX_RECONNECT_DELAY=1.6,
  )
  values.update(overrides)
  return unittest.mock.patch.multiple(risco_socket, create=True, **values)
