import asyncio
import logging
import time
from .risco_crypt import RiscoCrypt, DLE, END
from pyrisco.common import UnauthorizedError, CannotConnectError, CommunicationError, OperationError

_LOGGER = logging.getLogger(__name__)

MIN_CMD_ID = 1
MAX_CMD_ID = 49
CONNECT_TIMEOUT = 10
COMMAND_TIMEOUT = 10
# Bound both DCN and socket close, including on dead links.
DISCONNECT_TIMEOUT = 2
KEEP_ALIVE_INTERVAL = 5
# Close after consecutive unusable CLOCK answers; an identified refusal
# proves the link is alive and resets the count.
KEEP_ALIVE_MAX_FAILURES = 3
# Consecutive unreadable frames close the session to reset framing/encryption.
MAX_CORRUPTED_FRAMES = 2
# Allow the panel to reset encryption before reconnecting.
RECONNECT_DELAY = 5

# Terminal reads: retrying can spin. RiscoLocal reports ConnectionLostError.
READ_FAILURES = (OSError, EOFError, asyncio.LimitOverrunError)

# Share pacing per host/port across instances.
_panel_history = {}


class RiscoSocket:
  def __init__(self, host, port, code, **kwargs):
    self._host = host
    self._port = port
    self._code = code
    self._encoding = kwargs.get('encoding', 'utf-8')
    self._max_concurrency = kwargs.get('concurrency', 4)
    self._communication_delay = kwargs.get('communication_delay', 0)
    self._reader = None
    self._writer = None
    self._crypt = None
    self._listen_task = None
    self._keep_alive_task = None
    self._semaphore = None
    self._queue = None
    self._cmd_id = 0
    self._futures = [None] * MAX_CMD_ID
    # Shared receive order for readable replies and pushes this session.
    self._received = 0
    # Only unexpected session loss grows back-off.
    self._lost = False
    self._closing = False
    # Library-initiated close reason: failed keep-alive or unreadable frames.
    self._close_reason = None
    self._disconnect_lock = asyncio.Lock()

  @property
  def queue(self):
    return self._queue

  @property
  def close_reason(self):
    """Why the current or last session was closed by this library, or None."""
    return self._close_reason

  @property
  def concurrency(self):
    """How many commands may wait for a reply at once."""
    return self._max_concurrency

  async def connect(self):
    # Finish any old disconnect, then close any remaining session.
    async with self._disconnect_lock:
      pass
    if self._writer is not None:
      await self.disconnect()
    self._cmd_id = 0
    self._lost = False
    self._closing = False
    self._close_reason = None
    try:
      await self._wait_before_reconnect()
      self._check_not_disconnected()
      self._semaphore = asyncio.Semaphore(self._max_concurrency)
      self._futures = [None] * MAX_CMD_ID
      self._received = 0
      try:
        async with asyncio.timeout(CONNECT_TIMEOUT):
          self._reader, self._writer = await asyncio.open_connection(self._host, self._port)
      except TimeoutError:
        raise CannotConnectError(
            f'Timed out connecting to {self._host}:{self._port}') from None
      self._check_not_disconnected()
      if self._communication_delay > 0:
        await asyncio.sleep(self._communication_delay)
        self._check_not_disconnected()
      self._queue = asyncio.Queue()
      self._listen_task = asyncio.create_task(self._listen())
      self._crypt = RiscoCrypt(self._encoding)
      panel_id = int(await self.send_result_command('RID'), 16)
      self._crypt.set_panel_id(panel_id)
      if not await self.send_ack_command('LCL'):
        raise CannotConnectError('The panel did not acknowledge LCL')
      if not await self.send_ack_command(f'RMT={self._code}'):
        raise CannotConnectError('The panel did not acknowledge the login')

      self._check_not_disconnected()
      self._keep_alive_task = asyncio.create_task(self._keep_alive())
    except asyncio.CancelledError:
      # Cleanup that awaits could itself be interrupted; close synchronously.
      self._teardown()
      raise
    except (UnauthorizedError, CannotConnectError):
      await self._close()
      raise
    except Exception as exc:
      await self._close()
      # Prefer the library's close reason to the resulting command failure.
      raise CannotConnectError(self._close_reason or describe(exc)) from exc

  def _check_not_disconnected(self):
    if self._closing:
      raise CannotConnectError('disconnect() was called while connecting')

  async def disconnect(self):
    # Serialize closes so another caller cannot reconnect before close finishes.
    async with self._disconnect_lock:
      # Stop pending connects and treat EOF after DCN as deliberate.
      self._closing = True
      if self._writer is None:
        return
      try:
        # Await DCN only with a live listener; bound slot waiting and the reply.
        if self._listen_task and not self._listen_task.done():
          async with asyncio.timeout(DISCONNECT_TIMEOUT):
            await self.send_ack_command('DCN')
      except (OperationError, TimeoutError):
        # safe to ignore these when disconnecting
        pass
      finally:
        await self._close()

  def abort(self):
    """Close synchronously without DCN; cancellation cannot interrupt cleanup."""
    self._teardown()

  async def _listen(self):
    # Keep session references: teardown clears attributes before cancellation lands.
    queue, writer = self._queue, self._writer
    corrupted = 0
    given_up = False
    while self._writer is writer:
      try:
        cmd_id, command, crc = await self._read_command()
        _LOGGER.debug('Received %s %s%s', cmd_id, command, '' if crc else ' (unreadable)')
        if not crc:
          # Never deliver or ACK an unreadable frame; even its ID is untrusted.
          corrupted += 1
          # Encryption before RID means stale session state; bad plaintext only counts.
          # After a readable RID, connect() may not yet have stored the panel ID.
          early = (self._crypt is not None and self._crypt.encrypted_panel
                   and not self._crypt.has_panel_id and self._received == 0)
          if (corrupted >= MAX_CORRUPTED_FRAMES or early) and not given_up and not self._closing:
            given_up = True
            self._close_reason = (
                'The panel is still encrypting as for a previous session' if early
                else f'{corrupted} unreadable frames in a row')
            await queue.put(CommunicationError(
                f'{self._close_reason}; closing the connection'))
            self._lost = True
            # The listener then reads end-of-stream and reports the loss.
            _shut_transport(writer)
          raise CommunicationError(f'Unreadable frame (id {cmd_id})')
        corrupted = 0
        self._received += 1
        if not cmd_id:
          self._decrement_cmd_id()
          raise CommunicationError(f'Risco error: {command}')
        if cmd_id <= MAX_CMD_ID:
          future = self._futures[cmd_id-1]
          self._futures[cmd_id-1] = None
          if future is None or future.done():
            pass
          elif command[:1] in ('N', 'B'):
            future.set_exception(OperationError(f'cmd_id: {cmd_id}, Risco error: {command}'))
          else:
            # Anything else, even an empty reply, is the answer; the caller judges it.
            future.set_result(command)
        else:
          await self._handle_incoming(cmd_id, command, queue)
      except READ_FAILURES as error:
        self._fail_pending(CommunicationError('Connection lost'))
        _shut_transport(writer)
        if not self._closing:
          # Deliberate EOF, even before DCN's ACK, is not a lost session.
          self._lost = True
          await queue.put(error)
        break
      except Exception as error:
        await queue.put(error)
        # Whatever raised, never go round again without yielding.
        await asyncio.sleep(0)

  def _fail_pending(self, error):
    for i, future in enumerate(self._futures):
      if future is not None and not future.done():
        future.set_exception(error)
      self._futures[i] = None

  async def _keep_alive(self):
    queue, writer = self._queue, self._writer
    failures = 0
    refusing = False
    while True:
      try:
        await self.send_result_command("CLOCK")
        failures = 0
        refusing = False
      except Exception as error:
        if self._writer is not writer or not self._is_open():
          # Stop for a dead or replaced session; the listener reports loss.
          return
        if not isinstance(error, CommunicationError):
          # A refusal proves liveness; report only the first in a run.
          failures = 0
          if not refusing:
            await queue.put(error)
          refusing = True
        else:
          await queue.put(error)
          failures += 1
          if failures >= KEEP_ALIVE_MAX_FAILURES:
            self._close_reason = f'Keep-alive failed {failures} times in a row'
            notice = CommunicationError(f'{self._close_reason}; closing the connection')
            notice.__cause__ = error
            await queue.put(notice)
            self._lost = True
            # EOF makes the listener fail pending commands and report loss.
            _shut_transport(writer)
            return

      await asyncio.sleep(KEEP_ALIVE_INTERVAL)

  async def send_ack_command(self, command):
    command = await self.send_command(command)
    return command == 'ACK'

  async def send_result_command(self, command):
    return _value(command, await self.send_command(command))


  async def send_command(self, command, force_encryption=False):
    return await self._exchange(command, force_encryption)

  async def _exchange(self, command, force_encryption=False):
    if self._semaphore is None:
      raise CommunicationError('Not connected')
    async with self._semaphore:
      # Recheck after slot waiting: a dead-socket write may silently time out.
      if not self._is_open():
        raise CommunicationError('Not connected')
      self._increment_cmd_id()
      cmd_id = self._cmd_id
      slot = cmd_id - 1
      future = asyncio.get_running_loop().create_future()
      self._futures[slot] = future
      try:
        self._write_command(cmd_id, command, force_encryption)
        # Python 3.11 wait_for can swallow cancellation as a reply arrives.
        async with asyncio.timeout(COMMAND_TIMEOUT):
          return await future
      except TimeoutError:
        raise CommunicationError(f'Timeout in command: {_printable(command)}') from None
      finally:
        if self._futures[slot] is future:
          self._futures[slot] = None

  @property
  def connected(self):
    """Whether a session is open and its listener still running."""
    return self._is_open()

  def _is_open(self):
    if self._writer is None or self._writer.transport.is_closing():
      return False
    return self._listen_task is None or not self._listen_task.done()

  async def _handle_incoming(self, cmd_id, command, queue):
    self._write_command(cmd_id, 'ACK')
    await queue.put(command)

  async def _read_command(self):
    buffer = await self._reader.readuntil(END)
    while _end_is_escaped(buffer):
      buffer += await self._reader.readuntil(END)
    try:
      return self._crypt.decode(buffer)
    except (ValueError, IndexError):
      # Not a frame this session can read: no separator, no id, or cut short.
      return [None, '', False]

  def _write_command(self, cmd_id, command, force_encryption=False):
    _LOGGER.debug('Sent %s %s', cmd_id, _printable(command))
    buffer = self._crypt.encode(cmd_id, command, force_encryption)
    self._writer.write(buffer)

  async def _close(self):
    writer = self._teardown()
    if writer is not None:
      try:
        async with asyncio.timeout(DISCONNECT_TIMEOUT):
          await writer.wait_closed()
      except Exception:
        # Our end is already closed.
        pass

  def _teardown(self):
    """Synchronously stop tasks, fail commands and close; return writer or None."""
    current = asyncio.current_task()
    for task in (self._keep_alive_task, self._listen_task):
      if task is not None and task is not current:
        task.cancel()
    self._keep_alive_task = None
    self._listen_task = None
    self._fail_pending(CommunicationError('Connection closed'))

    writer = self._writer
    if writer is not None:
      _shut_transport(writer)
      self._record_close()
    self._crypt = None
    self._writer = None
    self._reader = None
    self._semaphore = None
    self._queue = None
    return writer

  def _record_close(self):
    _panel_history[(self._host, self._port)] = {'closed_at': time.monotonic(), 'losses': 0}

  async def _wait_before_reconnect(self):
    remaining = self._seconds_until_reconnect(time.monotonic())
    if remaining > 0:
      await asyncio.sleep(remaining)

  def _seconds_until_reconnect(self, now):
    history = _panel_history.get((self._host, self._port))
    if history is None:
      return 0
    return max(0, history['closed_at'] + RECONNECT_DELAY - now)

  def _increment_cmd_id(self):
    self._cmd_id += 1
    if self._cmd_id > MAX_CMD_ID:
      self._cmd_id = MIN_CMD_ID

  def _decrement_cmd_id(self):
    self._cmd_id -= 1
    if self._cmd_id < MIN_CMD_ID:
      self._cmd_id = MAX_CMD_ID




def _value(command, reply):
  key, separator, value = reply.partition('=')
  if not separator:
    raise CommunicationError(f'Unexpected reply to {_printable(command)}: {reply}')
  return value


def reset_reconnect_history():
  """Clear process-wide host/port pacing, e.g. for tests or a restarted panel."""
  _panel_history.clear()


def describe(error):
  """A message for an exception that may have none of its own."""
  return str(error) or type(error).__name__


def _printable(command):
  """A command as it may appear in an error or a log: never the access code."""
  return 'RMT=<code>' if command.startswith('RMT=') else command


def _end_is_escaped(buffer):
  """An END is data only after an odd DLE count; DLE DLE END ends a frame."""
  dles = len(buffer) - 1 - len(buffer[:-1].rstrip(DLE))
  return dles % 2 == 1


def _shut_transport(writer):
  if writer is None:
    return
  transport = writer.transport
  if transport.is_closing():
    return
  if transport.get_write_buffer_size():
    # close() would first wait to flush data that a dead link never takes.
    transport.abort()
  else:
    transport.close()
