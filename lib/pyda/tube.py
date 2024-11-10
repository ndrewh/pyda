from pwnlib.tubes.tube import tube
from pwnlib.context import context
from pwnlib import term
import sys
import os
import pyda_core
import errno
import threading
import select

# todo
class ProcessTube(tube):
    def __init__(self, stdin_fd, stdout_fd, **kwargs):
        super(ProcessTube, self).__init__(**kwargs)

        self.closed = {"recv": False, "send": False}
        if stdin_fd is None or stdout_fd is None:
            self.closed["recv"] = True
            self.closed["send"] = True
            self._captured = False
        else:
            self._captured = True

        self._stdin_fd = stdin_fd
        self._stdout_fd = stdout_fd

        # real_stdin is what is connected to the user's terminal.
        # used for p.interactive() (note: sys.stdin may be buffered
        # even if PYTHONUNBUFFERED)
        self._real_stdin = os.fdopen(sys.stdin.fileno(), 'rb', 0)

    # Overwritten for better usability
    def recvall(self, timeout = None):
        """recvall() -> str

        Receives data until the socket is closed.
        """
        # todo
        raise NotImplementedError("recvall() not implemented")

    def recv_raw(self, numb, *a):
        if not self._captured:
            raise RuntimeError("I/O must be explicitly captured using process(io=True)")

        if self.closed["recv"]:
            raise EOFError

        if len(a) > 0:
            raise NotImplementedError("recv_raw() with flags not implemented")

        while True:
            try:
                data = os.read(self._stdout_fd, numb)
                break
            except IOError as e:
                if e.errno == errno.EAGAIN:
                    # If we're waiting for data, let the program continue
                    try:
                        self._p.run_until_io()
                        continue
                    except Exception as e:
                        raise EOFError

                if e.errno == errno.ETIMEDOUT or 'timed out' in e.strerror:
                    return None
                elif e.errno in (errno.ECONNREFUSED, errno.ECONNRESET):
                    self.shutdown("recv")
                    raise EOFError
                elif e.errno == errno.EINTR:
                    continue
                else:
                    raise

        if not data:
            self.shutdown("recv")
            raise EOFError

        return data

    # TODO: What happens when the pipe fills? This call
    # will indefinitely block?
    def send_raw(self, data):
        if not self._captured:
            raise RuntimeError("I/O must be explicitly captured using process(io=True)")

        if self.closed["send"]:
            raise EOFError

        ptr = 0
        while ptr < len(data):
            try:
                count = os.write(self._stdin_fd, data[ptr:])
                ptr += count
            except IOError as e:
                eof_numbers = (errno.EPIPE, errno.ECONNRESET, errno.ECONNREFUSED)
                if e.errno in eof_numbers or 'Socket is closed' in e.args:
                    self.shutdown("send")
                    raise EOFError
                elif e.errno == errno.EAGAIN:
                    # If we're waiting for data, let the program continue
                    try:
                        self._p.run_until_io()
                        continue
                    except Exception as e:
                        raise EOFError
                else:
                    raise

    def settimeout_raw(self, timeout):
        raise NotImplementedError("settimeout_raw() not implemented")

    def can_recv_raw(self, timeout):
        if not self._captured:
            raise RuntimeError("I/O must be explicitly captured using process(io=True)")

        if self.closed["recv"]:
            return False

        try:
            if timeout is None:
                return select.select([self._stdout_fd], [], []) == ([self._stdout_fd], [], [])

            return select.select([self._stdout_fd], [], [], timeout) == ([self._stdout_fd], [], [])
        except ValueError:
            # Not sure why this isn't caught when testing self.proc.stdout.closed,
            # but it's not.
            #
            #   File "/home/user/pwntools/pwnlib/tubes/process.py", line 112, in can_recv_raw
            #     return select.select([self.proc.stdout], [], [], timeout) == ([self.proc.stdout], [], [])
            # ValueError: I/O operation on closed file
            raise EOFError
        except select.error as v:
            if v.args[0] == errno.EINTR:
                return False

    def connected_raw(self, direction):
        return True

    def close(self):
        pass

    def _close_msg(self):
        self.info('Closed pyda socket')

    def fileno(self):
        self.error("fileno() not implemented")
        return None

    def shutdown_raw(self, direction):
        pass

    # This code is taken from pwnlib.tubes
    def interactive(self, prompt=term.text.bold_red('$') + ' '):
        if not self._captured:
            raise RuntimeError("I/O must be explicitly captured using process(io=True)")

        self.info('Switching to interactive mode')

        go = threading.Event()
        def send_thread():
            from pwnlib.args import term_mode
            os_linesep = os.linesep.encode()
            to_skip = b''
            while not go.is_set():
                if term.term_mode:
                    # note: this case is not tested
                    data = term.readline.readline(prompt = prompt, float = True)
                    if data.endswith(b'\n') and self.newline != b'\n':
                        data = data[:-1] + self.newline
                else:
                    stdin = self._real_stdin
                    while True:
                        can_read = select.select([stdin], [], [], 0.1) == ([stdin], [], [])
                        if can_read:
                            data = stdin.read(1)
                            break
                        elif go.is_set():
                            data = b''
                            break

                    # Keep OS's line separator if NOTERM is set and
                    # the user did not specify a custom newline
                    # even if stdin is a tty.
                    if sys.stdin.isatty() and (
                        term_mode
                        or context.newline != b"\n"
                        or self._newline is not None
                    ):
                        if to_skip:
                            if to_skip[:1] != data:
                                data = os_linesep[: -len(to_skip)] + data
                            else:
                                to_skip = to_skip[1:]
                                if to_skip:
                                    continue
                                data = self.newline
                        # If we observe a prefix of the line separator in a tty,
                        # assume we'll see the rest of it immediately after.
                        # This could stall until the next character is seen if
                        # the line separator is started but never finished, but
                        # that is unlikely to happen in a dynamic tty.
                        elif data and os_linesep.startswith(data):
                            if len(os_linesep) > 1:
                                to_skip = os_linesep[1:]
                                continue
                            data = self.newline
                    else:
                        raise RuntimeError("interactive() called not attached to TTY")

                if data:
                    try:
                        self.send(data)
                    except EOFError:
                        go.set()
                        self.info('Got EOF while sending in interactive')
                else:
                    go.set()

        t = context.Thread(target=send_thread)
        t.daemon = True
        t.start()

        # Recv thread -- must be main thread
        while not go.is_set():
            try:
                cur = self.recv(timeout = 0.05)
                cur = cur.replace(self.newline, b'\n')
                if cur:
                    stdout = sys.stdout
                    if not term.term_mode:
                        stdout = getattr(stdout, 'buffer', stdout)
                    stdout.write(cur)
                    stdout.flush()
            except EOFError:
                self.info('Got EOF while reading in interactive')
                go.set()
                break
            except KeyboardInterrupt:
                self.info('Interrupted')
                go.set()
                break

        while t.is_alive():
            t.join(timeout = 0.1)
