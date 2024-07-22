from pwnlib.tubes.tube import tube
import os
import pyda_core
import errno

# todo
class ProcessTube(tube):
    def __init__(self, stdin_fd, stdout_fd, **kwargs):
        super(ProcessTube, self).__init__(**kwargs)

        self.closed = {"recv": False, "send": False}

        self.stdin_fd = stdin_fd
        self.stdout_fd = stdout_fd

    # Overwritten for better usability
    def recvall(self, timeout = None):
        """recvall() -> str

        Receives data until the socket is closed.
        """
        # todo
        raise NotImplementedError("recvall() not implemented")

    def recv_raw(self, numb, *a):
        if self.closed["recv"]:
            raise EOFError
        
        if len(a) > 0:
            raise NotImplementedError("recv_raw() with flags not implemented")

        while True:
            try:
                data = os.read(self.stdout_fd, numb)
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
        if self.closed["send"]:
            raise EOFError

        try:
            os.write(self.stdin_fd, data)
        except IOError as e:
            eof_numbers = (errno.EPIPE, errno.ECONNRESET, errno.ECONNREFUSED)
            if e.errno in eof_numbers or 'Socket is closed' in e.args:
                self.shutdown("send")
                raise EOFError
            else:
                raise

    def settimeout_raw(self, timeout):
        raise NotImplementedError("settimeout_raw() not implemented")

    def can_recv_raw(self, timeout):
        if self.closed["recv"]:
            return False

        try:
            if timeout is None:
                return select.select([self.stdout_fd], [], []) == ([self.stdout_fd], [], [])

            return select.select([self.stdout_fd], [], [], timeout) == ([self.stdout_fd], [], [])
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
    
    def interactive(self):
        self.error("interactive() is not currently supported.")
