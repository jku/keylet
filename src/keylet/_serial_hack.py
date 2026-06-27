import os
import select
import sys

if sys.platform == "linux":
    import array
    import fcntl
    import termios

from typing import Protocol


class SerialConnection(Protocol):
    timeout: float

    def read(self, n: int) -> bytes: ...
    def write(self, data: bytes) -> int: ...
    def close(self) -> None: ...

    @property
    def in_waiting(self) -> int: ...


class RawSerialConnection:
    """A Linux specific raw Python serial connection.

    This helper exists because pyserial does not work with glibc >=2.42:
    https://github.com/pyserial/pyserial/commit/70d18864 is the missing bug fix.
    """

    def __init__(self, port: str, baudrate: int, timeout: float) -> None:
        self.timeout = timeout
        self._fd: int | None = self._open(port, baudrate)

    def _open(self, port: str, baudrate: int) -> int:
        fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        try:
            # 1. Use termios to configure raw 8N1 mode
            attrs = termios.tcgetattr(fd)

            # Clear input processing
            attrs[0] &= ~(
                termios.IGNBRK
                | termios.BRKINT
                | termios.PARMRK
                | termios.ISTRIP
                | termios.INLCR
                | termios.IGNCR
                | termios.ICRNL
                | termios.IXON
                | termios.IXOFF
                | termios.IXANY
                | termios.INPCK
            )
            # Clear output processing (raw output)
            attrs[1] &= ~termios.OPOST
            # Clear local modes (no echo, no signals, no canonical input)
            attrs[3] &= ~(
                termios.ECHO
                | termios.ECHONL
                | termios.ICANON
                | termios.ISIG
                | termios.IEXTEN
            )
            # Clear control modes (no size, parity, stop bits, flow control)
            attrs[2] &= ~(
                termios.CSIZE | termios.PARENB | termios.CSTOPB | termios.CRTSCTS
            )
            attrs[2] |= termios.CS8 | termios.CREAD | termios.CLOCAL

            # Set speed using standard constants (this is changed below)
            attrs[4] = termios.B9600
            attrs[5] = termios.B9600

            termios.tcsetattr(fd, termios.TCSANOW, attrs)

            # 2. Use termios2 to set the custom 62500 baud rate
            tcgets2 = 0x802C542A
            tcsets2 = 0x402C542B
            bother = 0o010000

            buf = array.array("i", [0] * 64)
            fcntl.ioctl(fd, tcgets2, buf)

            buf[2] &= ~0x100F  # Clear CBAUD/CBAUDEX speed flags
            buf[2] |= bother  # Flag for custom speed (BOTHER)
            buf[9] = buf[10] = baudrate  # Set custom speed

            fcntl.ioctl(fd, tcsets2, buf)

            # 3. Restore blocking mode
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)

            # 4. Acquire exclusive access
            tiocexcl = 0x540C
            fcntl.ioctl(fd, tiocexcl, 0)

            return fd
        except Exception:
            os.close(fd)
            raise

    def write(self, data: bytes) -> int:
        if self._fd is None:
            raise ValueError("Port is closed")
        return os.write(self._fd, data)

    def read(self, n: int) -> bytes:
        """Read exactly n bytes blockingly, respecting the configured timeout."""
        if self._fd is None:
            raise ValueError("Port is closed")
        data = bytearray()
        while len(data) < n:
            r, _, _ = select.select([self._fd], [], [], self.timeout)
            if not r:
                break  # Timeout
            chunk = os.read(self._fd, n - len(data))
            if len(chunk) == 0:
                break  # EOF/Disconnect
            data.extend(chunk)
        return bytes(data)

    def reset_input_buffer(self) -> None:
        pass

    def reset_output_buffer(self) -> None:
        pass

    @property
    def in_waiting(self) -> int:
        if self._fd is None:
            return 0
        buf = array.array("i", [0])
        try:
            fcntl.ioctl(self._fd, termios.FIONREAD, buf)
            return buf[0]
        except Exception:
            return 0

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
