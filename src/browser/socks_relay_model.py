"""Offline SOCKS5 handshake model. It never opens a network connection."""
from dataclasses import dataclass
import re


@dataclass(frozen=True)
class SocksModelResult:
    diagnostic: str
    proxy_status: str = 'unconfirmed'
    may_launch: bool = False


def _read_exact(stream, count):
    result = bytearray()
    while len(result) < count:
        chunk = stream.recv(count - len(result))
        if not chunk:
            raise OSError('incomplete synthetic response')
        result.extend(chunk)
    return bytes(result)


def inspect_socks_exchange(stream, host, port):
    """Exercise protocol bytes on an injected fixture; no sockets or fallback."""
    try:
        if (not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9.-]+', host)
                or not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535):
            return SocksModelResult('rejected')
        encoded = host.encode('ascii')
        if not 1 <= len(encoded) <= 255:
            return SocksModelResult('rejected')
        stream.sendall(b'\x05\x01\x00')
        if _read_exact(stream, 2) != b'\x05\x00':
            return SocksModelResult('rejected')
        stream.sendall(b'\x05\x01\x00\x03' + bytes([len(encoded)]) + encoded + port.to_bytes(2, 'big'))
        reply = _read_exact(stream, 4)
        if reply[:3] != b'\x05\x00\x00':
            return SocksModelResult('rejected')
        if reply[3] == 1:
            address_length = 4
        elif reply[3] == 4:
            address_length = 16
        elif reply[3] == 3:
            address_length = _read_exact(stream, 1)[0]
            if not address_length:
                return SocksModelResult('rejected')
        else:
            return SocksModelResult('rejected')
        _read_exact(stream, address_length + 2)
        return SocksModelResult('candidate')
    except (OSError, TypeError, ValueError, UnicodeError):
        return SocksModelResult('rejected')
    finally:
        try:
            stream.close()
        except OSError:
            pass
