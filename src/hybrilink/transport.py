"""
hybrilink.transport
基于 TCP socket 的 framing 发送/接收工具。
"""
from __future__ import annotations

import socket
from .protocol import frame, deframe


class FramedSocket:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = b""

    def send_frame(self, payload: bytes) -> None:
        self.sock.sendall(frame(payload))

    def recv_frame(self) -> bytes:
        while True:
            payload, rest = deframe(self.buf)
            if payload is not None:
                self.buf = rest
                return payload
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError("connection closed")
            self.buf += chunk
