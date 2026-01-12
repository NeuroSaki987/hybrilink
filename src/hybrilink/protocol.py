"""
hybrilink.protocol
消息序列化与 framing（length-prefixed）。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Tuple, Optional

from .crypto import VERSION, SUITE_ID

# Frame types
FT_CLIENT_HELLO = 1
FT_SERVER_HELLO = 2
FT_DATA = 3

# Data flags
DF_APPLICATION = 0


def pack_u16(n: int) -> bytes:
    return struct.pack(">H", n)


def unpack_u16(b: bytes) -> int:
    return struct.unpack(">H", b)[0]


def pack_u32(n: int) -> bytes:
    return struct.pack(">I", n)


def unpack_u32(b: bytes) -> int:
    return struct.unpack(">I", b)[0]


def pack_u64(n: int) -> bytes:
    return struct.pack(">Q", n)


def unpack_u64(b: bytes) -> int:
    return struct.unpack(">Q", b)[0]


def frame(payload: bytes) -> bytes:
    return pack_u32(len(payload)) + payload


def deframe(buf: bytes) -> Tuple[Optional[bytes], bytes]:
    """从缓冲区中解析一帧：返回 (payload_or_none, remaining_buf)。"""
    if len(buf) < 4:
        return None, buf
    n = unpack_u32(buf[:4])
    if n > 10 * 1024 * 1024:
        raise ValueError("frame too large")
    if len(buf) < 4 + n:
        return None, buf
    return buf[4:4+n], buf[4+n:]


@dataclass
class ClientHello:
    version: int
    suite: int
    client_nonce: bytes  # 16
    client_eph_pub: bytes  # 32

    def encode(self) -> bytes:
        if len(self.client_nonce) != 16:
            raise ValueError("client_nonce must be 16 bytes")
        if len(self.client_eph_pub) != 32:
            raise ValueError("client_eph_pub must be 32 bytes")
        return bytes([FT_CLIENT_HELLO, self.version, self.suite]) + self.client_nonce + self.client_eph_pub

    @staticmethod
    def decode(b: bytes) -> "ClientHello":
        if len(b) != 1 + 1 + 1 + 16 + 32:
            raise ValueError("bad ClientHello length")
        if b[0] != FT_CLIENT_HELLO:
            raise ValueError("not ClientHello")
        return ClientHello(version=b[1], suite=b[2], client_nonce=b[3:19], client_eph_pub=b[19:51])


@dataclass
class ServerHello:
    version: int
    suite: int
    server_nonce: bytes  # 16
    server_eph_pub: bytes  # 32
    signature: bytes  # 64 for Ed25519

    def encode_without_sig(self) -> bytes:
        if len(self.server_nonce) != 16:
            raise ValueError("server_nonce must be 16 bytes")
        if len(self.server_eph_pub) != 32:
            raise ValueError("server_eph_pub must be 32 bytes")
        return bytes([FT_SERVER_HELLO, self.version, self.suite]) + self.server_nonce + self.server_eph_pub

    def encode(self) -> bytes:
        body = self.encode_without_sig()
        return body + pack_u16(len(self.signature)) + self.signature

    @staticmethod
    def decode(b: bytes) -> "ServerHello":
        if len(b) < 1 + 1 + 1 + 16 + 32 + 2:
            raise ValueError("bad ServerHello length")
        if b[0] != FT_SERVER_HELLO:
            raise ValueError("not ServerHello")
        version = b[1]
        suite = b[2]
        server_nonce = b[3:19]
        server_eph_pub = b[19:51]
        sig_len = unpack_u16(b[51:53])
        sig = b[53:53+sig_len]
        if len(sig) != sig_len:
            raise ValueError("truncated signature")
        return ServerHello(version=version, suite=suite, server_nonce=server_nonce, server_eph_pub=server_eph_pub, signature=sig)


@dataclass
class DataRecord:
    session_id: bytes  # 16
    counter: int       # u64
    flags: int         # u8
    ciphertext: bytes

    def encode(self) -> bytes:
        if len(self.session_id) != 16:
            raise ValueError("session_id must be 16 bytes")
        return bytes([FT_DATA]) + self.session_id + pack_u64(self.counter) + bytes([self.flags]) + self.ciphertext

    @staticmethod
    def decode(b: bytes) -> "DataRecord":
        if len(b) < 1 + 16 + 8 + 1:
            raise ValueError("bad DataRecord length")
        if b[0] != FT_DATA:
            raise ValueError("not DataRecord")
        sid = b[1:17]
        ctr = unpack_u64(b[17:25])
        flags = b[25]
        ct = b[26:]
        return DataRecord(session_id=sid, counter=ctr, flags=flags, ciphertext=ct)


def validate_hello(version: int, suite: int) -> None:
    if version != VERSION:
        raise ValueError(f"unsupported version {version}")
    if suite != SUITE_ID:
        raise ValueError(f"unsupported suite {suite}")
