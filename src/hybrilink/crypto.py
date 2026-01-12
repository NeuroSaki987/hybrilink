"""
hybrilink.crypto
核心密码学构件：X25519 + Ed25519 + HKDF + AESGCM + HMAC-based chain ratchet

注意：本项目为教学/原型，未实现完整的乱序处理、重传、密钥更新协商等生产级细节。
"""
from __future__ import annotations

import hmac
import hashlib
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


SUITE_ID = 1  # X25519 + Ed25519 + HKDF-SHA256 + AES-256-GCM + HMAC ratchet
VERSION = 1


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hkdf_extract_expand(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Extract + HKDF-Expand (SHA-256)."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(ikm)


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """Expand-only HKDF (SHA-256). 这里将 prk 视为 HKDF PRK。"""
    exp = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info)
    return exp.derive(prk)


@dataclass
class SessionKeys:
    session_id: bytes  # 16 bytes
    send_ck: bytes     # 32 bytes
    recv_ck: bytes     # 32 bytes


class ChainRatchet:
    """
    简化对称链式密钥演进（symmetric-key ratchet）：
    - 每发送/接收一条消息，基于当前 chain key 生成 message key，
      再单向推进到 next chain key。
    - 仅假设 TCP 等“可靠有序”传输：否则需要实现 skipped keys 窗口。
    """
    def __init__(self, chain_key: bytes):
        if len(chain_key) != 32:
            raise ValueError("chain_key must be 32 bytes")
        self.ck = chain_key
        self.counter = 0

    def _hmac(self, key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, hashlib.sha256).digest()

    def next_message_key(self) -> Tuple[int, bytes]:
        ctr = self.counter
        ctr_bytes = ctr.to_bytes(8, "big", signed=False)
        mk = self._hmac(self.ck, b"msg|" + ctr_bytes)
        self.ck = self._hmac(self.ck, b"ck|" + ctr_bytes)
        self.counter += 1
        return ctr, mk  # mk: 32 bytes

    def derive_key_at(self, expected_counter: int) -> bytes:
        """接收端“严格顺序”场景：record counter != 本地 counter 则拒绝（避免乱序/重放）。"""
        if expected_counter != self.counter:
            raise ValueError(f"out-of-order or replay: expected {self.counter}, got {expected_counter}")
        _, mk = self.next_message_key()
        return mk


def aead_encrypt(key32: bytes, nonce12: bytes, plaintext: bytes, aad: bytes) -> bytes:
    if len(key32) != 32:
        raise ValueError("AESGCM key must be 32 bytes")
    if len(nonce12) != 12:
        raise ValueError("AESGCM nonce must be 12 bytes")
    return AESGCM(key32).encrypt(nonce12, plaintext, aad)


def aead_decrypt(key32: bytes, nonce12: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    if len(key32) != 32:
        raise ValueError("AESGCM key must be 32 bytes")
    if len(nonce12) != 12:
        raise ValueError("AESGCM nonce must be 12 bytes")
    return AESGCM(key32).decrypt(nonce12, ciphertext, aad)


def load_ed25519_private_key_pem(path: str) -> ed25519.Ed25519PrivateKey:
    data = open(path, "rb").read()
    return serialization.load_pem_private_key(data, password=None)


def load_ed25519_public_key_pem(path: str) -> ed25519.Ed25519PublicKey:
    data = open(path, "rb").read()
    return serialization.load_pem_public_key(data)


def save_ed25519_private_key_pem(key: ed25519.Ed25519PrivateKey, path: str) -> None:
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    open(path, "wb").write(pem)


def save_ed25519_public_key_pem(key: ed25519.Ed25519PublicKey, path: str) -> None:
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    open(path, "wb").write(pem)


def x25519_keypair() -> Tuple[x25519.X25519PrivateKey, bytes]:
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub


def x25519_load_public(raw32: bytes) -> x25519.X25519PublicKey:
    if len(raw32) != 32:
        raise ValueError("X25519 public key must be 32 bytes")
    return x25519.X25519PublicKey.from_public_bytes(raw32)


def derive_session_keys(
    shared_secret: bytes,
    client_nonce: bytes,
    server_nonce: bytes,
    transcript: bytes,
    is_client: bool,
) -> SessionKeys:
    """
    以握手 transcript hash 作为盐，绑定上下文，减少跨协议/降级类风险。
    """
    salt = sha256(transcript)
    ikm = shared_secret + client_nonce + server_nonce

    master = hkdf_extract_expand(ikm=ikm, salt=salt, info=b"hybrilink|master", length=32)
    session_id = sha256(b"hybrilink|sid|" + transcript)[:16]

    ck_c2s = hkdf_expand(master, info=b"hybrilink|ck|c2s", length=32)
    ck_s2c = hkdf_expand(master, info=b"hybrilink|ck|s2c", length=32)

    if is_client:
        send_ck, recv_ck = ck_c2s, ck_s2c
    else:
        send_ck, recv_ck = ck_s2c, ck_c2s

    return SessionKeys(session_id=session_id, send_ck=send_ck, recv_ck=recv_ck)


def make_nonce(session_id: bytes, counter: int) -> bytes:
    """
    12字节 nonce：session_id 前4字节 + 8字节 counter
    注意：对于 AES-GCM，nonce 对于同一个 key 必须不重复。
    本协议每条消息使用独立 message key（由 ratchet 推导），因此 nonce=counter 仍保持规范性与可读性。
    """
    if len(session_id) != 16:
        raise ValueError("session_id must be 16 bytes")
    return session_id[:4] + counter.to_bytes(8, "big", signed=False)
