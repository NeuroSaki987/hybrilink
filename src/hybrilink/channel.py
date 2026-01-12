"""
hybrilink.channel
数据通道：使用 SessionKeys + ChainRatchet + AESGCM 实现加解密。
"""
from __future__ import annotations

from dataclasses import dataclass

from .crypto import ChainRatchet, make_nonce, aead_encrypt, aead_decrypt
from .protocol import DataRecord, DF_APPLICATION


@dataclass
class SecureChannel:
    session_id: bytes
    send: ChainRatchet
    recv: ChainRatchet

    @staticmethod
    def from_session_keys(keys) -> "SecureChannel":
        return SecureChannel(
            session_id=keys.session_id,
            send=ChainRatchet(keys.send_ck),
            recv=ChainRatchet(keys.recv_ck),
        )

    def encrypt(self, plaintext: bytes, flags: int = DF_APPLICATION) -> DataRecord:
        counter, mk = self.send.next_message_key()
        nonce = make_nonce(self.session_id, counter)
        aad = bytes([flags]) + self.session_id + counter.to_bytes(8, "big", signed=False)
        ct = aead_encrypt(mk, nonce, plaintext, aad)
        return DataRecord(session_id=self.session_id, counter=counter, flags=flags, ciphertext=ct)

    def decrypt(self, rec: DataRecord) -> bytes:
        if rec.session_id != self.session_id:
            raise ValueError("session_id mismatch")
        mk = self.recv.derive_key_at(rec.counter)
        nonce = make_nonce(self.session_id, rec.counter)
        aad = bytes([rec.flags]) + self.session_id + rec.counter.to_bytes(8, "big", signed=False)
        return aead_decrypt(mk, nonce, rec.ciphertext, aad)
