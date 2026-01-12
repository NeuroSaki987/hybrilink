"""
hybrilink.handshake
握手：ClientHello / ServerHello，派生会话密钥并返回会话上下文。
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519

from .crypto import x25519_keypair, x25519_load_public, derive_session_keys, SessionKeys
from .protocol import ClientHello, ServerHello, validate_hello


@dataclass
class ClientHandshakeState:
    client_nonce: bytes
    client_eph_priv: object
    client_eph_pub: bytes
    client_hello_bytes: bytes


def client_start() -> ClientHandshakeState:
    client_nonce = os.urandom(16)
    priv, pub = x25519_keypair()
    ch = ClientHello(version=1, suite=1, client_nonce=client_nonce, client_eph_pub=pub)
    ch_bytes = ch.encode()
    return ClientHandshakeState(
        client_nonce=client_nonce,
        client_eph_priv=priv,
        client_eph_pub=pub,
        client_hello_bytes=ch_bytes,
    )


def client_finish(
    st: ClientHandshakeState,
    server_hello_bytes: bytes,
    server_ed25519_pub: ed25519.Ed25519PublicKey,
) -> SessionKeys:
    sh = ServerHello.decode(server_hello_bytes)
    validate_hello(sh.version, sh.suite)

    # Verify signature
    tbs = st.client_hello_bytes + sh.encode_without_sig()
    server_ed25519_pub.verify(sh.signature, tbs)

    # ECDH
    server_eph_pub = x25519_load_public(sh.server_eph_pub)
    shared = st.client_eph_priv.exchange(server_eph_pub)

    transcript = tbs + sh.signature  # bind signature too
    return derive_session_keys(
        shared_secret=shared,
        client_nonce=st.client_nonce,
        server_nonce=sh.server_nonce,
        transcript=transcript,
        is_client=True,
    )


def server_respond(
    client_hello_bytes: bytes,
    server_ed25519_priv: ed25519.Ed25519PrivateKey,
) -> Tuple[bytes, SessionKeys]:
    ch = ClientHello.decode(client_hello_bytes)
    validate_hello(ch.version, ch.suite)

    server_nonce = os.urandom(16)
    s_priv, s_pub = x25519_keypair()

    sh_tmp = ServerHello(version=1, suite=1, server_nonce=server_nonce, server_eph_pub=s_pub, signature=b"")
    tbs = client_hello_bytes + sh_tmp.encode_without_sig()
    sig = server_ed25519_priv.sign(tbs)

    sh = ServerHello(version=1, suite=1, server_nonce=server_nonce, server_eph_pub=s_pub, signature=sig)
    sh_bytes = sh.encode()

    # ECDH
    client_eph_pub = x25519_load_public(ch.client_eph_pub)
    shared = s_priv.exchange(client_eph_pub)

    transcript = tbs + sig
    keys = derive_session_keys(
        shared_secret=shared,
        client_nonce=ch.client_nonce,
        server_nonce=server_nonce,
        transcript=transcript,
        is_client=False,
    )
    return sh_bytes, keys
