"""
hybrilink.client
演示客户端：完成握手后发送一条消息，读取回显。
"""
from __future__ import annotations

import argparse
import socket

from .crypto import load_ed25519_public_key_pem
from .handshake import client_start, client_finish
from .transport import FramedSocket
from .protocol import FT_SERVER_HELLO, FT_DATA, DataRecord
from .channel import SecureChannel


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--server-ed25519-pub", required=True, help="server Ed25519 public key PEM")
    ap.add_argument("--message", default="hello")
    args = ap.parse_args()

    pk = load_ed25519_public_key_pem(args.server_ed25519_pub)

    st = client_start()

    with socket.create_connection((args.host, args.port)) as sock:
        fs = FramedSocket(sock)
        fs.send_frame(st.client_hello_bytes)

        sh_bytes = fs.recv_frame()
        if sh_bytes[0] != FT_SERVER_HELLO:
            raise ValueError("expected ServerHello")

        keys = client_finish(st, sh_bytes, pk)
        chan = SecureChannel.from_session_keys(keys)
        print(f"[client] session established, session_id={keys.session_id.hex()}")

        rec = chan.encrypt(args.message.encode("utf-8"))
        fs.send_frame(rec.encode())

        payload = fs.recv_frame()
        if payload[0] != FT_DATA:
            raise ValueError("expected DataRecord")
        echoed = chan.decrypt(DataRecord.decode(payload))
        print(f"[client] recv: {echoed.decode('utf-8', errors='replace')}")


if __name__ == "__main__":
    main()
