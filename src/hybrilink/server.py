"""
hybrilink.server
演示服务器：接受单连接，完成握手后回显客户端消息。
"""
from __future__ import annotations

import argparse
import socket

from .crypto import load_ed25519_private_key_pem
from .handshake import server_respond
from .transport import FramedSocket
from .protocol import FT_CLIENT_HELLO, FT_DATA, DataRecord
from .channel import SecureChannel


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--server-ed25519", required=True, help="server Ed25519 private key PEM")
    args = ap.parse_args()

    sk = load_ed25519_private_key_pem(args.server_ed25519)

    with socket.create_server((args.host, args.port), reuse_port=False) as srv:
        print(f"[server] listening on {args.host}:{args.port}")
        conn, addr = srv.accept()
        print(f"[server] accepted from {addr}")
        with conn:
            fs = FramedSocket(conn)

            ch_bytes = fs.recv_frame()
            if ch_bytes[0] != FT_CLIENT_HELLO:
                raise ValueError("expected ClientHello")

            sh_bytes, keys = server_respond(ch_bytes, sk)
            fs.send_frame(sh_bytes)
            chan = SecureChannel.from_session_keys(keys)
            print(f"[server] session established, session_id={keys.session_id.hex()}")

            while True:
                payload = fs.recv_frame()
                if payload[0] != FT_DATA:
                    raise ValueError("expected DataRecord")
                rec = DataRecord.decode(payload)
                pt = chan.decrypt(rec)
                print(f"[server] recv: {pt!r}")

                echo = chan.encrypt(b"echo: " + pt)
                fs.send_frame(echo.encode())


if __name__ == "__main__":
    main()
