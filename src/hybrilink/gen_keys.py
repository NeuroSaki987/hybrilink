"""
生成服务器 Ed25519 身份密钥（PEM）。
"""
from __future__ import annotations

import argparse
import os
from cryptography.hazmat.primitives.asymmetric import ed25519

from .crypto import save_ed25519_private_key_pem, save_ed25519_public_key_pem


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default="keys", help="output directory")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()

    save_ed25519_private_key_pem(priv, os.path.join(args.outdir, "server_ed25519.pem"))
    save_ed25519_public_key_pem(pub, os.path.join(args.outdir, "server_ed25519_pub.pem"))

    print(f"written: {args.outdir}/server_ed25519.pem")
    print(f"written: {args.outdir}/server_ed25519_pub.pem")


if __name__ == "__main__":
    main()
