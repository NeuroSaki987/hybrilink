import os
from cryptography.hazmat.primitives.asymmetric import ed25519

from hybrilink.crypto import save_ed25519_private_key_pem, save_ed25519_public_key_pem
from hybrilink.crypto import load_ed25519_private_key_pem, load_ed25519_public_key_pem
from hybrilink.handshake import server_respond, client_start, client_finish
from hybrilink.channel import SecureChannel


def test_handshake_and_encrypt_roundtrip(tmp_path):
    outdir = tmp_path / "keys"
    os.makedirs(outdir, exist_ok=True)

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    save_ed25519_private_key_pem(priv, str(outdir / "server_ed25519.pem"))
    save_ed25519_public_key_pem(pub, str(outdir / "server_ed25519_pub.pem"))

    server_sk = load_ed25519_private_key_pem(str(outdir / "server_ed25519.pem"))
    server_pk = load_ed25519_public_key_pem(str(outdir / "server_ed25519_pub.pem"))

    st = client_start()
    sh_bytes, s_keys = server_respond(st.client_hello_bytes, server_sk)
    c_keys = client_finish(st, sh_bytes, server_pk)

    s_chan = SecureChannel.from_session_keys(s_keys)
    c_chan = SecureChannel.from_session_keys(c_keys)

    msg = b"abc"
    rec = c_chan.encrypt(msg)
    pt = s_chan.decrypt(rec)
    assert pt == msg
