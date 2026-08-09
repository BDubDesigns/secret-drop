#!/usr/bin/env python3
"""
decrypt_to_file.py -- fetch a Secret-Drop link and write the plaintext to a file.

Usage (agent side):
    python3 decrypt_to_file.py "<link>" /path/to/target/file

The link looks like:  https://<host>/<id>.<keybase64>
The fragment carries the one-time id + the AES-GCM key. We fetch GET /out/<id>
from the same origin, decrypt with the key, and write the plaintext to the
target file. NOTHING is printed to stdout -- the value goes straight to disk,
so the agent never sees it in context.

The target file is appended to (so it can coexist with other content in .env),
unless --overwrite is passed.
"""

import argparse
import base64
import pathlib
import sys
import urllib.request


def decrypt(ct_b64: str, iv_b64: str, key_b64: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ct_b64)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ct, None)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("link", help="full Secret-Drop link (with #fragment)")
    ap.add_argument("target", help="path to write the decrypted secret to")
    ap.add_argument("--overwrite", action="store_true", help="overwrite target instead of append")
    args = ap.parse_args()

    if "#" not in args.link:
        print("error: link has no decryption-key fragment", file=sys.stderr)
        return 2
    base, frag = args.link.split("#", 1)
    if "." not in frag:
        print("error: malformed fragment (expected <id>.<key>)", file=sys.stderr)
        return 2
    secret_id, key_b64 = frag.split(".", 1)

    with urllib.request.urlopen(base.rstrip("/") + "/out/" + secret_id) as resp:
        data = resp.read()
    import json as _json
    obj = _json.loads(data)
    if "payload" not in obj or "iv" not in obj:
        print("error: bad response from server", file=sys.stderr)
        return 3

    plaintext = decrypt(obj["payload"], obj["iv"], key_b64)

    target = pathlib.Path(args.target)
    target.parent.mkdir(parents=True, exist_ok=True)
    mode = "ab" if (not args.overwrite and target.exists()) else "wb"
    with open(target, mode) as fh:
        fh.write(plaintext)
        if not plaintext.endswith(b"\n"):
            fh.write(b"\n")
    print(f"ok: wrote {len(plaintext)} bytes to {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())