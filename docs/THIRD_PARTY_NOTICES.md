# Third-party notices

## PyNaCl 1.6.2

Used by `decrypt_to_file.py` for the receiver-side `SealedBox` API. PyNaCl is
licensed under the Apache License 2.0. Its normal PyPI wheel bundles the
receiver-side libsodium implementation; that is separate from the vendored
browser libsodium module. The dependency is pinned in `requirements.txt`.

## python-dotenv 1.2.2 (development verification)

Used only by the test suite to load generated `.env` files under normal
python-dotenv/Hermes interpolation semantics. It is licensed under BSD-3-Clause
and is pinned in `requirements-dev.txt`; it is not a `shh` runtime dependency.

## libsodium 0.8.4

Used by the browser module. The vendored browser file is
`vendor/libsodium.mjs`; its license text is `vendor/LICENSE.libsodium`.

## libsodium-wrappers 0.8.4

Used as the browser-facing JavaScript API for `crypto_box_seal`. The vendored
browser file is `vendor/libsodium-wrappers.mjs`; its license text is
`vendor/LICENSE.libsodium-wrappers`.

Both browser packages are obtained from the npm registry versions recorded in
this repository and served locally. The application does not load crypto code
from a CDN at runtime.
