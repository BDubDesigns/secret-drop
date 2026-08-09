# Third-party notices

## PyNaCl 1.6.0

Used by `decrypt_to_file.py` for the receiver-side `SealedBox` API. PyNaCl is
licensed under the Apache License 2.0. It binds to the system/libsodium crypto
implementation. The dependency is pinned in `requirements.txt`.

## libsodium 0.8.4

Used by the browser module and indirectly by PyNaCl. The vendored browser file
is `vendor/libsodium.mjs`; its license text is `vendor/LICENSE.libsodium`.

## libsodium-wrappers 0.8.4

Used as the browser-facing JavaScript API for `crypto_box_seal`. The vendored
browser file is `vendor/libsodium-wrappers.mjs`; its license text is
`vendor/LICENSE.libsodium-wrappers`.

Both browser packages are obtained from the npm registry versions recorded in
this repository and served locally. The application does not load crypto code
from a CDN at runtime.
