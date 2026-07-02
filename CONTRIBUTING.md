# Contributing

Thanks for your interest in `chain_c`.

## Ground rules

- **Byte-exactness is the contract.** This is a faithful port: outputs that the
  upstream TypeScript layer produces (locking/unlocking scripts, receipt and
  attestation preimages, hashes, signatures, fee math) must match **byte-for-byte**.
  Changes to any of these must be pinned by a golden vector in `tests/golden/`.
- **No hand-rolled crypto.** Use `libsecp256k1`, OpenSSL `libcrypto`, and the
  vendored RIPEMD-160. Don't add new cryptographic primitives.
- **Determinism.** Pure paths must be deterministic — no wall-clock, randomness,
  or locale dependence in anything that feeds a hash or a serialized transaction.
- **Public headers under `include/` are frozen contracts.** Changing a signature
  ripples through every consumer; do it deliberately and update all call sites.

## Building and testing

```sh
sudo apt install build-essential cmake pkg-config \
     libsecp256k1-dev libssl-dev libcurl4-openssl-dev
mkdir build && cd build
cmake ..
cmake --build .
ctest --output-on-failure -LE net      # default: unit + golden + zk-gated
```

- Code must compile clean under `-Wall -Wextra` (the build uses them).
- New modules: add `src/<area>/<name>.c` + `include/<area>/<name>.h` (the lib
  GLOBs `src/**/*.c`); add a `tests/test_<name>.c` (Unity) or a
  `tests/test_<name>_golden.c` (standalone byte-exact harness).
- `net`-labelled tests must also pass **offline** via the mock HTTP transport;
  don't make the default test run depend on live network or live keys.
- For a sanitized run: `cmake .. -DCMAKE_BUILD_TYPE=Debug -DBONSAI_ASAN=ON`.

## Commits & PRs

- Keep changes focused; explain *why* in the commit body, not just *what*.
- If you touch a byte-exact path, say which golden vector covers it (or add one).
- Never include private keys, funded addresses, or machine-specific paths.

## License

By contributing you agree your contributions are licensed under the Apache
License 2.0 (see [`LICENSE`](LICENSE)).
