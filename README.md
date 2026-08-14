# ISEKAI-util

Shared helpers for ISEKAI Link, extracted from
[`ISEKAI-link-server`](https://github.com/seera-networks/ISEKAI-link-server) so
that the server and other consumers can depend on one copy.

## Modules

- `acme.rs` — ACME certificate issuance
  ([`instant-acme`](https://github.com/seera-networks/instant-acme), our fork).
  Two entry points: `ensure_certificate()` generates the key pair here and
  writes cert / key / PKCS#12, while `issue_certificate_with_csr()` signs a CSR
  the caller supplies and returns the chain — that path never sees the
  certificate's private key, so there is no key or PKCS#12 to write.
- `dns.rs` — DNS resolution ([hickory](https://github.com/hickory-dns/hickory-dns)).
- `secure_fs.rs` — hardened file I/O; enforces `0600` permissions on key material.
- `pop.rs` — P2P Connect Proof-of-Possession primitives: RFC 7638 JWK thumbprints,
  Endpoint ID derivation, the canonical request string and ECDSA P-256 signature
  verification.

## Layout

A single crate at the repository root — `Cargo.toml` beside `src/`. Dependency
versions are written out in `Cargo.toml` rather than inherited from a workspace,
because the crate is consumed as a git dependency and has to resolve on its own.

## Build and test

```sh
cargo build
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

No native dependencies beyond OpenSSL: nothing here pulls in the msquic /
QUIC transport stack that the server needs.

## Conventions

- **Never write key material without `secure_fs`.** It creates files `0600` and
  refuses to widen an existing mode. `.pem` / `.key` / `.p12` / `.pfx` are
  gitignored.
- `instant-acme` is pinned to an exact git rev of
  [our fork](https://github.com/seera-networks/instant-acme), which adds the
  `Csr` type, `Order::finalize_with()` and `Order::validate_csr()` that
  `issue_certificate_with_csr()` is built on (features `fs` and `x509-parser`).
  Consumers enforce an allow-list of git sources (`deny.toml`), so both the
  source URL and the rev have to be reflected there.

## Consumers

- [`ISEKAI-link-server`](https://github.com/seera-networks/ISEKAI-link-server) —
  depends on this repository by git rev.
