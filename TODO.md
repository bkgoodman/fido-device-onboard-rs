# TODO — Known Deficiencies (fido-device-onboard-rs)

Known gaps in the Rust device client (`client-linuxapp`) and `data-formats`,
recorded so they are not mistaken for "done". The current priority is
interoperability with go-fdo, not feature parity: items here are documented,
not scheduled.

Reference implementations:
- **fdo-uefi-rs** implements the full `fdo.bmo` authorization model and its
  decision logic (`check_bmo_authorization`, the `*_hash_decision`
  functions, `check_setup_device20`, `verify_delegate_chain`).
- **go-fdo** is the interop peer (`test_rust_fdo20_interop.sh`).

Specs: `fdo-sim/fsim-repository/fdo.bmo.md` and `chunking-strategy.md`;
`FIDO-IoT-spec.bs` branch `fdo-2.0r1` (FDO 2.0 Errata 1).

## Security

### S1. Delegate chains: no permission checks
`verify_delegate_chain()` (`client-linuxapp/src/main.rs`) checks only that
the root is signed by the Owner and each certificate by its parent. It does
**not** check:
- the delegate permission OIDs (`fdo-ekt-permit-onboard-*` for ProveOVHdr20,
  `fdo-ekt-permit-redirect` for a to1d, `fdo-ekt-permit-onboard-reuse-cred`
  for credential reuse);
- that permissions hold for every certificate in the chain;
- BasicConstraints `cA` / `pathLen` on issuers, or a chain-length cap.

This was never implemented (not a regression). Before 2026-10, a chain whose
root was not signed by the Owner only logged a warning; that is now a hard
failure.

### S2. BMO: signed provisioning not supported
A signed (`COSE_Sign1`, tag 18) `fdo.bmo:image-begin` or `fdo.bmo:set` is
refused with BMO error 15. The client does not verify Owner or Delegate
(`x5chain` + `fdo-ekt-permit-provision`) signatures, the
`FDO-FSIM-BmoProvision-v1` AAD, or scope constraints.

### S3. BMO: unsigned provisioning accepted from any TO2 peer
Unsigned provisioning messages rely on channel authority, which the spec
grants only to the Owner or a Delegate with `fdo-ekt-permit-provision`. The
client does not track who the TO2 peer is (Owner vs. Delegate, and the
Delegate's permissions), so it accepts unsigned messages from an onboard-only
Delegate too. Depends on S1.

### S4. BMO: fetched content is not authenticated
"Authenticating Fetched Content" (chunking-strategy.md) is not implemented:
- **URL mode (1):** the client does not fetch the image. It writes the URL
  and `expected_hash` to `bmo-url.txt` / `expected_hash.bin` for an external
  consumer, which must do the authentication itself.
- **Meta-URL mode (2):** the client fetches the meta-payload over plain HTTP
  and parses it **without authenticating it** (no signature check, no
  `meta_signer`, no "pointer only" rule rejecting instruction fields such as
  `boot_args`). It does not fetch the image.

### S5. TO2 resale is declined
For `DispResale` the client verifies the Owner2 signature and nonce, then
declines resale (null `ReplacementHMac` in Done20). It does not install
replacement credentials.

## Protocol

### P1. `hashPrev2` computed over a re-encoded HelloDeviceAck20
`ProveDevice20.hashPrev2` is computed over `hello_ack.serialize_data()`, not
the bytes received. It matches only if the re-encoding is byte-identical.
(go-fdo does not yet verify `hashPrev2`, so this is latent.)

### P2. TO1.RVMore not supported
Only the first rendezvous blob of `TO1.RVRedirect` is used; a partial list
(Delegation with many blobs) is rejected.

### P3. DispDisable not supported
A `TO2.SetupDevice20` with `DispDisable` fails TO2.

## Housekeeping

- `cargo test -p fdo-data-formats` alone fails to compile (feature
  selection: `hex::FromHexError`); run `cargo test --workspace`.
- The interop script's meta-URL test leaves `python3 -m http.server 18081`
  running, which breaks later runs (and go-fdo's `bmo-meta-*` tests) on that
  port.
- `messages_uefi.rs` (no_std copy) is not maintained and does not reflect
  the FDO 2.0 wire format.
