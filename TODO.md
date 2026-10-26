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

### P4. TO2 key exchange suite is hard-coded to ECDH384
`client-linuxapp` always sends `ECDH384` in `TO2.ProveDevice20` and ignores
the suites the Owner offers in `TO2.HelloDeviceAck20`. The spec only allows
ECDH384 for a P-384 Owner key (ECDH256 for P-256, DHKEX for RSA). go-fdo's
2.0 server now offers and enforces the spec mapping, so with P-256 keys it
rejects this client at msg 82 ("key exchange ECDH384 is invalid for the
device and owner attestation types"). `test_rust_fdo20_interop.sh` therefore
starts the go-fdo server with `-lenient-kex` (not spec compliant; accepts any
ECDH suite for an ECDSA Owner key). Fix: select a suite from the offer, then
drop the flag (`GO_SERVER_KEX_FLAGS="" ./test_rust_fdo20_interop.sh` runs
against the strict server).

### P5. FDO 2.0 ECDH `ShSe` built in go-fdo's (wrong) order — FIXED 2026-10-24
Fixed (uncommitted): client passes `KeyDeriveSide::Device`; KAT
`types::test_ecdh_kat` (shared vectors, both sides); interop 7/7 vs fixed go-fdo.
`client-linuxapp/src/main.rs` (~657) derives the 2.0 session keys with
`KeyDeriveSide::OwnerService` to match go-fdo's positional
`Shx || xB.Rand || xA.Rand`. The spec order is by role,
`Shx || DeviceRandom || OwnerRandom`, which `derive_key_ecdh` already does
for `KeyDeriveSide::Device`. Fix: pass `KeyDeriveSide::Device`, in the same
change as go-fdo and fdo-uefi-rs (flag day). Cross-repo tracking:
workstream `fdo20-spec-issues`; spec background (editorial A/B prose fix)
filed in the upstream spec tracker 2026-10-24.

## TPM spec alignment (opened 2026-10-24)

Spec: `~/internet-of-things-specs/securing-fdo-in-tpm.bs`, branch
`bgoodman-tpm` (pushed through 522feec). Same items are tracked in go-fdo and
fdo-uefi-rs TODO.md "TPM spec alignment"; cross-repo workstream
`impl-alignment`.

### T1. Device key authPolicy = `PolicyCommandCode(TPM_CC_Certify)` — code done 2026-10-24
Code written (uncommitted): `tpm::key::device_key_auth_policy` + both EC
templates. **Not compiled or run**: devvm has no `libtss2-dev` / TPM
(`cargo test --features tpm_support` fails in tss-esapi-sys).
Spec Table 10/12 (adopted 2026-10-23, SHOULD). The DAK templates in
`data-formats/src/tpm/key.rs` and `manufacturing-client` (`SpecTpm` flow) set
an empty authPolicy; set the digest for the key's nameAlg (SHA256
`048e9a3a…65850`, SHA384 `a7108d53…1019a`). HMAC key stays empty. Only new
DI is affected (signing uses the USER role and the persisted handle; existing
keys with an empty policy stay compliant). Test: `TPM2_Certify(DAK, AK)`
succeeds via a policy session, `TPM2_ObjectChangeAuth` fails, signing still
works with an empty password.

### T2. `noDA = 1` on the DAK and HMAC key — code done 2026-10-24 (same caveat as T1)
Spec Table 11. Check the templates in `data-formats/src/tpm/key.rs`.

### T4. DCTPM readers ignore trailing bytes — code done 2026-10-26
`cborparser::decode_first_cbor_value` (tested) now used by `tpm/nv.rs` and
`tpm/credential.rs` (spec: index MAY be larger than DCTPM; go-fdo now
defines it at 512). Call sites not compiled here (tpm_support, see T1).

### T5. DCTPM DeviceKeyType holds the protocol key type
`manufacturing-client` writes `key_type_value` (the FDO protocol key type,
e.g. 10 = secp256r1) at DCTPM index 7. The TPM spec defines DeviceKeyType as
0 = DAK, 1 = IDevID, 2 = LDevID; write 0. go-fdo fixed the same deviation
2026-10-27 (f9fc84d); fdo-uefi-rs already writes 0.

### T3. Dead PolicyNV workaround
`data-formats/src/tpm/policy.rs` (`compute_fdo_auth_policy`, the second raw
ESYS connection for `Esys_PolicyNV`) is no longer called from outside the
file, and the spec no longer uses PolicyNV. Delete it and the AGENTS.md
"TPM PolicyNV Workaround" section together.

## Housekeeping

- `cargo test -p fdo-data-formats` alone fails to compile (feature
  selection: `hex::FromHexError`); run `cargo test --workspace`.
- The interop script's meta-URL test leaves `python3 -m http.server 18081`
  running, which breaks later runs (and go-fdo's `bmo-meta-*` tests) on that
  port.
- `messages_uefi.rs` (no_std copy) is not maintained and does not reflect
  the FDO 2.0 wire format.
