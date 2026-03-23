<!-- Copyright (c) 2026, Dell Technologies, Inc. -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# FDO 2.0 Migration Checklist

## Phase 1: Foundation - Protocol Support

- [x] Add `ProtocolVersion::Version2_0` enum variant
- [x] Implement `CapabilityFlags` type with FDO 2.0 version negotiation
  - [x] `Serialize_tuple` for CBOR array encoding (matches Go)
  - [x] Custom `Deserialize` for variable-length arrays (VendorUnique optional)
  - [x] Flattened encoding when embedded in Go structs (TO1 HelloRV/HelloRVAck)
- [x] Add FDO 2.0 TO2 message type constants (80-91)
- [x] Create `messages::v20` module structure
- [x] `DeviceMfgInfo` struct matching Go's `custom.DeviceMfgInfo` (KeyType, KeyEncoding, SerialNumber, DeviceInfo, CSR)
- [x] Fix EAT UEID claim key (11 → 256 per EAT spec)
- [x] `Hash` custom Deserialize to accept both CBOR arrays and maps
- [x] `OwnershipVoucherEntryPayload` custom Serializable using ParsedArray (CBOR array interop)
- [x] `RendezvousInstruction` variable-length enum (handle 1-element arrays like RVBypass)
- [x] `ParsedArray` support for CBOR null/special types (major type 7)
- [x] `ParsedArray` support for CBOR tags (major type 6)
- [x] IPv6-mapped IPv4 URL formatting fix
- [x] OwnerPort fallback for device-side RV parsing (bypass mode)
- [x] Metadata-only RV directives (Delaysec without port) handled gracefully
- [x] `ExtraType` changed to `Option<ByteBuf>` for Go's Bstr-wrapped encoding

## Phase 2: DI Protocol - FDO 2.0

- [x] Create `messages::v20::di` module
  - [x] `AppStart` with DeviceMfgInfo + CapabilityFlags
  - [x] `SetCredentials` (single-field: OVHeader only, matching Go server)
  - [x] `SetHMAC` (unchanged from 1.1)
  - [x] `Done` (unchanged from 1.1)
- [x] Update `manufacturing-client` for FDO 2.0
  - [x] `--fdo-version 200` CLI flag
  - [x] `perform_di_v20()` with DeviceMfgInfo and CSR generation
  - [x] CSR generation via OpenSSL `X509ReqBuilder` (CN=device.fdo-rs)
  - [x] `get_public_key_type()` for KeyType detection
  - [x] Save correct `ProtocolVersion::Version2_0` in credential file
- [x] End-to-end DI tested against Go server with `DeviceMfgInfo`

## Phase 3: TO1 Protocol - FDO 2.0

- [x] Create `messages::v20::to1` module
  - [x] `HelloRV` with flattened CapabilityFlags (Go embeds struct)
  - [x] `HelloRVAck` with custom Deserialize for variable-length (VendorUnique optional)
  - [x] `ProveToRV` (COSE wrapper, same as 1.1)
  - [x] `RVRedirect` (COSE wrapper, same as 1.1)
- [x] Update `client-linuxapp` TO1 - FDO 2.0 only, no version routing
- [x] End-to-end TO1 tested against Go server

## Phase 4: TO2 Protocol - FDO 2.0 (Device Proves First)

- [x] Create `messages::v20::to2` module - all 12 message types
  - [x] `HelloDeviceProbe` (80) - CapabilityFlags, GUID, HashTypes, Sugar
  - [x] `HelloDeviceAck20` (81) - CapabilityFlags, KexSuites, CipherSuites, Nonce, HashPrev
  - [x] `ProveDevice20` (82) - plain COSE Sign1 (NOT EAT)
  - [x] `ProveOVHdr20` (83) - COSE Sign1 with OVHeader, HMAC, XBKeyExchange
  - [x] `GetOVNextEntry20` (84) / `OVNextEntry20` (85) - bstr-wrapped COSE entries
  - [x] `DeviceSvcInfoRdy20` (86) - encrypted, no HMAC (moved to Done20)
  - [x] `SetupDevice20` (87) - encrypted, custom ParsedArray Serializable
  - [x] `DeviceSvcInfo20` (88) / `OwnerSvcInfo20` (89) - encrypted ServiceInfo
  - [x] `Done20` (90) - encrypted, ReplacementHMAC here
  - [x] `DoneAck20` (91) - encrypted
- [x] TO2 payload types
  - [x] `TO2ProveDevice20Payload` (KexSuite, CipherSuite, XAKeyExchange, Nonce, HashPrev2)
  - [x] `TO2ProveOVHdr20Payload` (OVHeader, NumEntries, HMAC, Nonce, XBKeyExchange, MaxMsgSize)
- [x] Update `client-linuxapp` TO2 - FDO 2.0 only
  - [x] `perform_to2()` with device-proves-first flow
  - [x] HelloDeviceProbe → HelloDeviceAck20 (version negotiation)
  - [x] ProveDevice20 → ProveOVHdr20 (device proves first, plain COSE)
  - [x] Nonce echo (NonceTO2ProveOVPrep = echo of server's NonceTO2ProveDVPrep)
  - [x] GetOVNextEntry20 → OVNextEntry20 (voucher retrieval)
  - [x] OV entry validation with COSE signature verification
  - [x] Key derivation with correct random order (`OwnerService` side for v2.0)
  - [x] `set_encryption_keys()` before encrypted messages
  - [x] DeviceSvcInfoRdy20 → SetupDevice20 (encrypted)
  - [x] ServiceInfo exchange using v2.0 message types (88/89)
  - [x] Done20 → DoneAck20 (encrypted, credential reuse)
- [x] End-to-end TO2 tested against Go server

## Phase 4b: BMO FSIM - Bare Metal Onboarding

BMO (fdo.bmo) is a critical FSIM for UEFI/firmware environments. It allows the
owner server to deliver boot images, BIOS parameters, and Secure Boot keys to
the device during onboarding via the ServiceInfo exchange (messages 88/89).

**Device-side (client-linuxapp) -- implemented:**
- [x] Register `fdo.bmo` module (`FdoServiceInfoModule::Bmo` in serviceinfo_names.rs)
- [x] Advertise `fdo.bmo` module in devmod active modules list
- [x] Handle `fdo.bmo:active` (enable/disable BMO module via `active_modules` set)
- [x] Handle `fdo.bmo:image-begin` (parse CBOR map with integer keys: image_type, total_size, hash_alg, require_ack, delivery_mode, name, boot_args, url)
- [x] Handle `fdo.bmo:image-ack` (send CBOR array `[true]` or `[false, code, msg]` when RequireAck set)
- [x] Handle `fdo.bmo:image-data-N` (receive chunked image data, accumulate across ServiceInfo rounds)
- [x] Handle `fdo.bmo:image-end` (parse hash from CBOR map, verify SHA-256/384, write image to disk)
- [x] Handle `fdo.bmo:image-result` (send CBOR array `[status, msg]` after finalization)
- [x] Handle `fdo.bmo:set` (receive CBOR array of `[name, value]` BIOS parameter pairs)
- [x] Handle `fdo.bmo:response` (send CBOR array `[status, msg]` per parameter)
- [x] Image storage: write received image to configurable `BMO_OUTPUT_DIR` (default `/tmp/fdo-bmo`)
- [x] BIOS parameter storage: write key=value pairs to `bios_params` file
- [x] Boot args: write to `boot_args` file if provided in image-begin
- [x] NAK support: reject unsupported delivery modes with error code 14
- [x] Fix `is_more_service_info` handling (ServiceInfo loop continues across multiple rounds)
- [x] Persist `active_modules` and `BmoInProgress` state across ServiceInfo loop iterations
- [x] Integration test: Go server with `-bmo-file` sends 64KB image, Rust client receives, hash-verifies, and writes (byte-for-byte match confirmed)
- [x] URL delivery mode (delivery_mode=1): accept URL from server, write URL info + metadata to `bmo-url.txt`
- [x] Meta-URL delivery mode (delivery_mode=2): accept meta-URL, write info to `bmo-meta-url.txt`, save TLS CA / expected hash / meta signer if provided
- [x] Integration test: Go server with `-bmo-url` sends URL, Rust client receives and writes URL info (verified)
- [x] Integration test: Go server with `-bmo` + `-bmo-set` combined (image delivered, BIOS params subject to server sequencing)
- [x] Meta-URL fetch and CBOR parse (delivery_mode=2): fetch meta-payload from URL, parse integer-keyed CBOR map, extract resolved image_url / image_type / hash / name
- [x] Integration test: Go `meta create` builds CBOR, Python HTTP serves it, Rust client fetches and resolves (verified image_url, name, hash_alg)

**Remaining (platform-specific -- not protocol work):**

The BMO protocol plumbing is complete. All message types and delivery modes
are received, parsed, and logged. The reference implementation writes data to
files. The items below are platform-specific actions that a real integration
would implement in the BMO callback layer (see README "Integrating with your
platform"):

- [ ] Secure Boot DB/DBX enrollment (image type `application/x-uefi-db-cert`, `application/x-uefi-dbx-hash` -- received as inline images, platform applies them)
- [ ] UEFI variable storage for BIOS parameters (currently writes to flat file)
- [ ] URL fetch for delivery mode 1 (currently writes URL to info file; platform fetches)
- [ ] Actual image fetch for resolved meta-URL (currently logs resolved URL; platform fetches)
- [ ] COSE Sign1 signature verification for signed meta-payloads

**Key Go server flags for testing:**
```bash
# Send boot image file to device
go run ./cmd server -bmo-file /path/to/image.iso -bmo-type application/x-iso9660-image

# Send BIOS parameters
go run ./cmd server -bmo-set key1=value1 -bmo-set key2=value2

# Send image via URL (device downloads)
go run ./cmd server -bmo-url "application/x-iso9660-image:http://example.com/image.iso"

# Send signed meta-payload with URL
go run ./cmd server -bmo-meta-url "http://example.com/meta.json:signer.key:ca.pem"
```

## Phase 5: Code Cleanup

### 5a: Remove Server Code
- [ ] Remove server crates
  - [ ] `rendezvous-server/`
  - [ ] `manufacturing-server/`
  - [ ] `owner-onboarding-server/`
  - [ ] `serviceinfo-api-server/`
  - [ ] `admin-tool/`
  - [ ] `owner-tool/`
- [ ] Remove database crates (`store/`, `db/`)
- [ ] Remove FDO 1.x message modules
  - [ ] `data-formats/src/messages/v10/`
  - [ ] `data-formats/src/messages/v11/`
- [ ] Update workspace `Cargo.toml` (client-only members)
- [ ] Remove unused dependencies
- [ ] Update `README.md`

### 5c: Remove Unnecessary FSIMs
Only `devmod` (required by protocol) and `fdo.bmo` (bare metal onboarding) are
needed for the target environments (firmware, UEFI, OS installer). All other
FSIMs are Linux-specific and assume a running OS -- the opposite of our use case.

- [ ] Remove `org.fedoraiot.sshkey` FSIM (requires running OS with user accounts)
- [ ] Remove `org.fedoraiot.binaryfile` FSIM (arbitrary file write to running OS)
- [ ] Remove `org.fedoraiot.command` FSIM (shell command execution on running OS)
- [ ] Remove `org.fedoraiot.reboot` FSIM (OS-level reboot)
- [ ] Remove `org.fedoraiot.diskencryption-clevis` FSIM (LUKS/Clevis, requires full OS + TPM stack)
- [ ] Remove `com.redhat.subscriptionmanager` FSIM (RHEL subscription, requires running OS)
- [ ] Remove corresponding enum variants from `FedoraIotServiceInfoModule` and `RedHatComServiceInfoModule`
- [ ] Remove `find_available_modules()` checks for `/usr/bin/clevis`, `/usr/sbin/subscription-manager`
- [ ] Remove `libcryptsetup-rs`, `devicemapper`, `nix` dependencies from `client-linuxapp`
- [ ] Remove `fdo-util/passwd_shadow` dependency
- [ ] Audit remaining dependencies -- `sys-info` may also be removable if devmod can be simplified

### 5b: Warnings & Linting
- [ ] `cargo clippy` clean (fix all warnings across workspace)
- [ ] `cargo fmt --all` applied
- [ ] Fix all `#[allow(unused_*)]` markers added during development
- [ ] Remove dead code paths and unused imports
- [ ] Remove `#[allow(dead_code)]` on types/functions that should be removed
- [ ] Audit and remove debug `println!` / `eprintln!` statements
- [ ] Remove temporary `log::info!("DEBUG: ...")` logging
- [ ] Fix any `clippy::needless_borrow`, `clippy::redundant_clone` warnings
- [ ] Fix `clippy::match_single_binding` and `clippy::single_match` warnings
- [ ] Review and fix all `TODO` / `FIXME` / `HACK` comments
- [ ] Ensure no `unwrap()` calls in non-test code (use `?` or `.context()`)
- [ ] Remove commented-out code blocks
- [ ] Verify `cargo test` passes with no warnings (deny warnings in CI)

## Phase 6: Optional Features - Delegate Support

- [x] Add Cargo feature flag `delegate_support` (default: enabled)
- [x] Add COSE header key 258 (`CUPHDelegateChain`) to HeaderKeys enum
- [x] Implement delegate chain extraction from ProveOVHdr20 unprotected header
  - [x] Parse raw CBOR map via ParsedArray (bypass serde_cbor CborValue lossy encoding)
  - [x] Extract X5Chain body as array of DER cert byte strings
  - [x] Extract leaf certificate public key for COSE signature verification
- [x] Implement delegate chain validation
  - [x] Verify root cert signed by OV owner public key
  - [x] Verify intermediate cert chain signatures
- [x] Conditional compilation: `#[cfg(feature = "delegate_support")]` gates delegate code
- [x] Binary size delta: ~99 KB (9,915,120 with vs 9,814,016 without)
- [x] Tested with Go server using `-onboardDelegate myDelegate` flag
- [x] Non-delegate flow still works with `--no-default-features`

## Phase 7: Testing & Validation

- [x] Unit tests for DI messages (data-formats)
- [x] Unit tests for CBOR encoding (DeviceMfgInfo, CapabilityFlags, Hash)
- [x] Unit tests for OV entry COSE round-trip
- [x] End-to-end DI against Go server
- [x] End-to-end TO1 against Go server
- [x] End-to-end TO2 against Go server (full device-proves-first flow)
- [x] Credential reuse protocol (Done20 with nil ReplacementHMAC)
- [x] Encrypted message exchange (DeviceSvcInfoRdy20 through DoneAck20)
- [ ] Edge case testing (error recovery, timeouts, retries)

### Binary Size Audit (do after Phase 5 cleanup is complete)

- [ ] Re-measure all binary sizes (unstripped and stripped) after server code removal and dead dependency cleanup
- [ ] Measure with/without delegate support (`--no-default-features`)
- [ ] Measure manufacturing-client (DI only) vs client-linuxapp (DI+TO1+TO2)
- [ ] Break down binary size by dependency (OpenSSL, tokio/hyper/h2, serde_cbor, TPM/tss2, cryptsetup/devicemapper, regex, FDO crates, etc.)
- [ ] Assess what removing or replacing OpenSSL would save (shared lib vs static link, and what a UEFI target with its own crypto would look like)
- [ ] Assess what removing the async HTTP stack (tokio/hyper/h2/reqwest) would save if replaced with a simpler blocking client
- [ ] Identify dependencies pulled in only by server/legacy code that can be dropped
- [ ] Publish final size table and dependency breakdown to README
- [ ] Note pre-cleanup vs post-cleanup size delta

## Phase 8: TPM Integration & New TPM Spec Standardization

### 8a: Make TPM a compile-time option (feature flag)

Current state: `tss-esapi` is a **hard dependency** in `data-formats` and
`manufacturing-client`. No feature flag exists. If `tpm2-tss-devel` is not
installed, nothing compiles. On UEFI platforms with different TPM libraries,
`tss-esapi` is useless.

The existing abstraction is clean (3 enums: `KeyStorageType`, `KeyStorage`,
`KeyReference` with filesystem/TPM variants). The TPM code is concentrated
in two files (~450 lines total):
- `data-formats/src/devicecredential/file.rs` -- `TpmCoseSigner`, HMAC, signing (~250 lines)
- `manufacturing-client/src/main.rs` -- Key generation, templates, public key extraction (~200 lines)

- [ ] Add `tpm_support` feature flag to `data-formats/Cargo.toml` (makes `tss-esapi` optional)
- [ ] Add `tpm_support` feature flag to `manufacturing-client/Cargo.toml` (forwards to data-formats)
- [ ] Gate `KeyStorage::Tpm` variant with `#[cfg(feature = "tpm_support")]`
- [ ] Gate `KeyReference::SemiTpm` variant with `#[cfg(feature = "tpm_support")]`
- [ ] Gate `TpmCoseSigner` struct and impl with `#[cfg(feature = "tpm_support")]`
- [ ] Gate TPM key generation functions (`get_new_key_tpm`, templates) with `#[cfg(feature = "tpm_support")]`
- [ ] Gate TPM HMAC path in `perform_hmac()` with `#[cfg(feature = "tpm_support")]`
- [ ] Gate `TssError` variant in `errors.rs` with `#[cfg(feature = "tpm_support")]`
- [ ] Return clear error when loading TPM credential without `tpm_support` feature
- [ ] Verify builds with `--features tpm_support` (full TPM, current behavior)
- [ ] Verify builds with `--no-default-features` (no TPM, no delegate)
- [ ] Verify builds with default features (decide: TPM on or off by default)
- [ ] Test DI with `--key-ref filesystem` still works without TPM feature
- [ ] Test DI with `--key-ref tpm` works with TPM feature (requires TPM hardware)

### 8b: TPM trait abstraction for portability

The goal is that a UEFI implementation can swap in a different TPM library
(e.g. UEFI TCG protocol) without changing protocol code. The `DeviceCredential`
trait's `get_signer() -> Box<dyn SigningPrivateKey>` is already the right
boundary. The TPM-specific part is below that.

- [ ] Extract TPM operations into a `TpmProvider` trait:
  - `create_primary()` -- create primary key in owner hierarchy
  - `create_signing_key()` -- create ECC signing key under primary
  - `create_hmac_key()` -- create HMAC key under primary
  - `load_key()` -- load key from public/private blobs
  - `sign()` -- sign digest with loaded key
  - `hmac()` -- compute HMAC with loaded key
- [ ] Implement `TpmProvider` for `tss-esapi` (Linux userspace, current code)
- [ ] Document `TpmProvider` trait for UEFI implementors
- [ ] Implement CSR generation for TPM keys (currently bails with "not yet supported")

### 8c: New TPM spec alignment

- [ ] Review proposed new TPM specification for FDO device attestation
- [ ] Align device key storage with new TPM spec requirements
  - [ ] TPM-backed device signing key generation during DI
  - [ ] TPM-sealed HMAC key storage
  - [ ] TPM-based credential protection (seal/unseal with PCR policy)
- [ ] Implement TPM attestation flow per new spec
  - [ ] Platform measurement (PCR quotes) during TO2
  - [ ] EK/AK certificate chain validation
  - [ ] Device identity binding to TPM endorsement hierarchy
- [ ] Evaluate TPM 2.0 vs fTPM (firmware TPM) support requirements for UEFI targets
- [ ] Coordinate with FIDO Alliance / TCG on spec alignment
- [ ] Integration test: DI with TPM-backed keys against Go server
- [ ] Integration test: TO2 with TPM attestation against Go server

## Success Criteria

- [x] Rust client completes DI with Go FDO 2.0 server
- [x] Rust client completes TO1 with Go FDO 2.0 server
- [x] Rust client completes TO2 with Go FDO 2.0 server
- [x] Device-first attestation (ProveDevice20 before ProveOVHdr20)
- [x] Service info exchange works (devmod module)
- [x] Credential reuse protocol works
- [x] BMO FSIM: device receives boot image from owner server
- [x] BMO FSIM: device receives URL delivery info from owner server
- [x] BMO FSIM: device receives BIOS parameters (handler implemented; platform-specific application deferred to integrator)
- [ ] All server code removed
- [x] Optional delegate support compiles conditionally
- [ ] All integration tests pass in CI
- [ ] Documentation updated
