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

**Device-side (client-linuxapp) responsibilities:**
- [ ] Advertise `fdo.bmo` module in devmod active modules list
- [ ] Handle `fdo.bmo:active` (enable/disable BMO module)
- [ ] Handle `fdo.bmo:image-type` (receive MIME type of boot image)
- [ ] Handle `fdo.bmo:image-length` (total size of incoming image)
- [ ] Handle `fdo.bmo:image-begin` (start of image transfer, optional hash for verification)
- [ ] Handle `fdo.bmo:image-data` (receive image data chunks, reassemble)
- [ ] Handle `fdo.bmo:image-end` (end of transfer, verify hash if provided)
- [ ] Handle `fdo.bmo:image-ack` (send acknowledgment with status/error code)
- [ ] Handle `fdo.bmo:set` (receive BIOS/UEFI parameter key=value pairs)
- [ ] Handle `fdo.bmo:set-ack` (acknowledge parameter setting)
- [ ] Handle `fdo.bmo:supported-types` (report supported image MIME types)
- [ ] Handle `fdo.bmo:error` (report errors back to owner)
- [ ] Image storage: write received image to configurable path or UEFI variable
- [ ] BIOS parameter storage: write key=value pairs to UEFI variables or config file
- [ ] Secure Boot DB/DBX modification support (optional, platform-dependent)
- [ ] URL-based image delivery (`fdo.bmo:image-url` mode - download from URL instead of inline)
- [ ] Meta-payload support (`fdo.bmo:meta-url` - signed metadata with URL reference)
- [ ] Integration test: Go server with `-bmo-file` sends image, Rust client receives and writes
- [ ] Integration test: Go server with `-bmo-set key=value` sends params, Rust client applies
- [ ] Integration test: Go server with `-bmo-url` sends URL reference, Rust client downloads

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

- [ ] Evaluate current TPM usage (tss2-esys dependency, key storage via TPM)
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
- [ ] Assess whether tss2-esys can be made optional (feature flag) for platforms without TPM
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
- [ ] BMO FSIM: device receives boot image from owner server
- [ ] BMO FSIM: device receives BIOS parameters from owner server
- [ ] All server code removed
- [x] Optional delegate support compiles conditionally
- [ ] All integration tests pass in CI
- [ ] Documentation updated
