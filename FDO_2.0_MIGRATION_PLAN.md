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
- [x] Remove server crates
  - [x] `rendezvous-server/`
  - [x] `manufacturing-server/`
  - [x] `owner-onboarding-server/`
  - [x] `serviceinfo-api-server/`
  - [x] `admin-tool/`
  - [x] `owner-tool/`
- [x] Remove database crates (`store/`, `db/`)
- [x] Remove `integration-tests/`, `libfdo-data/`
- [x] Strip `util/` -- removed `servers/` module, `passwd_shadow.rs`, `fdo-store` dependency
- [x] Strip `http-wrapper/` -- removed `fdo-store` dependency (server.rs already gated behind feature)
- [x] Update workspace `Cargo.toml` (client-only: data-formats, http-wrapper, util, client-linuxapp, manufacturing-client)
- [ ] Remove FDO 1.x message modules (v11 still used by manufacturing-client DI and ErrorMessage)
  - [ ] `data-formats/src/messages/v10/`
  - [ ] `data-formats/src/messages/v11/` (requires removing v1.1 DI path from manufacturing-client first)
- [ ] Update `README.md` (remove legacy crate references)

### 5c: Remove Unnecessary FSIMs (DONE)
Only `devmod` (required by protocol) and `fdo.bmo` (bare metal onboarding) are
needed for the target environments (firmware, UEFI, OS installer). All other
FSIMs are Linux-specific and assume a running OS -- the opposite of our use case.

- [x] Remove `org.fedoraiot.sshkey` FSIM (requires running OS with user accounts)
- [x] Remove `org.fedoraiot.binaryfile` FSIM (arbitrary file write to running OS)
- [x] Remove `org.fedoraiot.command` FSIM (shell command execution on running OS)
- [x] Remove `org.fedoraiot.reboot` FSIM (OS-level reboot)
- [x] Remove `org.fedoraiot.diskencryption-clevis` FSIM (LUKS/Clevis, requires full OS + TPM stack)
- [x] Remove `com.redhat.subscriptionmanager` FSIM (RHEL subscription, requires running OS)
- [x] Remove corresponding enum variants from `FedoraIotServiceInfoModule` and `RedHatComServiceInfoModule`
- [x] Remove `find_available_modules()` checks for `/usr/bin/clevis`, `/usr/sbin/subscription-manager`
- [x] Remove `libcryptsetup-rs`, `devicemapper`, `nix` dependencies from `client-linuxapp`
- [x] Remove `fdo-util/passwd_shadow` dependency
- [x] Remove `reencrypt` module from `client-linuxapp`

### 5b: Warnings & Linting (DONE)
- [x] `cargo clippy` clean (zero warnings across all workspace crates)
- [x] `cargo fmt --all` applied
- [x] Fix all unused imports, unused variables, unnecessary unwrap calls
- [x] Fix lifetime elision warnings
- [x] Remove dead code (unused functions, structs, enum variants)

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

### Binary Size Audit (post-cleanup)

Release builds (`cargo build --release`, x86_64 Linux, dynamically linked OpenSSL/TSS2):

| Binary | Features | Unstripped | Stripped |
| ------ | -------- | ---------: | -------: |
| `fdo-client-linuxapp` | default (delegate) | 9,294,632 | 7,094,576 |
| `fdo-client-linuxapp` | no delegate (`--no-default-features`) | 9,234,944 | 7,046,328 |
| `fdo-manufacturing-client` | default | 9,167,976 | 6,989,808 |

**Improvement from cleanup:** Stripped client went from 7,562,696 to 7,094,576 (468 KB saved, ~6.2%).

**Dependency breakdown** (approximate .text contribution, client-linuxapp default):

| Component | Size | Notes |
| --------- | ---: | ----- |
| serde_cbor / ciborium | 569 KB | CBOR serialization (core protocol) |
| regex + aho-corasick | 506 KB + 132 KB | Pulled in transitively; candidate for removal |
| fdo-client-linuxapp | 367 KB | Our TO1/TO2 + BMO code |
| core / std / alloc | ~508 KB | Rust standard library |
| h2 | 250 KB | HTTP/2 framing (used by hyper) |
| hyper | 249 KB | HTTP client engine |
| fdo-data-formats | 225 KB | Protocol messages, CBOR types |
| tokio | 195 KB | Async runtime |
| reqwest | 140 KB | HTTP client (used for BMO meta-url fetch) |
| tss-esapi / TPM | 89 KB | TPM bindings (will be feature-gated in Phase 8) |
| http | 70 KB | HTTP types |
| openssl bindings | 65 KB | Rust-side OpenSSL FFI (actual crypto in shared lib) |
| Delegate support | ~48 KB | Delta between default and no-delegate builds |
| fdo-http-wrapper | 8 KB | Our HTTP transport layer |

**Shared library dependencies** (not included in binary size above):

| Library | Size | Required by |
| ------- | ---: | ----------- |
| libcrypto.so.3 (OpenSSL) | 4,456 KB | All crypto operations |
| libssl.so.3 (OpenSSL) | 668 KB | TLS for HTTP |
| libtss2-esys.so.0 | 601 KB | TPM operations (removable with feature flag) |
| libtss2-mu.so.0 | 318 KB | TPM marshalling (removable with feature flag) |
| libtss2-tctildr.so.0 | 40 KB | TPM TCTI loader (removable with feature flag) |
| libtss2-sys.so.1 | ~200 KB | TPM system API (removable with feature flag) |

**Size reduction opportunities:**

| Opportunity | Estimated savings | Effort |
| ----------- | ----------------: | ------ |
| Remove TPM (`tpm_support` feature flag) | ~89 KB binary + ~1,159 KB shared libs | Phase 8a (planned) |
| Replace regex with simpler parsing | ~638 KB | Medium (audit transitive deps pulling regex) |
| Replace tokio/hyper/h2 with blocking HTTP | ~694 KB | High (rewrite async to sync) |
| Replace reqwest with minimal HTTP client | ~140 KB | Medium (BMO meta-url only use) |
| Static link OpenSSL | +~5,124 KB (bigger) | Trades shared lib for self-contained binary |
| UEFI target with platform crypto | -65 KB - shared libs | Platform-specific (no OpenSSL/TSS2 at all) |

## Phase 8: TPM Integration & New TPM Spec Standardization

### 8a: Make TPM a compile-time option (feature flag)

Current state: `tss-esapi` is a **hard dependency** in `data-formats`,
`manufacturing-client`, and `owner-tool`. No feature flag exists. If
`tpm2-tss-devel` is not installed, nothing compiles. On UEFI platforms with
different TPM libraries, `tss-esapi` is useless.

The existing abstraction is clean (3 enums: `KeyStorageType`, `KeyStorage`,
`KeyReference` with filesystem/TPM variants). The TPM code is concentrated
in two files (~450 lines total):
- `data-formats/src/devicecredential/file.rs` -- `TpmCoseSigner`, HMAC, signing (~250 lines)
- `manufacturing-client/src/main.rs` -- Key generation, templates, public key extraction (~200 lines)

- [x] Add `tpm_support` feature flag to `data-formats/Cargo.toml` (makes `tss-esapi` optional)
- [x] Add `tpm_support` feature flag to `manufacturing-client/Cargo.toml` (forwards to data-formats)
- [x] Add `tpm_support` feature flag to `owner-tool/Cargo.toml` (forwards to data-formats)
- [x] Gate `KeyStorage::Tpm` match arms with `#[cfg(feature = "tpm_support")]`
- [x] Gate `KeyReference::SemiTpm` variant with `#[cfg(feature = "tpm_support")]`
- [x] Gate `TpmCoseSigner` struct and impl with `#[cfg(feature = "tpm_support")]`
- [x] Gate TPM key generation functions (`get_new_key_tpm`, templates) with `#[cfg(feature = "tpm_support")]`
- [x] Gate TPM HMAC path in `perform_hmac()` with `#[cfg(feature = "tpm_support")]`
- [x] Gate `TssError` variant in `errors.rs` with `#[cfg(feature = "tpm_support")]`
- [x] Gate TPM inspection in `owner-tool/src/main.rs`
- [x] Return clear error when loading TPM credential without `tpm_support` feature
- [x] Verify builds without TPM feature (default: no TPM) -- `cargo check` passes, `cargo clippy` clean
- [x] Verify builds with `--features tpm_support` (full TPM, current behavior) -- `cargo check` + `cargo clippy` clean
- [x] Test DI with `--key-ref filesystem` still works without TPM feature -- full interop suite passes (DI, TO1/TO2, delegate, BMO)
- [x] Test DI with `--key-ref tpm` works with TPM feature -- DI + TO1 + TO2 against Go server (P-256, real hardware TPM)

**Additional fixes during TPM testing:**
- [x] Fix `str_key()` and `env_key()` to route `--key-ref tpm` to `get_new_key_tpm()` (was dead code)
- [x] Auto-detect TPM curve support (try P-256 first, fall back to P-384)
- [x] Detect actual key type from TPM public key in `get_public_key_type()` (was hardcoded P-384)
- [x] Implement CSR generation for TPM keys (sign TBS with TPM, assemble DER)
- [x] Remove `generate-bindings` default (no longer requires `libclang-dev`); available as `tpm_generate_bindings` feature
- Note: `client-linuxapp` TCTI fallback is `Tabrmd`; set `TSS2_TCTI=device:/dev/tpmrm0` for direct access

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

**Completed: NV-based credential storage (DI side)**
- [x] New `data-formats/src/tpm/` module: `mod.rs` (constants, profiles, context), `nv.rs` (NV operations), `key.rs` (key management)
- [x] NV index constants matching Go: `0x01D10000`-`0x01D10005` (DCActive, DCTPM, DCOV, US indices)
- [x] Persistent handle constants: `0x81020002` (DAK), `0x81020003` (HMAC key)
- [x] NV attribute profiles A/B/C per spec Table 9
- [x] Spec-compliant ECC key creation under Endorsement hierarchy with unique strings
- [x] Spec-compliant HMAC key creation under Endorsement hierarchy with unique strings
- [x] Persistent key handles via `TPM2_EvictControl`
- [x] `KeyReference::SpecTpm` variant in manufacturing-client with full NV provisioning flow
- [x] DI stores credentials in NV indices (DCTPM: GUID+DeviceInfo, DCOV: CBOR metadata, DCActive: flag) -- no file written
- [x] Integration test: DI with NV-backed keys against Go server (verified with `tpm2_nvreadpublic`)

**Remaining: TO2 side (load from NV)**
- [ ] Update `client-linuxapp` to discover and load credentials from TPM NV indices
- [ ] Read DCTPM/DCOV/DCActive from NV → reconstruct DeviceCredential
- [ ] Load persistent DAK/HMAC key handles for TO1/TO2 signing
- [ ] Integration test: full DI + TO1 + TO2 with NV-only credentials
- [ ] Credential reuse: Save() updates NV indices after TO2

**Deferred (policy session hardening):**
- [ ] `userWithAuth=false` with PolicyNV + PolicySecret (tss-esapi 7.6 missing `PolicyNV`; using password auth)
- [ ] HMAC sequence operations (tss-esapi 7.6 missing `HMAC_Start`/`SequenceUpdate`/`SequenceComplete`)
- [ ] PCR quotes during TO2 (not in current Go implementation either)
- [ ] EK/AK certificate chain validation

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
