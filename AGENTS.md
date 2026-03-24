<!-- Copyright (c) 2026, Dell Technologies, Inc. -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# AGENTS.md

This document provides guidance for AI agents and automated tools working with the fido-device-onboard-rs codebase.

## Agent Rules and Guidelines

### Critical Rules

- **NEVER stage or commit code** - The user will always handle commits
- **ALWAYS test before claiming functionality works** - Run relevant test suites
- **ALWAYS run linters before check-in** - Use `cargo clippy` and `cargo fmt`
- **DO NOT make unproductive loops** - If repeatedly fixing issues, comment and move on

### Testing Guidelines

- **Partial testing is acceptable** for debugging individual components:
  - Unit tests: `cargo test` or `cargo test -p <package>`
  - Specific tests: `cargo test <test_name>`
  - Integration tests: `./test_rust_fdo20_interop.sh <specific_test>`
- **Interoperability testing required** for protocol changes:
  - FDO 2.0 interop: `./test_rust_fdo20_interop.sh` (tests Rust client vs Go server)
  - Requires `../go-fdo` directory

### Code Quality Standards

- **Final prep for check-in**: Run `cargo clippy` and `cargo fmt`
- **Use existing patterns** - Follow Rust conventions and existing code structure
- **Prefer minimal changes** - Make the smallest change that fixes the issue

## Project Overview

`fido-device-onboard-rs` is a Rust implementation of FIDO Device Onboard (FDO) focused on **client-side functionality** for FDO 2.0. It provides device and device initialization client roles optimized for UEFI/firmware environments.

### Migration Status: FDO 1.1 → FDO 2.0

This project is undergoing migration from FDO 1.1 to FDO 2.0 with the following goals:
- **Client-only implementation** (DI, TO1, TO2)
- **FDO 2.0 protocol** with backward compatibility removed
- **Minimal FSIMs**: devmod (required) + BMO (bare metal onboarding)
- **No server code** - servers will be removed

## Key Components

### Core Library Structure

- **data-formats**: FDO protocol message definitions and types
  - `messages::v11::*` - FDO 1.1 messages (legacy, will be removed)
  - `messages::v20::*` - FDO 2.0 messages (new)
  - `types::CapabilityFlags` - FDO 2.0 version negotiation
- **manufacturing-client**: Device initialization (DI) client
- **client-linuxapp**: Device onboarding (TO1/TO2) client
- **http-wrapper**: HTTP transport layer

### Testing Infrastructure

- **Unit Tests**: `cargo test` - tests individual components
- **Interop Tests**: `./test_rust_fdo20_interop.sh` - tests against Go FDO server

Available interop tests:
| Test | Description |
| ---- | ----------- |
| `di-fdo20` | DI with FDO 2.0 protocol |
| `full-fdo20` | Full flow DI + TO1 + TO2 (Rust client, FDO 2.0) |
| `delegate` | TO2 with delegate certificate chain |
| `bmo` | BMO image transfer |
| `bmo-url` | BMO URL delivery mode |
| `bmo-set` | BMO BIOS parameter setting |
| `bmo-meta-url` | BMO meta-URL delivery mode |
| `tpm-cross` | All TPM cross-implementation tests (requires /dev/tpmrm0) |
| `tpm-rust-di-go-onboard` | Rust DI -> Go onboard via TPM NV |
| `tpm-go-di-rust-onboard` | Go DI -> Rust onboard via TPM NV |
| `all` | Run all interop tests except TPM (default) |

## Development Workflow

### Initial Setup

```bash
cargo build    # Build all packages
```

### Building and Testing

```bash
cargo build --release                    # Build release binaries
cargo test                               # Run unit tests
cargo test -p fdo-data-formats          # Test specific package
cargo clippy                             # Run linter
cargo fmt                                # Format code
./test_rust_fdo20_interop.sh            # Interop tests (requires ../go-fdo)
```

### FDO 2.0 Development

```bash
# Test DI with FDO 2.0
./test_rust_fdo20_interop.sh di-fdo20

# Compare protocol versions
./test_rust_fdo20_interop.sh compare

# Full test suite
./test_rust_fdo20_interop.sh all
```

## FDO Protocol Implementation

### Device Initialization (DI)

**FDO 1.1** (legacy):
- AppStart → SetCredentials → SetHMAC → Done
- No capability flags

**FDO 2.0** (current):
- AppStart (with CapabilityFlags) → SetCredentials (with server capabilities) → SetHMAC → Done
- Version negotiation via capability flags
- Messages in `data-formats/src/messages/v20/di.rs`

### Protocol Version Support

The `manufacturing-client` supports protocol version selection:

**CLI:**
```bash
--fdo-version 110  # FDO 1.1 (default)
--fdo-version 200  # FDO 2.0
```

**Environment:**
```bash
export FDO_VERSION=200
```

Implementation routes to:
- `perform_di_v11()` - uses `messages::v11::di::*`
- `perform_di_v20()` - uses `messages::v20::di::*` with CapabilityFlags

### Transfer of Ownership (TO1/TO2)

**Status**: Implemented for FDO 2.0 (client-linuxapp speaks FDO 2.0 only)

**TO1 (FDO 2.0):**
- HelloRV with flattened CapabilityFlags → HelloRVAck → ProveToRV (EAT) → RVRedirect
- Messages in `data-formats/src/messages/v20/to1.rs`

**TO2 (FDO 2.0 - Device Proves First):**
```
HelloDeviceProbe(80) → HelloDeviceAck20(81) → ProveDevice20(82) →
ProveOVHdr20(83) → GetOVNextEntry20(84) → OVNextEntry20(85) →
DeviceSvcInfoRdy20(86) → SetupDevice20(87) → DeviceSvcInfo20(88) →
OwnerSvcInfo20(89) → Done20(90) → DoneAck20(91)
```
- Messages in `data-formats/src/messages/v20/to2.rs`
- Client flow in `client-linuxapp/src/main.rs` (`perform_to2`)
- ServiceInfo exchange in `client-linuxapp/src/serviceinfo.rs`

### Service Info Modules (FSIMs)

**Target FSIMs** (post-migration):
- **devmod**: Device module (protocol requirement)
- **bmo**: Bare metal onboarding (UEFI/firmware use case)

**To be removed**:
- All other FSIMs (payload, wifi, sysconfig, etc.)

## Code Architecture

### Message Definitions

Messages follow this pattern:

```rust
// data-formats/src/messages/v20/di.rs
#[derive(Debug)]
pub struct AppStart {
    pub info: Option<CborSimpleType>,
    pub capability_flags: CapabilityFlags,
}

impl Message for AppStart {
    fn protocol_version() -> ProtocolVersion {
        ProtocolVersion::Version2_0
    }
    fn message_type() -> MessageType {
        MessageType::DIAppStart
    }
    // ...
}
```

### Key Interfaces

- `Message`: Base trait for all FDO protocol messages
- `ClientMessage`: Trait for device→server messages
- `ServerMessage`: Trait for server→device messages
- `Serializable`: CBOR serialization/deserialization
- `CapabilityFlags`: Version negotiation bitfield

## Testing Guidelines

### Test Environment Setup

Interop tests use:
- Go FDO server from `../go-fdo`
- Ephemeral files in `ephemeral-test-files/`
- Server on `127.0.0.1:9999`
- Credentials in `~/.config/fdo/device_credential`

### Test Script Structure

Each test in `test_rust_fdo20_interop.sh`:
1. Clean up artifacts
2. Build Rust client
3. Start Go FDO server
4. Run DI/onboarding operations
5. Verify results
6. Stop server (automatic cleanup)

### Debugging Tests

- Server logs: `/tmp/fdo_server.log`
- Ephemeral files: `ephemeral-test-files/` (preserved)
- Credentials: `~/.config/fdo/device_credential`
- Run with verbose output: `bash -x ./test_rust_fdo20_interop.sh`

## Common Development Tasks

### Adding FDO 2.0 Messages

1. Define message struct in `data-formats/src/messages/v20/`
2. Implement `Message` trait with `protocol_version() -> Version2_0`
3. Implement `Serializable` for custom CBOR encoding (if needed)
4. Add accessor methods (`into_*`, getters)
5. Add unit tests

### Protocol Version Testing

- FDO 2.0: Use `--fdo-version 200` flag for manufacturing-client
- client-linuxapp: FDO 2.0 only (rejects non-2.0 credentials)

### Security Testing

- Certificate validation: Delegates and x509 (future build-time feature)
- Key exchange: ECDH256 (default), DHKEXid14, ASYMKEX3072
- Capability flags: Version negotiation

## File Organization

```
fido-device-onboard-rs/
├── README.md                           # Main documentation
├── AGENTS.md                           # This file
├── FDO_2.0_MIGRATION_PLAN.md          # Migration checklist
├── test_rust_fdo20_interop.sh         # Interop test suite
├── data-formats/                       # Protocol messages & types
│   ├── src/
│   │   ├── constants/mod.rs            # ProtocolVersion, MessageType, EAT_UEID_CLAIM_KEY
│   │   ├── types.rs                    # CapabilityFlags, DeviceMfgInfo, Hash, TO2 payloads
│   │   ├── serializable.rs            # Serializable trait + blanket impl
│   │   ├── cborparser.rs              # ParsedArray (supports null/tags)
│   │   ├── messages/
│   │   │   ├── v11/                    # FDO 1.1 (legacy, to be removed)
│   │   │   └── v20/                    # FDO 2.0
│   │   │       ├── di.rs               # DI messages (AppStart with DeviceMfgInfo)
│   │   │       ├── to1.rs              # TO1 messages (HelloRV with CapabilityFlags)
│   │   │       └── to2.rs              # TO2 messages (all 12 types, 80-91)
│   │   ├── ownershipvoucher.rs         # OV validation (custom Serializable for entry payloads)
│   │   ├── enhanced_types.rs           # RendezvousInstruction enum, IPv6 URL fix
│   │   └── publickey.rs
├── manufacturing-client/               # DI client (FDO 2.0 with CSR generation)
│   └── src/main.rs
├── client-linuxapp/                    # TO1/TO2 client (FDO 2.0 only)
│   └── src/
│       ├── main.rs                     # TO1 + TO2 device-proves-first flow
│       └── serviceinfo.rs              # ServiceInfo exchange (v2.0 message types)
├── http-wrapper/                       # HTTP transport
│   └── src/
│       ├── client.rs                   # ServiceClient with set_encryption_keys()
│       └── lib.rs                      # EncryptionKeys encrypt/decrypt
└── ephemeral-test-files/               # Test artifacts (gitignored)
```

## Agent-Specific Notes

### Code Navigation

- FDO 2.0 DI messages: `data-formats/src/messages/v20/di.rs`
- FDO 2.0 TO1 messages: `data-formats/src/messages/v20/to1.rs`
- FDO 2.0 TO2 messages: `data-formats/src/messages/v20/to2.rs`
- TO2 payload types: `data-formats/src/types.rs` (TO2ProveDevice20Payload, TO2ProveOVHdr20Payload)
- Protocol constants: `data-formats/src/constants/mod.rs`
- DI client: `manufacturing-client/src/main.rs`
- TO1/TO2 client: `client-linuxapp/src/main.rs`
- ServiceInfo: `client-linuxapp/src/serviceinfo.rs`
- Test script: `test_rust_fdo20_interop.sh`

### Common Patterns

- Error handling: `Result<T>` with `anyhow::Context`
- Logging: `log::info!`, `log::debug!`, etc.
- Testing: Unit tests in module files, interop tests in shell script
- CBOR: Use `ciborium` for serialization

### Debugging Tips

- Enable debug logging: Set `RUST_LOG=debug`
- Check server logs: `cat /tmp/fdo_server.log`
- Inspect credentials: `hexdump -C ~/.config/fdo/device_credential`
- Preserve test files: Already done by test script

## Migration Roadmap

**Completed:**
- ✅ Phase 1: Foundation - FDO 2.0 protocol support
  - ProtocolVersion::Version2_0, CapabilityFlags, DeviceMfgInfo
  - EAT UEID fix, Hash array/map Deserialize, ParsedArray null/tag support
  - RendezvousInstruction variable-length, IPv6 URL fix, OwnerPort fallback
- ✅ Phase 2: FDO 2.0 DI protocol (messages, manufacturing-client, CSR generation)
- ✅ Phase 3: FDO 2.0 TO1 protocol (CapabilityFlags in HelloRV/HelloRVAck)
- ✅ Phase 4: FDO 2.0 TO2 protocol (device-proves-first, all 12 message types 80-91)
  - ProveDevice20 plain COSE (not EAT), key derivation, encrypted messages
  - OV validation, ServiceInfo exchange, credential reuse
  - Full end-to-end DI+TO1+TO2 tested against Go FDO server

**Remaining:**
- Phase 5: Remove server code and FDO 1.x compatibility
- Phase 6: Optional delegate/x509 support (build-time feature)
- Phase 7: Edge case testing, clippy/fmt cleanup, CI

See `FDO_2.0_MIGRATION_PLAN.md` for the full checklist.

## Security Considerations

### Development vs Production

- Reference implementation may skip security checks
- Production deployments require:
  - Certificate revocation checking
  - Secure key storage (TPM integration available)
  - Proper credential management

### Testing Security Features

- Protocol version negotiation via CapabilityFlags
- Key exchange testing (ECDH, ASYMKEX)
- Credential integrity (HMAC verification)

## Known Issues / TODOs

### TPM PolicyNV Workaround (tss-esapi 7.6)

**Status:** Active workaround in `data-formats/src/tpm/policy.rs`

`tss-esapi` 7.6 does not implement `TPM2_PolicyNV`. This was explicitly skipped
in the original implementation (https://github.com/parallaxsecond/rust-tss-esapi/pull/95)
because "some of them require complicated structures." `HMAC_Start`,
`SequenceUpdate`, and `SequenceComplete` are also missing.

**Workaround:** We open a **second, independent ESYS connection** to the same
TPM device using `tss-esapi-sys` (the raw C FFI layer) and call `Esys_PolicyNV`
directly on that connection. The policy session is built entirely on the second
connection (StartAuthSession + PolicyNV + PolicySecret + Sign/HMAC), because
ESYS_TR session handles are context-local and cannot be transferred between
ESYS contexts.

The trial policy digest (for key creation) is computed in **pure software** by
replicating the TPM's hash extension algorithm, avoiding the TPM call entirely.

**Why we can't call raw FFI on the primary context:**
- `tss_esapi::Context` is not `#[repr(C)]`, so rustc may reorder struct fields
- The `ESYS_CONTEXT*` pointer is in a private field (`mut_context()`)
- We cannot reliably extract the pointer to make raw ESYS calls

**Resolution:** This workaround should be removed when:
- `tss-esapi` adds `policy_nv()` (file a PR upstream)
- We upgrade to a version that includes it
- `tss-esapi::Context` exposes the raw `ESYS_CONTEXT*`

**Remaining issue:** The software-computed auth policy digest may not match the
TPM-computed digest. This needs investigation -- the PolicyNV hash extension
format (args hash, operand encoding) must exactly match the TPM's implementation.
See `compute_fdo_auth_policy()` in `data-formats/src/tpm/policy.rs`.


This document helps AI agents understand the Rust FDO client migration project structure, development workflow, and testing patterns.
