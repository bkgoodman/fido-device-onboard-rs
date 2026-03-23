<!-- Copyright (c) 2021, Red Hat, Inc. -->
<!-- Copyright (c) 2026, Dell Technologies, Inc. -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# FDO 2.0 Client Fork

> **Note:** The upstream `fido-device-onboard-rs` project has been deprecated and
> is no longer actively maintained. **This fork picks up where it left off**,
> adding full FDO 2.0 client-side protocol support while stripping out the
> server components that are no longer needed.

## Why a Rust FDO client?

This project exists for environments where a full Go runtime is not available
or practical, and where the device has no operating system yet:

- **Device firmware and BIOS** -- UEFI DXE drivers or PEI modules that need
  to onboard before any OS is loaded.
- **OS installers and provisioning agents** -- minimal environments whose
  whole purpose is to install an operating system. They need FDO to receive
  boot images and configuration, not to manage an already-running system.
- **Embedded and constrained devices** -- resource-limited hardware where
  a statically linked Rust binary is far smaller than a Go runtime.

Because these environments have no running OS, the only Service Info Modules
(FSIMs) that matter are `devmod` (required by the protocol) and `fdo.bmo`
(Bare Metal Onboarding -- delivering boot images, BIOS parameters, and
Secure Boot keys to the device). The upstream FSIMs that assume a running
Linux system (SSH key injection, arbitrary file writes, shell commands,
LUKS disk encryption, RHEL subscription management) are being removed.

## Getting started -- interop test script

The fastest way to see this code in action is the interop test script. It
builds the Rust clients, spins up a Go FDO 2.0 server, and runs a real
device-onboarding flow end-to-end -- no manual setup required. It doubles
as a **test suite, usage example, and tutorial**: read it to understand the
exact commands, environment variables, and flags each binary expects.

### Prerequisites

1. **Rust toolchain** -- `cargo build` must work.
2. **Go toolchain** -- needed to run the Go FDO reference server.
3. **Go FDO server** -- clone [go-fdo](https://github.com/nicjohnson145/go-fdo)
   next to this repo so it lives at `../go-fdo`.
4. **OpenSSL CLI** -- used by the script to generate ephemeral DI keys.

### Running

```bash
./test_rust_fdo20_interop.sh            # run all tests (default)
./test_rust_fdo20_interop.sh di-fdo20   # DI only -- device initialization
./test_rust_fdo20_interop.sh full-fdo20 # DI + TO1 + TO2 -- full onboarding
./test_rust_fdo20_interop.sh delegate   # TO2 with delegate certificate chain
```

### What each test does

| Test | What it exercises |
| ---- | ----------------- |
| `di-fdo20` | Builds the manufacturing client, generates an ECDSA P-256 key pair and HMAC key, starts the Go server with `-reuse-cred`, runs `fdo-manufacturing-client plain-di --fdo-version 200`, and verifies the credential file is written. This is the simplest smoke test. |
| `full-fdo20` | Runs DI (as above), then immediately runs `fdo-client-linuxapp` against the same server to perform TO1 (rendezvous) and TO2 (ownership transfer) using the credential from DI. Covers the entire device lifecycle with a single server instance. |
| `delegate` | Creates a delegate certificate chain on the Go server (`delegate create myDelegate ...`), performs DI with a P-384 key (matching the delegate chain's key type), then runs TO1+TO2. The Rust client validates the delegate chain in the `ProveOVHdr20` COSE unprotected header before accepting the owner. |

### Key environment variables the script sets

These are the same variables you would set when running the binaries
yourself -- the script is the reference for how to wire everything together:

| Variable | Binary | Purpose |
| -------- | ------ | ------- |
| `DEVICE_CREDENTIAL_FILENAME` | manufacturing-client | Where DI writes the device credential |
| `DI_SIGN_KEY_PATH` | manufacturing-client | Path to the device signing key (DER, PKCS#8) |
| `DI_HMAC_KEY_PATH` | manufacturing-client | Path to the HMAC key (32 random bytes) |
| `MANUFACTURING_INFO` | manufacturing-client | Device serial number / info string |
| `DEVICE_CREDENTIAL` | client-linuxapp | Path to the credential produced by DI |
| `DEVICE_ONBOARDING_EXECUTED_MARKER_FILE_PATH` | client-linuxapp | Marker file written after successful TO2 |
| `ALLOW_NONINTEROPERABLE_KDF` | client-linuxapp | Set to `1` for test environments |

### Test artifacts

The script stores all ephemeral keys, credentials, and server state in
`ephemeral-test-files/` (git-ignored). Server logs go to `/tmp/fdo_server.log`.
Everything is cleaned up between test runs automatically.

---

## What changed in this fork

The upstream project implemented the full FDO 1.1 specification -- client
*and* server -- but was abandoned before FDO 2.0 support was added. This
fork refocuses the codebase on **client-only functionality** targeting the
FDO 2.0 protocol, intended for device and firmware (UEFI) environments where
only the device-side roles (DI, TO1, TO2) are needed.

### FDO 2.0 protocol support (new)

All three device-side protocols have been implemented and tested end-to-end
against the [Go FDO](https://github.com/nicjohnson145/go-fdo) reference server:

- **Device Initialization (DI)** -- `DeviceMfgInfo` with CSR generation,
  `CapabilityFlags` version negotiation, protocol version selection
  (`--fdo-version 200`).
- **Transfer Ownership 1 (TO1)** -- `HelloRV` / `HelloRVAck` with flattened
  `CapabilityFlags`, EAT-based `ProveToRV`, `RVRedirect`.
- **Transfer Ownership 2 (TO2)** -- Complete device-proves-first flow with
  12 new message types (80-91): `ProveDevice20` (plain COSE, not EAT),
  ownership voucher validation, key exchange, encrypted ServiceInfo, and
  credential reuse.
- **Delegate certificate support** -- Optional (`delegate_support` Cargo
  feature, enabled by default). Validates delegate chains in
  `ProveOVHdr20` unprotected headers, allowing delegated onboarding.

### Server code removed / being removed

The server-side crates (`rendezvous-server`, `manufacturing-server`,
`owner-onboarding-server`, `serviceinfo-api-server`, `admin-tool`,
`owner-tool`) and FDO 1.x message modules are being removed. See
`FDO_2.0_MIGRATION_PLAN.md` for the full status.

### Integrating with your platform -- the BMO callback model

Everything in this codebase except the BMO handler is **protocol plumbing**
that should run as-is on any platform: DI, TO1, TO2, CBOR serialization,
COSE signatures, key exchange, encryption. A real-world integration should
not need to modify any of that.

**The only integration point is BMO.** When the owner server delivers data
during onboarding, the BMO handler in `client-linuxapp/src/serviceinfo.rs`
receives it and must do something platform-specific with it. This is where
your implementation hooks in:

| BMO event | What the handler receives | What your platform does |
| --------- | ------------------------ | ----------------------- |
| **Inline image** | Image bytes + metadata (type, name, hash) | Write to flash, chainload EFI binary, stage for OS installer |
| **URL delivery** | URL string + metadata (type, hash, TLS CA) | Fetch image from URL (HTTP/HTTPS), verify hash, apply |
| **Meta-URL delivery** | Meta-URL + COSE signer key | Fetch signed meta-payload, verify signature, resolve actual image URL, fetch and apply |
| **BIOS parameters** | Key-value pairs (e.g. `secure-boot=true`) | Write UEFI variables, update BIOS/firmware settings |
| **Secure Boot certs** | DER certificate bytes (type `application/x-uefi-db-cert`) | Enroll into UEFI Secure Boot DB/DBX |

The reference implementation writes everything to files under `BMO_OUTPUT_DIR`
(default `/tmp/fdo-bmo`). To integrate with a real platform, replace the
file-write calls in the BMO handler with your platform-specific operations.
The protocol machinery delivers the data; your code decides what to do with it.

This design means a firmware or installer team can take this codebase, leave
the FDO protocol stack untouched, and only implement the BMO callback layer
for their specific hardware.

---

*The original upstream README follows below for reference.*

---

# Deprecated (upstream)

This project is **deprecated** and is no longer actively maintained.

- No new features will be added.
- Bug fixes and security patches will be provided on a case by case basis.
- The repository will remain available for archival and reference purposes.

If you depend on this project, consider:

1. Forking the repository to maintain your own version, or  
2. Migrating to an alternative implementation that is actively maintained.

We thank all contributors and users who supported this project.

# fido-device-onboard-rs
An implementation of the FIDO Device Onboard Specification written in rust.

The upstream implementation targeted specification version [1.1 20211214](https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-RD-v1.1-20211214/FIDO-device-onboard-spec-v1.1-rd-20211214.html).
This fork targets **FDO 2.0**.

## Components (this fork)

Client-side only:
- **[manufacturing-client](manufacturing-client/)** -- Device Initialization (DI) client. Supports FDO 2.0 (`--fdo-version 200`) with `DeviceMfgInfo` and CSR generation.
- **[client-linuxapp](client-linuxapp/)** -- Device onboarding client (TO1 + TO2). FDO 2.0 only, device-proves-first flow.
- **[data-formats](data-formats/)** -- FDO protocol message definitions, CBOR serialization, and types for both v1.1 (legacy) and v2.0.
- **[http-wrapper](http-wrapper/)** -- HTTP transport layer with encryption support.

## Protocols (FDO 2.0)
- **Device Initialize (DI)** -- AppStart with DeviceMfgInfo + CapabilityFlags, SetCredentials, SetHMAC, Done
- **Transfer Ownership 1 (TO1)** -- HelloRV, HelloRVAck, ProveToRV (EAT), RVRedirect
- **Transfer Ownership 2 (TO2)** -- 12 message types (80-91): HelloDeviceProbe, HelloDeviceAck20, ProveDevice20, ProveOVHdr20, GetOVNextEntry20, OVNextEntry20, DeviceSvcInfoRdy20, SetupDevice20, DeviceSvcInfo20, OwnerSvcInfo20, Done20, DoneAck20

## Quick start

```bash
# Build client binaries
cargo build --release -p fdo-manufacturing-client -p fdo-client-linuxapp

# Run DI against a Go FDO 2.0 server
DEVICE_CREDENTIAL_FILENAME=cred.bin \
DI_SIGN_KEY_PATH=sign_key.der \
DI_HMAC_KEY_PATH=hmac_key.bin \
MANUFACTURING_INFO=my-device \
./target/release/fdo-manufacturing-client plain-di \
    --manufacturing-server-url http://localhost:9999 \
    --mfg-string-type SerialNumber \
    --key-ref filesystem \
    --fdo-version 200

# Run TO1 + TO2
DEVICE_CREDENTIAL=cred.bin \
./target/release/fdo-client-linuxapp
```

## TPM Support

The Rust FDO clients can store device keys in a hardware TPM 2.0 instead of
on the filesystem. This keeps the signing key and HMAC key inside the TPM
where they cannot be extracted.

### Build flags

TPM key storage is selected at runtime via the `--key-ref` flag on the
manufacturing client. No special Cargo feature flags are needed -- the
`tss-esapi` dependency is always compiled.

| `--key-ref` value | Key storage | Credential metadata | Use case |
|---|---|---|---|
| `filesystem` | DER files on disk | File (`cred.bin`) | Development, testing, non-TPM hardware |
| `tpm` | TPM 2.0 persistent handles | File (`cred.bin`) | Production hardware with TPM |

### DI with TPM key storage

```bash
# DI -- keys are generated inside the TPM; credential metadata written to file
DEVICE_CREDENTIAL_FILENAME=cred.bin \
MANUFACTURING_INFO=my-device \
./target/release/fdo-manufacturing-client plain-di \
    --manufacturing-server-url http://localhost:9999 \
    --mfg-string-type SerialNumber \
    --key-ref tpm \
    --fdo-version 200
```

The TPM is auto-detected via the `TSS2_TCTI_NAME` environment variable or
falls back to `/dev/tpmrm0` (the Linux kernel resource manager).

### Onboarding (TO1/TO2) with TPM

After DI, the onboarding client (`fdo-client-linuxapp`) uses the credential
file produced by DI together with the TPM-resident keys to complete TO1 and
TO2:

```bash
DEVICE_CREDENTIAL=cred.bin \
ALLOW_NONINTEROPERABLE_KDF=1 \
./target/release/fdo-client-linuxapp
```

The signing key remains in the TPM throughout the onboarding flow -- the
credential file contains only metadata (GUID, rendezvous info, public key
hash), never secret material.

### Cross-project verification with Go FDO

The [Go FDO](../go-fdo) project provides CLI commands that inspect
TPM-stored FDO credentials. When both implementations follow the
["Securing FDO Credentials in the TPM"](https://fidoalliance.org/specs/FDO/)
specification for NV index layout, credentials written by the Rust client
can be read and displayed by the Go client as proof of spec compliance:

```bash
# Build Go client with TPM support
cd ../go-fdo/examples && go build -tags=tpm -o fdo ./cmd

# Inspect what the Rust DI wrote to the TPM
./fdo client -tpm-show           # Display all NV indices, GUID, RV info, key type
./fdo client -tpm-export-dak     # Export DAK public key as PEM
./fdo client -tpm-prove          # Sign a challenge with the DAK to prove possession
```

`tpm-show` output includes:
- **DCActive** -- whether the device is initialized
- **DCTPM** -- device GUID and DeviceInfo string
- **DCOV** -- protocol version, key type, owner public key hash, rendezvous URLs
- **DAK** -- the Device Attestation Key curve and public coordinates
- **HMAC Key** -- presence of the persistent HMAC key

If Go can successfully parse and display credentials provisioned by the Rust
client, it confirms both implementations agree on the TPM NV index layout,
CBOR encoding, and key formats defined by the specification.

### End-to-end TPM interop test

The full cross-language TPM verification flow:

```bash
# 1. Start Go FDO server
cd ../go-fdo/examples
go run ./cmd server -http 127.0.0.1:9999 -db test.db -reuse-cred &

# 2. Rust DI -- provisions TPM with device credentials
cd ../fido-device-onboard-rs
DEVICE_CREDENTIAL_FILENAME=cred.bin \
MANUFACTURING_INFO=rust-tpm-test \
./target/release/fdo-manufacturing-client plain-di \
    --manufacturing-server-url http://127.0.0.1:9999 \
    --mfg-string-type SerialNumber \
    --key-ref tpm \
    --fdo-version 200

# 3. Go inspects TPM -- proof of compliance
cd ../go-fdo/examples
go build -tags=tpm -o fdo ./cmd
./fdo client -tpm-show            # ← Rust-written creds, read by Go
./fdo client -tpm-export-dak      # ← DAK created by Rust, exported by Go

# 4. Rust onboarding -- TO1/TO2 using TPM-resident keys
cd ../fido-device-onboard-rs
DEVICE_CREDENTIAL=cred.bin \
ALLOW_NONINTEROPERABLE_KDF=1 \
./target/release/fdo-client-linuxapp

# 5. Go inspects again -- credential updated after onboarding
cd ../go-fdo/examples
./fdo client -tpm-show            # ← Updated GUID and RV info after TO2
```

## Legacy crates (upstream, being removed)

These crates are from the upstream project and are slated for removal:
- `fdo-manufacturing-server`, `fdo-owner-onboarding-server`, `fdo-rendezvous-server`
- `fdo-serviceinfo-api-server`, `fdo-owner-tool`, `fdo-admin-tool`
- `fdo-store`, `fdo-integration-tests`, `fdo-libfdo-data`

## RPMs and containers (upstream)

The upstream project released RPMs and containers tracking the `main` branch. RPMs were available in [COPR](https://copr.fedorainfracloud.org/coprs/g/fedora-iot/fedora-iot/). Containers were available on [Quay.io](https://quay.io/organization/fido-fdo). These are not maintained by this fork.
