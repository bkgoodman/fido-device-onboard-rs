<!-- Copyright (c) 2021, Red Hat, Inc. -->
<!-- Copyright (c) 2026, Dell Technologies, Inc. -->
<!-- SPDX-License-Identifier: BSD-3-Clause -->

# FDO 2.0 Client Fork

> **Note:** The upstream `fido-device-onboard-rs` project has been deprecated and
> is no longer actively maintained. **This fork picks up where it left off**,
> adding full FDO 2.0 client-side protocol support while stripping out the
> server components that are no longer needed.

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

## Legacy crates (upstream, being removed)

These crates are from the upstream project and are slated for removal:
- `fdo-manufacturing-server`, `fdo-owner-onboarding-server`, `fdo-rendezvous-server`
- `fdo-serviceinfo-api-server`, `fdo-owner-tool`, `fdo-admin-tool`
- `fdo-store`, `fdo-integration-tests`, `fdo-libfdo-data`

## RPMs and containers (upstream)

The upstream project released RPMs and containers tracking the `main` branch. RPMs were available in [COPR](https://copr.fedorainfracloud.org/coprs/g/fedora-iot/fedora-iot/). Containers were available on [Quay.io](https://quay.io/organization/fido-fdo). These are not maintained by this fork.
