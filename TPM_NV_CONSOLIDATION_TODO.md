# TPM NV Consolidation: Rust Client Update

**Date:** 2026-03-28  
**Context:** The Go library (`go-fdo`) has been updated to a consolidated
single-NV-index model per the revised TPM spec. The Rust client needs to
match. This document describes exactly what changed and what needs updating.

## What Changed in the Go Library / TPM Spec

### Before (OLD model — what Rust currently implements)

6 separate NV indices:
- `0x01D10000` (DCActive) — 1 byte boolean (active flag)
- `0x01D10001` (DCTPM) — raw bytes: GUID (16 bytes) + DeviceInfo string
- `0x01D10002` (DCOV) — CBOR: `[version, rvinfo, pubkeyhash, keytype]`
- `0x01D10003` (HMAC_US) — HMAC Unique String (32 bytes)
- `0x01D10004` (DeviceKey_US) — Device Key Unique String (64 bytes)
- `0x01D10005` (FDO_Cert) — Optional X.509 certificate

2 persistent object handles:
- `0x81020002` (DAK) — ECC signing key
- `0x81020003` (HMAC key)

### After (NEW model — what Go now implements)

**1 mandatory NV index:**
- `0x01D10001` (DCTPM) — CBOR-encoded structure with ALL credentials

**2 optional NV indices** (provisioning-entity artifacts, NOT required by client):
- `0x01D10003` (HMAC_US) — only if using Primary keys with rotation
- `0x01D10004` (DeviceKey_US) — only if using Primary keys with rotation

**Persistent object handles:** Implementation-chosen, recorded in DCTPM structure.
Default test values remain `0x81020002` (DAK) and `0x81020003` (HMAC key).

### DCTPM CBOR Structure (NEW)

```
DCTPM = [
    DCTPMMagic:      uint,      ; CBOR key 0 — SHALL be 0x46444F31 ("FDO1")
    DCActive:        bool,      ; CBOR key 1 — FDO active flag
    DCProtVer:       uint,      ; CBOR key 2 — protocol version (101, 200, etc.)
    DCDeviceInfo:    tstr,      ; CBOR key 3 — device info string
    DCGuid:          bstr,      ; CBOR key 4 — 16-byte GUID
    DCRVInfo:        array,     ; CBOR key 5 — rendezvous directives
    DCPubKeyHash:    Hash,      ; CBOR key 6 — owner public key hash
    DeviceKeyType:   uint,      ; CBOR key 7 — 0=DAK, 1=IDevID, 2=LDevID (informational)
    DeviceKeyHandle: uint,      ; CBOR key 8 — persistent TPM handle for device key
    HMACKeyHandle:   uint,      ; CBOR key 9 — persistent TPM handle for HMAC key (omitempty)
]
```

Magic value `0x46444F31` = ASCII "FDO1". Readers MUST verify before interpreting.

### Go Code Reference (what Rust needs to match)

**Go struct** (in `go-fdo/cred/tpm_store.go`):
```go
type dctpmNVData struct {
    Magic         uint32                     `cbor:"0,keyasint"`
    Active        bool                       `cbor:"1,keyasint"`
    Version       uint16                     `cbor:"2,keyasint"`
    DeviceInfo    string                     `cbor:"3,keyasint"`
    GUID          protocol.GUID              `cbor:"4,keyasint"`
    RvInfo        [][]protocol.RvInstruction `cbor:"5,keyasint"`
    PublicKeyHash protocol.Hash              `cbor:"6,keyasint"`
    KeyType       protocol.KeyType           `cbor:"7,keyasint"`
    DAKHandle     uint32                     `cbor:"8,keyasint"`
    HMACHandle    uint32                     `cbor:"9,keyasint,omitempty"`
}
```

**Go constants** (in `go-fdo/tpm/nv.go`):
```go
const DCTPMIndex = 0x01D10001
const DCTPMMagic uint32 = 0x46444F31
```

## Files to Update in Rust

### 1. `data-formats/src/tpm/mod.rs` — Constants

**Remove:**
- `DC_ACTIVE_INDEX` (0x01D10000)
- `DCOV_INDEX` (0x01D10002)
- `FDO_CERT_INDEX` (0x01D10005)
- `NvProfile::A` (was for DCActive)

**Add:**
- `DCTPM_MAGIC: u32 = 0x46444F31`

**Keep:**
- `DCTPM_INDEX` (0x01D10001) — now the single mandatory index
- `HMAC_US_INDEX` (0x01D10003) — optional
- `DEVICE_KEY_US_INDEX` (0x01D10004) — optional
- `DAK_HANDLE` (0x81020002)
- `HMAC_KEY_HANDLE` (0x81020003)
- `NvProfile::B` and `NvProfile::C` (still used for optional indices and DCTPM)

### 2. `data-formats/src/tpm/nv.rs` — NV Read/Write/Cleanup

**`NvCredentialInfo` struct — rewrite completely:**

Old fields to remove: `active`, `guid`, `device_info`, `has_dcov`, `dcov_data`

New struct:
```rust
pub struct NvCredentialInfo {
    pub has_dctpm: bool,
    pub raw_dctpm: Vec<u8>,    // raw CBOR from DCTPM NV index
    pub dctpm_size: u16,
    pub hmac_us_size: u16,
    pub device_key_us_size: u16,
    pub has_dak: bool,
    pub has_hmac_key: bool,
}
```

**`read_nv_credentials()` — simplify:**
- Remove DCActive read section
- Remove separate DCTPM (raw GUID+DeviceInfo) read section  
- Remove DCOV read section
- Remove FDO_Cert read section
- Add single DCTPM read using `NvProfile::C` (OwnerRead)

**`cleanup_fdo_state()` — simplify:**
- Remove `DC_ACTIVE_INDEX`, `DCOV_INDEX`, `FDO_CERT_INDEX` from cleanup list
- Keep `DCTPM_INDEX`, `HMAC_US_INDEX`, `DEVICE_KEY_US_INDEX`

### 3. `data-formats/src/tpm/credential.rs` — DeviceCredential Loading

**`load_from_tpm()` — rewrite CBOR decode:**

Old: Reads `info.active`, `info.guid`, `info.device_info` separately, then
decodes `info.dcov_data` as `[version, rvinfo, pubkeyhash, keytype]`.

New: Reads `info.raw_dctpm`, decodes as consolidated CBOR map with integer keys:
```rust
// Decode DCTPM CBOR
let dctpm: serde_cbor::Value = serde_cbor::from_slice(&info.raw_dctpm)?;
// Verify magic (key 0) == 0x46444F31
// Read active (key 1) — reject if false
// Read version (key 2), device_info (key 3), guid (key 4), 
// rvinfo (key 5), pubkeyhash (key 6), keytype (key 7),
// dak_handle (key 8), hmac_handle (key 9)
```

### 4. `manufacturing-client/src/main.rs` — DI Provisioning (NV Write)

**`store_credentials_to_tpm_nv()` (or equivalent) — rewrite:**

Old: Writes 3 separate NV indices (DCActive, DCTPM raw, DCOV CBOR).

New: Writes single DCTPM CBOR blob:
```rust
let dctpm = serde_cbor::Value::Map(vec![
    (serde_cbor::Value::Integer(0), serde_cbor::Value::Integer(0x46444F31)),  // Magic
    (serde_cbor::Value::Integer(1), serde_cbor::Value::Bool(true)),           // Active
    (serde_cbor::Value::Integer(2), serde_cbor::Value::Integer(version as i128)), // Version
    (serde_cbor::Value::Integer(3), serde_cbor::Value::Text(device_info)),    // DeviceInfo
    (serde_cbor::Value::Integer(4), serde_cbor::Value::Bytes(guid.to_vec())), // GUID
    (serde_cbor::Value::Integer(5), rvinfo_cbor),                             // RvInfo
    (serde_cbor::Value::Integer(6), pubkeyhash_cbor),                         // PubKeyHash
    (serde_cbor::Value::Integer(7), serde_cbor::Value::Integer(keytype as i128)), // KeyType
    (serde_cbor::Value::Integer(8), serde_cbor::Value::Integer(DAK_HANDLE as i128)), // DAKHandle
    (serde_cbor::Value::Integer(9), serde_cbor::Value::Integer(HMAC_KEY_HANDLE as i128)), // HMACHandle
]);
let dctpm_bytes = serde_cbor::to_vec(&dctpm)?;
// Write to DCTPM_INDEX using NvProfile::C
```

**Important:** The Go code uses CBOR integer-keyed maps (via `keyasint` struct tags).
The Rust `serde_cbor` equivalent is `serde_cbor::Value::Map` with `Integer` keys.
Alternatively, define a proper Rust struct with `#[serde(rename)]` or use ciborium.

### 5. `client-linuxapp/src/main.rs` — TO2 Credential Update

After TO2 completes (non-reuse), the client updates credentials:
- Rewrite the DCTPM NV index with new GUID, RVInfo, PubKeyHash (keeping
  Magic, Active=true, key handles same)
- This replaces the old code that wrote separate DCTPM + DCOV + DCActive indices

### 6. Test Updates

**Interop test script** (`test_rust_fdo20_interop.sh`):
- TPM cross-implementation tests need to match the new NV layout
- `tpm-rust-di-go-onboard`: Rust DI writes new DCTPM format → Go loads it
- `tpm-go-di-rust-onboard`: Go DI writes new DCTPM format → Rust loads it

## Cross-Implementation Compatibility

The critical interop requirement: Go DI writes DCTPM → Rust reads it (and vice versa).

**The CBOR wire format MUST match exactly:**
- Integer-keyed map (keys 0-9)
- Magic at key 0 = `0x46444F31`
- GUID at key 4 as `bstr` (16 bytes)
- RvInfo at key 5 in the same CBOR format both sides use
- Hash at key 6 in the same format (algorithm + value)

**Test this with hex dumps:** After Go DI writes to TPM, read with `tpm2_nvread`
and decode. After Rust DI writes, do the same. Compare byte-for-byte.

## What Does NOT Need to Change

- Key creation (CreatePrimary, EvictControl) — same TPM operations
- Unique String NV indices — still provisioned the same way (optional)
- DAK/HMAC persistent handles — same defaults
- Policy session auth (PolicyNV + PolicySecret) — same, still optional
- The `rvserver.local` fallback — this is Go client-side only, not a TPM concern

## Priority Order

1. **Constants + NvCredentialInfo struct** (mod.rs, nv.rs) — foundation
2. **DI write path** (manufacturing-client) — writes the new format
3. **Load path** (credential.rs) — reads the new format
4. **TO2 update path** (client-linuxapp) — updates after onboarding
5. **Interop tests** — verify Go ↔ Rust compatibility
6. **Cleanup** — remove dead code, old NV profile references
