# FDO TPM Spec Revision Plan

This document captures the design decisions, rationale, and specific changes
to be made to `securing-fdo-in-tpm.bs` based on the completeness review of
policy digest computation and the subsequent architectural simplification.

## Background

The original spec review focused on whether Section 7.2 (Policy Digest
Computation) was prescriptive enough for cross-implementation interoperability.
The review found the algorithm itself was correctly specified, but the spec
allowed too many degrees of freedom in NV index configuration — all of which
feed into the policy digest hash. Two conforming implementations making
different (but individually valid) choices for NV attributes would produce
incompatible keys.

This led to a deeper architectural discussion about TPM hierarchy design,
which produced a significantly simplified credential storage model. A
subsequent analysis of the key authorization model determined that the
policy-based authorization (`userWithAuth=0` with PolicyNV + PolicySecret)
adds implementation complexity without meaningful security benefit when the
DCTPM authValue is empty — which is the common case. Switching to
`userWithAuth=1` with empty authValue eliminates the entire policy digest
machinery while preserving the TPM's fundamental security guarantee
(`fixedTPM=1` — key material never leaves the TPM hardware).

---

## Summary of Changes

### A. Consolidated NV Storage (DCTPM)

**Change:** Collapse six NV indices into one.

**Current spec:** Six NV indices, each with separate handles:

| Handle | Name | Purpose |
|--------|------|---------|
| 0x01D10000 | DCActive | 1-byte "should FDO run?" flag |
| 0x01D10001 | DCTPM | Public credentials (GUID, RVInfo, etc.) |
| 0x01D10002 | DCOV | Ownership Voucher (optional) |
| 0x01D10003 | HMAC U/S | HMAC key unique string |
| 0x01D10004 | Device Key U/S | Device key unique string |
| 0x01D10005 | FDO Certificate | X.509 certificate (optional) |

**New spec:** One NV index:

| Handle | Name | Purpose |
|--------|------|---------|
| 0x01D10001 | DCTPM | All FDO credential data (combined) |

**Rationale:**

1. The Active flag was separate because NV indices have index-level (not
   field-level) permissions. Active needed `OWNERWRITE=1` while other
   credential data was more restricted. However, the HMAC binding in the
   Ownership Voucher is the real integrity check — if credential data is
   tampered with, the HMAC won't match the OV and TO2 fails. NV permissions
   are a secondary layer. Combining Active into DCTPM is acceptable because
   tamper is cryptographically detectable.

2. The unique strings (HMAC U/S, Device Key U/S) were separate because the
   key authPolicy (PolicyNV + PolicySecret) referenced them by NV Name. With
   the switch to `userWithAuth=1` (see Section D), keys no longer have an
   authPolicy and the policy machinery is eliminated entirely. The unique
   strings are now just data — they can be stored anywhere the software can
   read them. DCTPM is the natural location.

3. DCOV (Ownership Voucher) is a delivery mechanism for TPM vendor → device
   manufacturer supply chain. It is not needed for FDO protocol operation.
   Dropped from the spec. Vendors who need this can use vendor-specific
   storage.

4. FDO Certificate (X.509) is optional and rarely needed — the certificate
   lives in the Ownership Voucher on the server side. Dropped from the spec.

**Impact on existing sections:**

- Section 5.2 (Handles, Table 5): Replace six NV index entries with one.
  Reserve 0x01D10000–0x01D10005 for FDO but only 0x01D10001 is defined.
- Section 5.4 (FDO Active flag): Remove as standalone section; Active becomes
  a field in DCTPM.
- Section 5.5 (FDO Public Device Credentials): Rewrite DCTPM CDDL to include
  all fields.
- Section 5.8 (HMAC Secret): Remove unique string NV storage discussion;
  unique string is now a DCTPM field.
- Section 5.6 (Device Key): Same — unique string in DCTPM.
- Section 6 (Ownership Voucher): Remove or reduce to informative note.
- Section 7.1 (NV Index Attributes, Tables 8 and 9): Simplify to one NV index
  with two profile variants.
- Section 7.2 (Policy Digest Computation): **Remove entirely** (see Section D).
- Section 7.2.1 (Test Vectors): **Remove entirely** (see Section D).

### B. New DCTPM CBOR Structure

**Current CDDL:**

```cddl
DCTPM = [
    DCProtVer:       protver,
    DCDeviceInfo:    tstr,
    DCGuid:          Guid,
    DCRVInfo:        RendezvousInfo,
    DCPubKeyHash:    Hash,
    DeviceKeyType:   uint,
    DeviceKeyHandle: uint
]
```

**New CDDL:**

```cddl
DCTPM = [
    DCProtVer:        protver,
    DCDeviceInfo:     tstr,
    DCGuid:           Guid,
    DCRVInfo:         RendezvousInfo,
    DCPubKeyHash:     Hash,
    DeviceKeyHandle:  uint,
    HMACKeyHandle:    uint,
    Active:           uint,           ; 1 = FDO should run, 0 = skip
    DeviceKeyUnique:  bstr / null,    ; non-null = DAK (rotatable), null = IDevID/LDevID
    HMACUnique:       bstr            ; always present (FDO-managed)
]
```

**Field changes:**

- `DeviceKeyType` **removed** — redundant with `DeviceKeyUnique`:
  - `DeviceKeyUnique` non-null → DAK (FDO-managed, rotatable)
  - `DeviceKeyUnique` null → IDevID or LDevID (managed by TCG DevID spec)
  - The specific key type (IDevID vs LDevID) doesn't affect FDO protocol
    behavior — FDO just signs with whatever key is at `DeviceKeyHandle`.
    The type only matters for lifecycle management, which is inferred from
    the handle and unique string presence.

- `HMACKeyHandle` **added** — the HMAC key persistent handle was previously
  at a well-known fixed address. Now it's discoverable from DCTPM, same as
  the device key. This supports both Profile O and Profile P without
  hardcoding handle ranges.

- `Active` **moved in** from DCActive NV index — saves an NV index. The OS
  toggles Active by reading DCTPM, modifying the Active field, and writing
  back. The HMAC binding detects any credential tampering.

- `DeviceKeyUnique` **moved in** from Device Key U/S NV index.

- `HMACUnique` **moved in** from HMAC U/S NV index.

**NV allocation:** The spec SHALL recommend a minimum DCTPM dataSize of 768
bytes to accommodate the combined structure with room for variable-length
fields (DeviceInfo, RVInfo). The dataSize is fixed at `NV_DefineSpace` time.

### C. Two Hierarchy Profiles (Profile O and Profile P)

**Change:** Define exactly two NV attribute profiles for the DCTPM index.

**Current spec:** Table 9 defines attribute bits with SHOULD/MAY language and
a footnote about PLATFORMCREATE variability. This allows arbitrary attribute
combinations.

**New spec:** Two named, fully specified profiles. With the elimination of
policy-based key authorization (Section D), the profiles no longer affect
key authPolicy digests. They control only NV lifecycle (survives Clear or
not) and persistent handle ranges.

**Profile O (Owner hierarchy):**

- For: supply chain entities, post-onboarding credential management, anyone
  provisioning with Owner auth.
- NV attributes: `OWNERWRITE=1, AUTHWRITE=1, OWNERREAD=1, AUTHREAD=1,
  NO_DA=1, PLATFORMCREATE=0, NT=TPM_NT_ORDINARY`
- Key derivation hierarchy: Owner (SPS)
- Persistent handle range: 0x81000000–0x817FFFFF (Owner persistent)
- `TPM2_Clear` behavior: **wipes everything** (NV deleted, persistent objects
  evicted, SPS changes so re-derivation produces different keys)
- Rotation: Owner auth can rewrite DCTPM (new unique strings → new keys)
- Recommended persistent handles: 0x81020002 (DAK), 0x81020003 (HMAC)
- Persistence: OPTIONAL for keys (can re-derive with `CreatePrimary` under
  Owner hierarchy since Owner auth is typically available at runtime)

**Profile P (Platform hierarchy):**

- For: TPM vendors and OEMs provisioning during manufacturing, where
  credentials must survive `TPM2_Clear` by downstream firmware/BIOS.
- NV attributes: `AUTHWRITE=1, AUTHREAD=1, NO_DA=1, PLATFORMCREATE=1,
  NT=TPM_NT_ORDINARY`
- Key derivation hierarchy: Platform (PPS)
- Persistent handle range: 0x81800000–0x81FFFFFF (Platform persistent)
- `TPM2_Clear` behavior: **everything survives** (PLATFORMCREATE NV persists,
  Platform persistent objects survive, PPS unchanged)
- Rotation: requires Platform auth (typically firmware only)
- Recommended persistent handles: 0x81800002 (DAK), 0x81800003 (HMAC)
- Persistence: REQUIRED for keys (Platform auth is locked by firmware after
  boot; runtime software cannot call `CreatePrimary` under Platform hierarchy)

**Rationale:**

Two profiles are needed because of a fundamental TPM design constraint:

- **Owner hierarchy** (SPS) is reset by `TPM2_Clear`. NV indices without
  PLATFORMCREATE are deleted. Owner persistent objects are evicted. This is
  the "clean slate" behavior appropriate for post-manufacture provisioning.

- **Platform hierarchy** (PPS) survives `TPM2_Clear`. NV indices with
  PLATFORMCREATE survive. Platform persistent objects survive. This is needed
  for TPM vendor pre-provisioning where downstream manufacturers may issue
  `TPM2_Clear` (e.g., BIOS/firmware initialization sequences).

Note: with the `userWithAuth=1` model (Section D), the PLATFORMCREATE bit no
longer affects key authorization (there is no authPolicy to be influenced by
the NV Name). The profiles differ only in lifecycle behavior and persistent
handle ranges, not in key usability. A key provisioned under either profile
is used identically at runtime: `TPM2_Sign` or `TPM2_HMAC` with empty
password authorization.

**Impact on existing sections:**

- Section 5.3 (Authorization, Tables 6–7): Simplify — keys use password auth
  with empty authValue.
- Section 7.1 (NV Index Attributes, Tables 8–9): Replace with two named
  profile definitions.

### D. Elimination of Policy-Based Key Authorization

**Change:** Replace `userWithAuth=0` + PolicyNV/PolicySecret authorization
with `userWithAuth=1` + empty authValue. Remove the entire policy digest
machinery from the spec.

**Current spec:** Keys are created with `userWithAuth=0` and an `authPolicy`
computed from `PolicyNV(Unique String NV) + PolicySecret(Unique String NV)`.
This requires:
- Section 7.2: Three-step policy digest computation algorithm
- Section 7.2.1: Test vectors with computed hash values
- Table 12: Object policy description per key
- NV Name sensitivity: any NV attribute change produces a different policy
  digest, making keys incompatible across implementations that choose
  different attributes

**New spec:** Keys are created with `userWithAuth=1` and empty authValue.
No authPolicy. Any software that can reach the TPM can call `TPM2_Sign` or
`TPM2_HMAC` with empty password authorization. No policy sessions needed.

**Sections removed:**

- Section 7.2 (Policy Digest Computation): **Removed entirely.**
- Section 7.2.1 (Test Vectors for Policy Digest): **Removed entirely.**
- Table 12 (Object policy for FDO keys): **Removed entirely.**

**Rationale:**

The policy-based model was designed to restrict key usage to callers who
know the NV index's authValue. However:

1. **Empty authValue = no restriction.** In the common deployment (DCTPM
   authValue is empty), the policy session succeeds for any caller.
   `userWithAuth=1` with empty password provides identical access.

2. **The real security is `fixedTPM=1`.** The TPM's fundamental guarantee
   is that key material never leaves the hardware. An attacker who can reach
   the TPM can ask it to sign, but cannot extract the private key. This
   property is independent of the authorization model.

3. **HMAC binding detects tampering.** If credential data in DCTPM is
   modified, the HMAC in the Ownership Voucher won't match and TO2 fails.
   NV access controls are a secondary integrity layer.

4. **Massive implementation simplification.** Eliminating policy digests
   removes:
   - The NV Name sensitivity problem (NV attributes no longer affect key
     usability)
   - The need for policy digest computation (trial sessions or software
     hash computation)
   - The need for profile-specific test vectors
   - The PolicyNV + PolicySecret session construction at runtime
   - The entire interoperability surface around policy digest matching

5. **Cross-profile compatibility.** Without authPolicy, a key provisioned
   under Profile O is used identically to a key provisioned under Profile P.
   The runtime software calls `TPM2_Sign(handle, digest)` with empty password
   regardless of which profile created the key. The profiles differ only in
   NV lifecycle and handle ranges, not in key authorization.

**Tradeoffs accepted:**

- **No future access restriction.** With `userWithAuth=1`, the key's
  authorization model is permanently set at creation time. A deployment
  cannot later restrict key usage by setting a DCTPM authValue (the key
  ignores it — it uses its own authValue, which is empty and immutable for
  primary keys). With the policy model, changing DCTPM's authValue via
  `NV_ChangeAuth` would have restricted PolicySecret satisfaction.

- **No credential lifecycle coupling.** With the policy model, deleting
  DCTPM made the key unusable (PolicyNV fails on non-existent NV). With
  `userWithAuth=1`, deleting DCTPM has no effect on key usability — the
  key is still usable with empty password. Implementations that delete FDO
  credentials MUST also evict the persistent DAK and HMAC key objects.

- **No time-based key locking.** The policy model could have supported
  `NV_ReadLock` to disable keys after the ROE phase (if READ_STCLEAR were
  enabled). This option is no longer available. The current spec does not
  use READ_STCLEAR, so this is not a regression.

**Impact on IDevID/LDevID compatibility:**

The `userWithAuth=1` model for DAK now matches the common IDevID model
(`userWithAuth=1`, empty authValue). This means DAK and IDevID keys are
authorized identically — the runtime software uses the same code path for
both. The `DeviceKeyUnique` null/non-null distinction determines rotatability,
not authorization behavior.

### E. Simplified Device Key Model

**Change:** Remove `DeviceKeyType` field. Infer key type from
`DeviceKeyUnique`.

**Current spec:** `DCTPM.DeviceKeyType` is an enum:
- 0 = FDO key (DAK)
- 1 = IDevID
- 2 = LDevID

Plus `DCTPM.DeviceKeyHandle` stores the handle.

**New spec:** `DeviceKeyUnique` (bstr / null) replaces `DeviceKeyType`:
- Non-null → DAK. The bytes are the unique string used for key derivation.
  Key is rotatable (write new unique to DCTPM, re-derive).
- Null → IDevID or LDevID. Key is not FDO-managed. Authorization follows
  the TCG DevID specification. Key is not rotatable by this spec.

`DeviceKeyHandle` continues to store the persistent handle.

**Rationale:** The type enum was redundant:
- Whether the key is rotatable is determined by the presence of a unique
  string, not by a type code.
- The FDO protocol doesn't behave differently based on key type — it signs
  with whatever key is at the handle.
- IDevID vs LDevID distinction is irrelevant to FDO — both are "not
  FDO-managed, use the TCG DevID spec."

**Impact on existing sections:**

- Section 5.1 (Credentials Overview, Table 1): Remove DeviceKeyType row.
  Update DeviceKeyHandle description.
- Section 5.5 (FDO Public Device Credentials): Update CDDL.
- Section 5.7 (Device Key Preference Order): Simplify. The preference order
  (DAK > LDevID > IDevID) is still valid but discovery changes: check
  `DeviceKeyUnique` field instead of `DeviceKeyType`.
- Section 8.1 (Credential Reuse Pathways): Update to reference
  `DeviceKeyUnique` instead of unique string NV index.

### F. Removed Sections

**DCOV (Section 6, Table 3, NV index 0x01D10002):** Remove entirely. The
Ownership Voucher delivery-via-TPM mechanism is a niche TPM vendor use case
that adds NV index allocation and spec complexity. Vendors who need this can
use vendor-specific storage outside this spec's scope.

**FDO Certificate (NV index 0x01D10005):** Remove. The device certificate
lives in the Ownership Voucher on the server side. If the device key is
IDevID, the certificate is managed by the TCG DevID specification.

**DCActive (NV index 0x01D10000):** Remove as standalone entity. The Active
flag is now a field in DCTPM.

**Unique String NV indices (0x01D10003, 0x01D10004):** Remove as standalone
entities. Unique strings are now fields in DCTPM.

### G. Persistent Object Handles

**Current spec (Table 4):**

| Object | Handle |
|--------|--------|
| FDO Device key | 0x81020002 |
| FDO HMAC secret | 0x81020003 |

These are in the Owner persistent range (0x81000000–0x817FFFFF).

**New spec:**

| Object | Profile O (recommended) | Profile P (recommended) |
|--------|------------------------|------------------------|
| DAK | 0x81020002 | 0x81800002 |
| HMAC key | 0x81020003 | 0x81800003 |

Recommended handles per profile, but the **authoritative source** is always
`DCTPM.DeviceKeyHandle` and `DCTPM.HMACKeyHandle`. Implementations MUST
read DCTPM to discover handles, not hardcode them.

**Rationale:** The TPM enforces different persistent handle ranges based on
which hierarchy authorization is used for `EvictControl`:
- Owner auth → 0x81000000–0x817FFFFF (evicted by `TPM2_Clear`)
- Platform auth → 0x81800000–0x81FFFFFF (survives `TPM2_Clear`)

Profile P requires Platform persistent range for `TPM2_Clear` survival.

**Handle allocation note:** The handle values above are for testing.
Production values require TCG allocation. FIDO is expected to be delegated
the range 0x01D10000–0x01D100FF for NV indices. Persistent object handle
allocation needs to be coordinated with TCG.

### H. Key Template Updates

**Change:** Keys use `userWithAuth=1` with empty authValue and empty
authPolicy. No policy sessions required.

Table 10 (FDO Device Key Templates) changes:
- `authPolicy.size` = 0 (empty — no policy)
- `authPolicy.buffer` = empty

The unique field in the key template:
- DAK: `inPublic.unique = TPMS_ECC_POINT` read from `DCTPM.DeviceKeyUnique`
  (first half = X, second half = Y)
- HMAC: `inPublic.unique = TPM2B_DIGEST` read from `DCTPM.HMACUnique`

Table 11 (Object attributes) changes:

| Attribute | Old value | New value | Rationale |
|-----------|-----------|-----------|-----------|
| `userWithAuth` | 0 | **1** | Enable password authorization (empty password) |
| `fixedTPM` | 1 | 1 | Unchanged — fundamental security guarantee |
| `fixedParent` | 1 | 1 | Unchanged |
| `sensitiveDataOrigin` | 1 | 1 | Unchanged |
| `sign` | 1 | 1 | Unchanged |
| All others | 0 | 0 | Unchanged |

Table 12 (Object policy for FDO keys): **Removed entirely.**

### I. TPM2_Clear Constraint

**Add normative text:** If FDO credentials have been pre-provisioned in the
TPM (e.g., by the TPM vendor using Profile P), the device manufacturer and
any intermediate supply chain entity SHALL NOT issue `TPM2_Clear` or
`TPM2_ChangePPS` before the device completes its first FDO onboarding.
Firmware, BIOS, or OS initialization sequences that include TPM clearing
operations MUST be configured to skip clearing when pre-provisioned FDO
credentials are present.

**Rationale:** Profile P credentials survive `TPM2_Clear` by design
(PLATFORMCREATE NV + Platform persistent objects). However, `TPM2_ChangePPS`
would change the Platform Primary Seed, making re-derivation of Platform
hierarchy keys produce different keys. While persisted keys survive
`TPM2_ChangePPS` (they're stored by value, not derived on the fly), any
future key derivation under Platform hierarchy would be inconsistent. The
constraint is belt-and-suspenders: Profile P credentials survive Clear, but
the spec should still warn against it.

For Profile O: `TPM2_Clear` intentionally wipes all FDO state. The device
falls back to IDevID (if present) and requires re-provisioning (DI).

### J. Discovery and Runtime Model

**Add normative text for implementation runtime flow:**

1. Probe NV index 0x01D10001 — if present, FDO credentials exist.
2. Read DCTPM — parse CBOR to get all fields.
3. Check `Active` field — if 0, do not run FDO.
4. Read `DeviceKeyHandle` — this is the device key's persistent handle.
5. Read `DeviceKeyUnique` — if non-null, device key is a DAK (rotatable);
   if null, device key is IDevID/LDevID (not FDO-managed).
6. Read `HMACKeyHandle` — this is the HMAC key's persistent handle.
7. Determine profile by handle range:
   - Handle in 0x81000000–0x817FFFFF → Profile O
   - Handle in 0x81800000–0x81FFFFFF → Profile P
8. Use DAK via `TPM2_Sign(DeviceKeyHandle, digest)` with empty password auth.
9. Use HMAC key via `TPM2_HMAC(HMACKeyHandle, data)` with empty password auth.

**Runtime software is profile-agnostic.** The authorization is identical for
both profiles: empty password. The profile distinction only matters during
provisioning (which hierarchy and handle range to use).

**IDevID/LDevID note:** When `DeviceKeyUnique` is null, the device key is
managed by the TCG DevID specification. To use such a key, the FDO software
MUST be able to call `TPM2_Sign` using the key at `DeviceKeyHandle`. The
authorization requirements vary by TPM vendor. Implementations SHOULD support
keys with `userWithAuth=1` (password authorization with empty authValue), which
is the common IDevID configuration. Support for vendor-specific authPolicy on
IDevID/LDevID keys is implementation-dependent and outside the scope of this
specification.

NOTE: The DAK path (`DeviceKeyUnique` non-null) provides fully specified
authorization (`userWithAuth=1`, empty password) with guaranteed
cross-implementation interoperability. The IDevID/LDevID path depends on
vendor-specific authorization that may require implementation-specific
integration work.

### K. Remaining Spec Gaps (from original review)

These items from the original completeness review are addressed by the changes
above:

| # | Original Gap | Resolution |
|---|-----|-----------|
| 1 | No computed test vector hash values | **Eliminated.** No policy digest = no test vectors needed. |
| 2 | NV attribute variability (SHOULD vs MUST) | **Fixed** by defining two mandatory profiles. NV attributes no longer affect key auth (no authPolicy). |
| 3 | Test vector inconsistent with Table 9 | **Eliminated.** Table 9 replaced by two named profiles. No test vectors. |
| 4 | PolicySecret policyRef not constrained | **Eliminated.** No PolicySecret. |
| 5 | NV nameAlg not required to match key nameAlg | **Eliminated.** NV Name no longer feeds into key authPolicy. NV nameAlg is a free choice. |
| 6 | NV authPolicy not constrained to empty | **Eliminated.** NV authPolicy is no longer security-critical (not hashed into key auth). |
| 7 | NV index type (NT) not specified | **Fixed** by specifying `NT=TPM_NT_ORDINARY` in both profiles. |
| 8 | SHA-384 path untested | **Still relevant** for key templates (SHA-384 curve/hash selection). No policy digest dependency. |

---

## Design Decisions Record

### D1: Why one NV index instead of six?

The unique strings were originally in separate NV indices because the key
authPolicy (PolicyNV + PolicySecret) referenced them by NV Name. With the
switch to `userWithAuth=1` (no authPolicy), the unique strings are just data
with no policy significance — they can be stored anywhere the software can
read them. The NV data content does not affect the NV Name, so consolidating
into DCTPM has no side effects. It eliminates five NV index allocations,
simplifies provisioning, and reduces the spec surface area.

### D2: Why two profiles?

The two hierarchy profiles (Owner and Platform) exist to support two real-
world deployment models: post-manufacture provisioning (wiped on Clear) and
TPM vendor pre-provisioning (survives Clear). With `userWithAuth=1`, the
profiles no longer produce different policy digests — they differ only in NV
lifecycle (PLATFORMCREATE) and persistent handle ranges. This makes them a
pure provisioning concern, invisible to runtime software.

### D3: Why Platform hierarchy (not Endorsement) for Profile P?

Platform auth is available to BOTH TPM vendors and device manufacturers during
their respective manufacturing flows. Endorsement auth is controlled by the
TPM vendor and may not be available to device manufacturers. Platform hierarchy
is literally the "manufacturing control" hierarchy in the TPM's design.
Endorsement hierarchy is reserved for permanent identity keys (EK, IDevID)
per TCG convention.

### D4: Why is persistence required for Profile P but optional for Profile O?

To use a TPM key, you either need it persisted (always available) or you
need to call `CreatePrimary` to re-derive it (requires hierarchy auth).
Owner auth is typically available to runtime software. Platform auth is
locked by firmware after boot. So Profile P keys must be persisted because
runtime software cannot re-derive them. Profile O keys can be re-derived
on demand.

### D5: Why was DeviceKeyType removed?

It was redundant with DeviceKeyUnique. The presence of a non-null unique
string means "DAK, FDO-managed, rotatable." Null means "IDevID or LDevID,
not FDO-managed." The specific IDevID-vs-LDevID distinction doesn't affect
FDO protocol behavior — FDO signs with whatever key is at the handle.

### D6: Why `userWithAuth=1` instead of policy-based authorization?

The policy-based model (`userWithAuth=0` with PolicyNV + PolicySecret) was
designed to tie key usage to the NV credential state. However, with an empty
authValue on the NV index (the common case), the policy provides no access
restriction beyond "NV exists" — which `fixedTPM=1` and the HMAC binding
already cover more fundamentally.

The policy model caused the original interoperability problem: the policy
digest is a cryptographic hash of the NV Name, which includes every NV
attribute bit. Different implementations choosing different NV attributes
(PLATFORMCREATE, OWNERWRITE, etc.) produced different policy digests and
incompatible keys. This was the central finding of the completeness review.

Switching to `userWithAuth=1` eliminates the policy digest entirely. NV
attributes no longer affect key usability. Keys provisioned under either
profile (O or P) are authorized identically at runtime. The interoperability
problem is solved by removing the mechanism that caused it.

The tradeoffs (no future access restriction, no lifecycle coupling, no time-
based locking) were evaluated and found acceptable for FDO's threat model.
The fundamental TPM guarantees (`fixedTPM=1`, HMAC binding, non-exportable
keys) provide the meaningful security. See Section D for full analysis.

### D7: Why keep the HMAC key as a TPM key object?

The FDO protocol (FDO 2.0 spec) requires the device to compute HMACs over
credential data for the Ownership Voucher. The HMAC value travels in the OV;
the HMAC secret stays in the device. Keeping the secret as a TPM keyed-hash
object ensures it never leaves the TPM hardware — software calls
`TPM2_HMAC(handle, data)` and gets back the result without seeing the key
material. This prevents offline OV forgery even if the device software is
compromised. The FDO 2.0 protocol cannot be changed to eliminate the HMAC
requirement at this time.

### D8: Why drop DCOV and FDO Certificate?

DCOV (Ownership Voucher in TPM) is a niche delivery mechanism for TPM vendors.
It's not needed for FDO operation. The OV normally lives on the server side.
FDO Certificate (device X.509 cert) is normally part of the OV, not stored
separately. Both add NV index allocations and spec complexity for rarely-used
features. Vendors who need them can use vendor-specific storage.

---

## Items NOT Changed

The following spec elements remain as-is:

- **Key templates (Table 10):** Algorithm parameters, curve IDs, and scheme
  definitions are unchanged. The `authPolicy` field becomes empty and
  `userWithAuth` changes to 1 (see Section D and H), but the cryptographic
  parameters (ECC curve, hash algorithm, key type) are unchanged.

- **Core object attributes:** `fixedTPM=1, fixedParent=1,
  sensitiveDataOrigin=1, sign=1` — unchanged. These provide the fundamental
  TPM security guarantees.

- **Device key preference order:** DAK > LDevID > IDevID priority is
  unchanged. Discovery mechanism changes (check DeviceKeyUnique instead of
  DeviceKeyType).

- **Credential reuse pathways:** Pathway A (rewrite DAK unique) and Pathway B
  (create LDevID) are both still valid. The unique string is now a field in
  DCTPM instead of a separate NV index.

- **Post-onboarding security model:** The Owner hierarchy access model and
  threat analysis are unchanged.

- **Section 8 (Implementation of FDO Using TPM):** Cryptographic operations
  table is unchanged.

---

## Migration Impact on Implementations

### Go implementation (go-fdo/tpm/)

- `nv.go`: NVProfileA/B/C collapse to two profiles (O and P). Single NV
  index for DCTPM.
- `nv.go`: **Remove** `ComputeFDOAuthPolicy` and `fdoKeyPolicy` functions
  entirely. No policy sessions needed.
- `key.go`: `GenerateSpecECKey` and `GenerateSpecHMACKey` change to
  `userWithAuth=1`, empty authPolicy. Read unique strings from DCTPM CBOR
  instead of separate NV reads.
- `spec_compliance_test.go`: Remove all AuthPolicyDigest tests. Update
  provisioning to use consolidated DCTPM. Simplify key usage tests (empty
  password instead of policy sessions).
- `phase9_integration_test.go`: Simplify provisioning flow (one NV define +
  write instead of four). Remove policy computation steps.

### Rust implementation (fido-device-onboard-rs/data-formats/src/tpm/)

- `policy.rs`: **Remove entirely.** No policy computation needed. The entire
  second-ESYS-connection workaround becomes unnecessary.
- `nv.rs`: Consolidate NV operations. Remove separate unique string indices.
- `mod.rs`: Update NV index constants (only DCTPM_INDEX remains).
- Manufacturing client: Simplify DI provisioning flow. Remove policy
  computation. Use `userWithAuth=1` in key templates.

### Cross-implementation testing

- Update `test_tpm_examples.sh` and interop tests.
- Key usage tests simplify dramatically: `TPM2_Sign` and `TPM2_HMAC` with
  empty password authorization. No policy session construction.
- Verify that keys created by Go implementation can be used by Rust
  implementation and vice versa, for both Profile O and Profile P.
