// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause

//! LEGACY: TPM policy session operations for FDO key authorization.
//!
//! This module implements the PolicyNV+PolicySecret compound policy that was
//! required by earlier versions of the FDO TPM spec when keys had
//! `userWithAuth=0`. The current spec (Table 11) uses `userWithAuth=1` with
//! empty authValue, making policy sessions unnecessary for key usage.
//!
//! This module is retained for reference and backward compatibility with
//! devices provisioned under the old authorization model.
//!
//! # Old Model (userWithAuth=0, authPolicy required):
//!   PolicyNV(US_NV, offset=0, operand=0x00, UnsignedGE) + PolicySecret(US_NV)
//!
//! # Current Model (userWithAuth=1, no authPolicy):
//!   Empty password auth (null auth) via TPM2_Sign / TPM2_HMAC
//!
//! # Known Limitation: tss-esapi 7.6 Missing PolicyNV
//!
//! The Rust TSS wrapper library `tss-esapi` version 7.6 does not implement
//! `TPM2_PolicyNV`. It was explicitly skipped in the original implementation
//! (see: https://github.com/parallaxsecond/rust-tss-esapi/pull/95).
//! `HMAC_Start`, `SequenceUpdate`, and `SequenceComplete` are also missing.
//!
//! ## Workaround: Second ESYS Connection
//!
//! We cannot call `Esys_PolicyNV` through the `tss_esapi::Context` because:
//! - The `Context` struct is not `#[repr(C)]`, so rustc may reorder fields
//! - The `ESYS_CONTEXT*` pointer is in a private field (`mut_context()`)
//! - We cannot reliably extract the pointer to make raw FFI calls
//!
//! Instead, we open a **second, independent ESYS connection** to the same TPM
//! device using `tss-esapi-sys` directly. This second connection is used only
//! for `Esys_PolicyNV` calls. The policy session handle is created on the
//! primary `tss_esapi::Context` and its raw `ESYS_TR` value is passed to the
//! second connection (ESYS_TR values are process-global via the resource
//! manager, so they work across ESYS contexts connected to the same TPM).
//!
//! ## TODO: Upstream Fix
//!
//! This workaround should be removed when either:
//! - `tss-esapi` adds `policy_nv()` (file an upstream PR)
//! - We upgrade to a version of `tss-esapi` that includes it
//! - `tss-esapi::Context` exposes the raw `ESYS_CONTEXT*` pointer
//!
//! Tracking: https://github.com/parallaxsecond/rust-tss-esapi/pull/95

use std::convert::TryFrom;
use std::str::FromStr;

use tss_esapi::{
    constants::SessionType,
    handles::{NvIndexHandle, ObjectHandle, SessionHandle},
    interface_types::algorithm::HashingAlgorithm,
    interface_types::session_handles::{AuthSession, PolicySession},
    structures::{Digest, Name, Nonce, SymmetricDefinition},
    Context,
};

use crate::errors::Error;

/// TPM2_CC_PolicyNV command code
const TPM2_CC_POLICY_NV: u32 = 0x0000_0149;
/// TPM2_CC_PolicySecret command code
const TPM2_CC_POLICY_SECRET: u32 = 0x0000_0151;
/// TPM2_EO_UNSIGNED_GE operation code (0x0007 per TPM 2.0 spec Part 2, Table 88).
/// Must match tss_esapi::constants::tss::TPM2_EO_UNSIGNED_GE.
const TPM2_EO_UNSIGNED_GE: u16 = tss_esapi::constants::tss::TPM2_EO_UNSIGNED_GE as u16;

// ============================================================
// Trial Policy: Software Computation (no TPM call needed)
// ============================================================

/// Compute the FDO auth policy digest using a real TPM trial session.
///
/// Uses the second-connection workaround (see module docs) to run a trial
/// session with PolicyNV + PolicySecret, then reads the resulting digest.
/// This produces an authoritative, TPM-computed digest that exactly matches
/// what the TPM will expect at runtime.
///
/// Policy: PolicyNV(US_NV, offset=0, operand=0x00, UnsignedGE) + PolicySecret(US_NV)
#[deprecated(note = "Legacy: current spec uses userWithAuth=1 with empty authValue. No policy session needed.")]
pub fn compute_fdo_auth_policy(
    _ctx: &mut Context,
    us_nv_handle: NvIndexHandle,
) -> Result<Digest, Error> {
    // Get the raw TPM NV index value from the handle
    let nv_tpm_index: u32 = {
        let (nv_public, _) =
            _ctx.execute_without_session(|ctx| ctx.nv_read_public(us_nv_handle))?;
        nv_public.nv_index().into()
    };

    let digest_bytes = compute_policy_digest_on_raw_connection(nv_tpm_index)?;
    Digest::try_from(digest_bytes).map_err(Error::from)
}

/// Run a trial policy session on a second ESYS connection and return the digest.
///
/// WORKAROUND: tss-esapi 7.6 lacks PolicyNV, so we do this on a raw connection.
/// TODO: Remove when tss-esapi adds `policy_nv()`.
fn compute_policy_digest_on_raw_connection(nv_tpm_index: u32) -> Result<Vec<u8>, Error> {
    use tss_esapi::constants::tss::{TPM2_ALG_AES, TPM2_ALG_CFB, TPM2_ALG_SHA256, TPM2_SE_TRIAL};
    use tss_esapi::tss2_esys::*;

    let esys_ctx = open_raw_esys_connection()?;

    // Convert NV index to ESYS_TR
    let mut nv_tr: ESYS_TR = ESYS_TR_NONE;
    let rc = unsafe {
        Esys_TR_FromTPMPublic(
            esys_ctx,
            nv_tpm_index,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut nv_tr,
        )
    };
    if rc != 0 {
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented(
            "TR_FromTPMPublic failed in trial session",
        ));
    }

    // Debug: dump the NV Name and attributes that ESYS sees
    {
        let mut nv_pub_ptr: *mut TPM2B_NV_PUBLIC = std::ptr::null_mut();
        let mut nv_name_ptr: *mut TPM2B_NAME = std::ptr::null_mut();
        let rc = unsafe {
            Esys_NV_ReadPublic(
                esys_ctx,
                nv_tr,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &mut nv_pub_ptr,
                &mut nv_name_ptr,
            )
        };
        if rc == 0 {
            if !nv_name_ptr.is_null() {
                let n = unsafe { &*nv_name_ptr };
                let hex: String = n.name[..n.size as usize]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
                log::info!("ESYS NV Name for 0x{:08X}: {}", nv_tpm_index, hex);
            }
            if !nv_pub_ptr.is_null() {
                let p = unsafe { &*nv_pub_ptr };
                log::info!(
                    "ESYS NV attrs for 0x{:08X}: 0x{:08X}, size={}",
                    nv_tpm_index,
                    p.nvPublic.attributes,
                    p.nvPublic.dataSize
                );
            }
        }
    }

    // Start TRIAL session
    let symmetric = TPMT_SYM_DEF {
        algorithm: TPM2_ALG_AES as u16,
        keyBits: TPMU_SYM_KEY_BITS { aes: 128 },
        mode: TPMU_SYM_MODE {
            aes: TPM2_ALG_CFB as u16,
        },
    };
    let mut session_tr: ESYS_TR = ESYS_TR_NONE;
    let rc = unsafe {
        Esys_StartAuthSession(
            esys_ctx,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            std::ptr::null(),
            TPM2_SE_TRIAL,
            &symmetric,
            TPM2_ALG_SHA256 as u16,
            &mut session_tr,
        )
    };
    if rc != 0 {
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented("StartAuthSession (trial) failed"));
    }

    // PolicyNV
    let operand = TPM2B_OPERAND {
        size: 1,
        buffer: {
            let mut b = [0u8; 64];
            b[0] = 0;
            b
        },
    };
    let rc = unsafe {
        Esys_PolicyNV(
            esys_ctx,
            nv_tr,
            nv_tr,
            session_tr,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &operand,
            0,
            TPM2_EO_UNSIGNED_GE as TPM2_EO,
        )
    };
    if rc != 0 {
        log::error!("PolicyNV (trial): 0x{:08X}", rc);
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented("PolicyNV (trial) failed"));
    }

    // Debug: digest after PolicyNV
    {
        let mut d: *mut TPM2B_DIGEST = std::ptr::null_mut();
        let rc = unsafe {
            Esys_PolicyGetDigest(
                esys_ctx,
                session_tr,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &mut d,
            )
        };
        if rc == 0 && !d.is_null() {
            let dig = unsafe { &*d };
            let hex: String = dig.buffer[..dig.size as usize]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect();
            log::info!("Digest after PolicyNV: {}", hex);
        }
    }

    // PolicySecret
    let empty = TPM2B_NONCE {
        size: 0,
        buffer: [0u8; 64],
    };
    let empty_d = TPM2B_DIGEST {
        size: 0,
        buffer: [0u8; 64],
    };
    let mut to: *mut TPM2B_TIMEOUT = std::ptr::null_mut();
    let mut tk: *mut TPMT_TK_AUTH = std::ptr::null_mut();
    let rc = unsafe {
        Esys_PolicySecret(
            esys_ctx,
            nv_tr,
            session_tr,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &empty,
            &empty_d,
            &empty,
            0,
            &mut to,
            &mut tk,
        )
    };
    if rc != 0 {
        log::error!("PolicySecret (trial): 0x{:08X}", rc);
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented("PolicySecret (trial) failed"));
    }

    // Get the policy digest
    let mut digest_ptr: *mut TPM2B_DIGEST = std::ptr::null_mut();
    let rc = unsafe {
        Esys_PolicyGetDigest(
            esys_ctx,
            session_tr,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut digest_ptr,
        )
    };
    if rc != 0 {
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented("PolicyGetDigest failed"));
    }

    let digest = unsafe { &*digest_ptr };
    let result = digest.buffer[..digest.size as usize].to_vec();

    // Flush the trial session and close
    unsafe { Esys_FlushContext(esys_ctx, session_tr) };
    close_raw_esys_connection(esys_ctx);

    log::info!(
        "Trial policy digest computed on second connection ({} bytes)",
        result.len()
    );
    Ok(result)
}

// ============================================================
// Runtime Policy Session: Second ESYS Connection for PolicyNV
// ============================================================

/// Open a second, independent ESYS connection to the TPM for raw FFI calls.
///
/// WORKAROUND: See module-level documentation for why this is needed.
/// This connection is used exclusively for `Esys_PolicyNV` which is missing
/// from tss-esapi 7.6. The returned pointer must be freed with `Esys_Finalize`.
fn open_raw_esys_connection() -> Result<*mut tss_esapi::tss2_esys::ESYS_CONTEXT, Error> {
    use tss_esapi::tss2_esys::*;

    // Determine TCTI the same way tss-esapi does: env var or /dev/tpmrm0
    let tcti_name = std::env::var("TSS2_TCTI").unwrap_or_else(|_| "device:/dev/tpmrm0".to_string());

    // Initialize TCTI
    let tcti_name_c = std::ffi::CString::new(tcti_name.as_str())
        .map_err(|_| Error::NotImplemented("invalid TCTI name"))?;

    let mut tcti_ctx: *mut TSS2_TCTI_CONTEXT = std::ptr::null_mut();
    let rc = unsafe { Tss2_TctiLdr_Initialize(tcti_name_c.as_ptr(), &mut tcti_ctx) };
    if rc != 0 {
        return Err(Error::NotImplemented("Tss2_TctiLdr_Initialize failed"));
    }

    // Initialize ESYS context on top of the TCTI
    let mut esys_ctx: *mut ESYS_CONTEXT = std::ptr::null_mut();
    let rc = unsafe { Esys_Initialize(&mut esys_ctx, tcti_ctx, std::ptr::null_mut()) };
    if rc != 0 {
        unsafe { Tss2_TctiLdr_Finalize(&mut tcti_ctx) };
        return Err(Error::NotImplemented("Esys_Initialize failed"));
    }

    Ok(esys_ctx)
}

/// Close a raw ESYS connection opened by `open_raw_esys_connection`.
fn close_raw_esys_connection(esys_ctx: *mut tss_esapi::tss2_esys::ESYS_CONTEXT) {
    if !esys_ctx.is_null() {
        unsafe { tss_esapi::tss2_esys::Esys_Finalize(&mut (esys_ctx as *mut _)) };
    }
}

/// Call TPM2_PolicyNV via a second ESYS connection.
///
/// WORKAROUND: tss-esapi 7.6 does not implement PolicyNV.
/// We open an independent ESYS connection to the same TPM resource manager
/// and call `Esys_PolicyNV` directly. The policy session handle (ESYS_TR)
/// was created by the primary tss-esapi Context, but ESYS_TR values are
/// process-global when using the kernel resource manager (/dev/tpmrm0),
/// so they work across ESYS contexts.
///
/// TODO: Remove this when tss-esapi adds `policy_nv()`.
fn call_policy_nv_via_second_connection(
    nv_index: u32,
    session_tr: tss_esapi::tss2_esys::ESYS_TR,
) -> Result<(), Error> {
    use tss_esapi::tss2_esys::*;

    let esys_ctx = open_raw_esys_connection()?;

    // Convert the NV index to an ESYS_TR on this new context
    let mut nv_tr: ESYS_TR = ESYS_TR_NONE;
    let nv_tpm_handle = nv_index;
    let rc = unsafe {
        Esys_TR_FromTPMPublic(
            esys_ctx,
            nv_tpm_handle,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut nv_tr,
        )
    };
    if rc != 0 {
        log::error!(
            "Esys_TR_FromTPMPublic for NV 0x{:08X} failed: 0x{:08X}",
            nv_index,
            rc
        );
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented(
            "TR_FromTPMPublic failed for NV index",
        ));
    }

    let operand = TPM2B_OPERAND {
        size: 1,
        buffer: {
            let mut buf = [0u8; 64]; // TPM2B_OPERAND = TPM2B_DIGEST, 64-byte buffer
            buf[0] = 0x00;
            buf
        },
    };

    let rc = unsafe {
        Esys_PolicyNV(
            esys_ctx,
            nv_tr,            // authHandle: NV index self-auth
            nv_tr,            // nvIndex: NV index to compare
            session_tr,       // policySession
            ESYS_TR_PASSWORD, // shandle1: password auth for NV index
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &operand,
            0, // offset
            TPM2_EO_UNSIGNED_GE as TPM2_EO,
        )
    };

    close_raw_esys_connection(esys_ctx);

    if rc != 0 {
        log::error!("Esys_PolicyNV failed: 0x{:08X}", rc);
        return Err(Error::NotImplemented("PolicyNV call failed"));
    }

    Ok(())
}

/// Build a complete policy session (StartAuthSession + PolicyNV + PolicySecret)
/// on a second ESYS connection, returning the TPM-level session handle.
///
/// The returned handle can be imported into the primary tss-esapi Context
/// via `tr_from_tpm_public`.
///
/// WORKAROUND: This exists because tss-esapi 7.6 doesn't implement PolicyNV.
/// TODO: Remove when tss-esapi adds `policy_nv()`.
fn build_policy_session_on_raw_connection(nv_tpm_index: u32) -> Result<u32, Error> {
    use tss_esapi::constants::tss::{TPM2_ALG_AES, TPM2_ALG_CFB, TPM2_ALG_SHA256, TPM2_SE_POLICY};
    use tss_esapi::tss2_esys::*;

    let esys_ctx = open_raw_esys_connection()?;

    // Convert NV index to ESYS_TR
    let mut nv_tr: ESYS_TR = ESYS_TR_NONE;
    let rc = unsafe {
        Esys_TR_FromTPMPublic(
            esys_ctx,
            nv_tpm_index,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut nv_tr,
        )
    };
    if rc != 0 {
        log::error!("TR_FromTPMPublic NV 0x{:08X}: 0x{:08X}", nv_tpm_index, rc);
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented("TR_FromTPMPublic failed"));
    }

    // StartAuthSession (trial=false, policy session)
    let symmetric = TPMT_SYM_DEF {
        algorithm: TPM2_ALG_AES as u16,
        keyBits: TPMU_SYM_KEY_BITS { aes: 128 },
        mode: TPMU_SYM_MODE {
            aes: TPM2_ALG_CFB as u16,
        },
    };
    let mut session_tr: ESYS_TR = ESYS_TR_NONE;
    let rc = unsafe {
        Esys_StartAuthSession(
            esys_ctx,
            ESYS_TR_NONE, // tpmKey
            ESYS_TR_NONE, // bind
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,     // shandles
            std::ptr::null(), // nonceCaller (NULL = TPM generates)
            TPM2_SE_POLICY,   // sessionType = policy
            &symmetric,
            TPM2_ALG_SHA256 as u16, // authHash
            &mut session_tr,
        )
    };
    if rc != 0 {
        log::error!("StartAuthSession: 0x{:08X}", rc);
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented("StartAuthSession failed"));
    }

    // PolicyNV
    let operand = TPM2B_OPERAND {
        size: 1,
        buffer: {
            let mut buf = [0u8; 64];
            buf[0] = 0x00;
            buf
        },
    };
    let rc = unsafe {
        Esys_PolicyNV(
            esys_ctx,
            nv_tr,            // authHandle
            nv_tr,            // nvIndex
            session_tr,       // policySession
            ESYS_TR_PASSWORD, // shandle1
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &operand,
            0, // offset
            TPM2_EO_UNSIGNED_GE as TPM2_EO,
        )
    };
    if rc != 0 {
        log::error!("PolicyNV: 0x{:08X}", rc);
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented("PolicyNV failed"));
    }

    // PolicySecret
    let empty = TPM2B_NONCE {
        size: 0,
        buffer: [0u8; 64],
    };
    let empty_digest = TPM2B_DIGEST {
        size: 0,
        buffer: [0u8; 64],
    };
    let mut timeout_ptr: *mut TPM2B_TIMEOUT = std::ptr::null_mut();
    let mut ticket_ptr: *mut TPMT_TK_AUTH = std::ptr::null_mut();
    let rc = unsafe {
        Esys_PolicySecret(
            esys_ctx,
            nv_tr,            // authHandle (NV index)
            session_tr,       // policySession
            ESYS_TR_PASSWORD, // shandle1
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &empty,        // nonceTPM
            &empty_digest, // cpHashA
            &empty,        // policyRef
            0,             // expiration
            &mut timeout_ptr,
            &mut ticket_ptr,
        )
    };
    if rc != 0 {
        log::error!("PolicySecret: 0x{:08X}", rc);
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented("PolicySecret failed"));
    }

    // Get the TPM-level handle for this session so we can import it
    // into the primary context. ESYS_TR -> TPM handle via Esys_TR_GetTpmHandle.
    let mut tpm_handle: u32 = 0;
    let rc = unsafe { Esys_TR_GetTpmHandle(esys_ctx, session_tr, &mut tpm_handle) };
    if rc != 0 {
        log::error!("TR_GetTpmHandle: 0x{:08X}", rc);
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented("TR_GetTpmHandle failed"));
    }

    log::info!(
        "Policy session built on second connection, TPM handle=0x{:08X}",
        tpm_handle
    );

    // NOTE: We intentionally do NOT close the second ESYS connection here.
    // Esys_Finalize would flush the policy session we just built.
    // The second connection will be leaked (the OS will clean it up on process exit).
    // This is acceptable because policy sessions are short-lived (used once for
    // the next sign/hmac operation, then the TPM auto-flushes them).
    //
    // TODO: Track the raw connection and close it after the sign/hmac operation.
    // close_raw_esys_connection(esys_ctx);

    Ok(tpm_handle)
}

/// Sign a digest using a persistent key with PolicyNV+PolicySecret authorization.
///
/// WORKAROUND: The entire operation (start session, satisfy policy, sign) is
/// performed on a second ESYS connection because tss-esapi 7.6 lacks PolicyNV.
///
/// TODO: Remove when tss-esapi adds `policy_nv()`.
pub fn sign_with_policy(
    nv_tpm_index: u32,
    key_persistent_handle: u32,
    digest: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    use tss_esapi::constants::tss::{
        TPM2_ALG_AES, TPM2_ALG_CFB, TPM2_ALG_NULL, TPM2_ALG_SHA256, TPM2_RH_NULL, TPM2_SE_POLICY,
        TPM2_ST_HASHCHECK,
    };
    use tss_esapi::tss2_esys::*;

    let esys_ctx = open_raw_esys_connection()?;

    // Get NV ESYS_TR
    let mut nv_tr: ESYS_TR = ESYS_TR_NONE;
    let rc = unsafe {
        Esys_TR_FromTPMPublic(
            esys_ctx,
            nv_tpm_index,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut nv_tr,
        )
    };
    if rc != 0 {
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented("TR_FromTPMPublic NV"));
    }

    // Get key ESYS_TR
    let mut key_tr: ESYS_TR = ESYS_TR_NONE;
    let rc = unsafe {
        Esys_TR_FromTPMPublic(
            esys_ctx,
            key_persistent_handle,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut key_tr,
        )
    };
    if rc != 0 {
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented("TR_FromTPMPublic key"));
    }

    // Build policy session
    let symmetric = TPMT_SYM_DEF {
        algorithm: TPM2_ALG_AES as u16,
        keyBits: TPMU_SYM_KEY_BITS { aes: 128 },
        mode: TPMU_SYM_MODE {
            aes: TPM2_ALG_CFB as u16,
        },
    };
    let mut session_tr: ESYS_TR = ESYS_TR_NONE;
    let rc = unsafe {
        Esys_StartAuthSession(
            esys_ctx,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            std::ptr::null(),
            TPM2_SE_POLICY,
            &symmetric,
            TPM2_ALG_SHA256 as u16,
            &mut session_tr,
        )
    };
    if rc != 0 {
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented("StartAuthSession"));
    }

    // PolicyNV
    let operand = TPM2B_OPERAND {
        size: 1,
        buffer: {
            let mut b = [0u8; 64];
            b[0] = 0;
            b
        },
    };
    let rc = unsafe {
        Esys_PolicyNV(
            esys_ctx,
            nv_tr,
            nv_tr,
            session_tr,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &operand,
            0,
            TPM2_EO_UNSIGNED_GE as TPM2_EO,
        )
    };
    if rc != 0 {
        log::error!("PolicyNV: 0x{:08X}", rc);
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented("PolicyNV"));
    }

    // PolicySecret
    let empty = TPM2B_NONCE {
        size: 0,
        buffer: [0u8; 64],
    };
    let empty_d = TPM2B_DIGEST {
        size: 0,
        buffer: [0u8; 64],
    };
    let mut to: *mut TPM2B_TIMEOUT = std::ptr::null_mut();
    let mut tk: *mut TPMT_TK_AUTH = std::ptr::null_mut();
    let rc = unsafe {
        Esys_PolicySecret(
            esys_ctx,
            nv_tr,
            session_tr,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &empty,
            &empty_d,
            &empty,
            0,
            &mut to,
            &mut tk,
        )
    };
    if rc != 0 {
        log::error!("PolicySecret: 0x{:08X}", rc);
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented("PolicySecret"));
    }

    // Sign with policy session
    let tpm_digest = TPM2B_DIGEST {
        size: digest.len() as u16,
        buffer: {
            let mut buf = [0u8; 64];
            buf[..digest.len()].copy_from_slice(digest);
            buf
        },
    };
    let validation = TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: TPM2B_DIGEST {
            size: 0,
            buffer: [0u8; 64],
        },
    };
    let scheme = TPMT_SIG_SCHEME {
        scheme: TPM2_ALG_NULL as u16,
        details: TPMU_SIG_SCHEME {
            any: TPMS_SCHEME_HASH { hashAlg: 0 },
        },
    };

    let mut sig_ptr: *mut TPMT_SIGNATURE = std::ptr::null_mut();
    let rc = unsafe {
        Esys_Sign(
            esys_ctx,
            key_tr,
            session_tr,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &tpm_digest,
            &scheme,
            &validation,
            &mut sig_ptr,
        )
    };
    close_raw_esys_connection(esys_ctx);

    if rc != 0 {
        log::error!("Sign: 0x{:08X}", rc);
        return Err(Error::NotImplemented("Sign with policy failed"));
    }

    // Extract ECDSA r,s from signature
    let sig = unsafe { &*sig_ptr };
    let ecdsa = unsafe { &sig.signature.ecdsa };
    let r = ecdsa.signatureR.buffer[..ecdsa.signatureR.size as usize].to_vec();
    let s = ecdsa.signatureS.buffer[..ecdsa.signatureS.size as usize].to_vec();
    Ok((r, s))
}

/// Compute HMAC using a persistent key with PolicyNV+PolicySecret authorization.
///
/// WORKAROUND: Same second-connection approach as sign_with_policy.
/// TODO: Remove when tss-esapi adds `policy_nv()`.
pub fn hmac_with_policy(
    nv_tpm_index: u32,
    key_persistent_handle: u32,
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    use tss_esapi::constants::tss::{TPM2_ALG_AES, TPM2_ALG_CFB, TPM2_ALG_SHA256, TPM2_SE_POLICY};
    use tss_esapi::tss2_esys::*;

    let esys_ctx = open_raw_esys_connection()?;

    // Get NV ESYS_TR
    let mut nv_tr: ESYS_TR = ESYS_TR_NONE;
    let rc = unsafe {
        Esys_TR_FromTPMPublic(
            esys_ctx,
            nv_tpm_index,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut nv_tr,
        )
    };
    if rc != 0 {
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented("TR_FromTPMPublic NV"));
    }

    // Get key ESYS_TR
    let mut key_tr: ESYS_TR = ESYS_TR_NONE;
    let rc = unsafe {
        Esys_TR_FromTPMPublic(
            esys_ctx,
            key_persistent_handle,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut key_tr,
        )
    };
    if rc != 0 {
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented("TR_FromTPMPublic key"));
    }

    // Build policy session
    let symmetric = TPMT_SYM_DEF {
        algorithm: TPM2_ALG_AES as u16,
        keyBits: TPMU_SYM_KEY_BITS { aes: 128 },
        mode: TPMU_SYM_MODE {
            aes: TPM2_ALG_CFB as u16,
        },
    };
    let mut session_tr: ESYS_TR = ESYS_TR_NONE;
    let rc = unsafe {
        Esys_StartAuthSession(
            esys_ctx,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            std::ptr::null(),
            TPM2_SE_POLICY,
            &symmetric,
            TPM2_ALG_SHA256 as u16,
            &mut session_tr,
        )
    };
    if rc != 0 {
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented("StartAuthSession"));
    }

    // PolicyNV
    let operand = TPM2B_OPERAND {
        size: 1,
        buffer: {
            let mut b = [0u8; 64];
            b[0] = 0;
            b
        },
    };
    let rc = unsafe {
        Esys_PolicyNV(
            esys_ctx,
            nv_tr,
            nv_tr,
            session_tr,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &operand,
            0,
            TPM2_EO_UNSIGNED_GE as TPM2_EO,
        )
    };
    if rc != 0 {
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented("PolicyNV"));
    }

    // PolicySecret
    let empty = TPM2B_NONCE {
        size: 0,
        buffer: [0u8; 64],
    };
    let empty_d = TPM2B_DIGEST {
        size: 0,
        buffer: [0u8; 64],
    };
    let mut to: *mut TPM2B_TIMEOUT = std::ptr::null_mut();
    let mut tk: *mut TPMT_TK_AUTH = std::ptr::null_mut();
    let rc = unsafe {
        Esys_PolicySecret(
            esys_ctx,
            nv_tr,
            session_tr,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &empty,
            &empty_d,
            &empty,
            0,
            &mut to,
            &mut tk,
        )
    };
    if rc != 0 {
        close_raw_esys_connection(esys_ctx);
        return Err(Error::NotImplemented("PolicySecret"));
    }

    // HMAC with policy session
    let buffer = TPM2B_MAX_BUFFER {
        size: data.len() as u16,
        buffer: {
            let mut buf = [0u8; 1024]; // TPM2B_MAX_BUFFER max
            buf[..data.len()].copy_from_slice(data);
            buf
        },
    };
    let mut hmac_ptr: *mut TPM2B_DIGEST = std::ptr::null_mut();
    let rc = unsafe {
        Esys_HMAC(
            esys_ctx,
            key_tr,
            session_tr,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &buffer,
            TPM2_ALG_SHA256 as u16,
            &mut hmac_ptr,
        )
    };
    close_raw_esys_connection(esys_ctx);

    if rc != 0 {
        log::error!("HMAC: 0x{:08X}", rc);
        return Err(Error::NotImplemented("HMAC with policy failed"));
    }

    let hmac = unsafe { &*hmac_ptr };
    Ok(hmac.buffer[..hmac.size as usize].to_vec())
}

// The old create_fdo_key_policy_session is no longer the primary interface.
// Callers should use sign_with_policy() and hmac_with_policy() directly.
///
/// Satisfies the compound policy:
///   PolicyNV(US_NV, offset=0, operand=0x00, UnsignedGE) + PolicySecret(US_NV)
///
/// WORKAROUND: The entire policy session (StartAuthSession + PolicyNV + PolicySecret)
/// is executed on a second, independent ESYS connection because tss-esapi 7.6 lacks
/// PolicyNV. The satisfied session handle is then imported into the primary context
/// via `tr_from_tpm_public` so it can be used with tss-esapi's `execute_with_session`.
///
/// TODO: Remove second connection when tss-esapi adds `policy_nv()`.
pub fn create_fdo_key_policy_session(
    ctx: &mut Context,
    us_nv_handle: NvIndexHandle,
) -> Result<(PolicySession, AuthSession), Error> {
    // Get the NV index's TPM handle value (needed for the second connection)
    let (nv_public, _) = ctx.execute_without_session(|ctx| ctx.nv_read_public(us_nv_handle))?;
    let nv_tpm_index: u32 = nv_public.nv_index().into();

    // Do the entire policy session on a second ESYS connection
    let session_tpm_handle = build_policy_session_on_raw_connection(nv_tpm_index)?;

    // Import the TPM session handle into the primary tss-esapi context.
    // Policy session TPM handles are in the 0x03xxxxxx range.
    let session_object: ObjectHandle = ctx.execute_without_session(|ctx| {
        ctx.tr_from_tpm_public(tss_esapi::handles::TpmHandle::PolicySession(
            tss_esapi::handles::PolicySessionTpmHandle::new(session_tpm_handle)?,
        ))
    })?;

    // Wrap as AuthSession for tss-esapi
    let session_handle: tss_esapi::handles::SessionHandle = session_object.into();
    let auth_session = AuthSession::create(
        SessionType::Policy,
        session_handle,
        HashingAlgorithm::Sha256,
    )
    .ok_or(Error::NotImplemented("session creation returned None"))?;

    let policy_session: PolicySession = match auth_session {
        AuthSession::PolicySession(ps) => ps,
        _ => return Err(Error::NotImplemented("expected PolicySession")),
    };

    Ok((policy_session, auth_session))
}
