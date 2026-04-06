// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause

//! TPM spec-compliant credential storage for FDO.
//!
//! Implements "Securing FDO Credentials in the TPM v1.0" using NV indices
//! for credential storage, persistent handles for keys, and Endorsement
//! hierarchy for key derivation with unique strings.
//!
//! This module is only compiled when the `tpm_support` feature is enabled.

pub mod credential;
pub mod key;
pub mod nv;
#[allow(dead_code, unused_imports, clippy::all)]
pub mod policy;

use std::str::FromStr;

use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::Context;

use crate::errors::Error;

// ============================================================
// NV Index Handles (per spec section 4.2)
// ============================================================

/// Consolidated DCTPM NV index: single index for all FDO credentials (CBOR array).
pub const DCTPM_INDEX: u32 = 0x01D1_0001;

// Legacy NV indices — kept for cleanup_fdo_state to remove old-format data.
pub(crate) const LEGACY_DC_ACTIVE_INDEX: u32 = 0x01D1_0000;
pub(crate) const LEGACY_DCOV_INDEX: u32 = 0x01D1_0002;
pub(crate) const LEGACY_FDO_CERT_INDEX: u32 = 0x01D1_0005;

// ============================================================
// Persistent Object Handles
// ============================================================

/// Device Attestation Key (ECC signing key).
pub const DAK_HANDLE: u32 = 0x8102_0002;
/// HMAC key.
pub const HMAC_KEY_HANDLE: u32 = 0x8102_0003;

// ============================================================
// NV Attribute Profiles (per spec Table 9)
// ============================================================

/// NV index attribute profile, determining access controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvProfile {
    /// DCTPM profile: Owner+Auth R/W, NoDA, optional PlatformCreate.
    /// Used for the consolidated DCTPM NV index (0x01D10001).
    Dctpm,
    /// Legacy Profile B: Owner+Auth R/W, NoDA, PlatformCreate.
    /// Retained for cleanup of old-format indices.
    #[allow(dead_code)]
    LegacyB,
}

// ============================================================
// Context Initialization
// ============================================================

/// Open a TPM context using the environment variable or /dev/tpmrm0 fallback.
pub fn open_context() -> Result<Context, Error> {
    let tcti_conf = TctiNameConf::from_environment_variable().unwrap_or_else(|_| {
        let device = tss_esapi::tcti_ldr::DeviceConfig::from_str("/dev/tpmrm0")
            .expect("Error creating device config for /dev/tpmrm0");
        TctiNameConf::Device(device)
    });
    Context::new(tcti_conf).map_err(Error::from)
}
