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
pub mod policy;

use std::str::FromStr;

use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::Context;

use crate::errors::Error;

// ============================================================
// NV Index Handles (per spec section 4.2)
// ============================================================

/// DCActive flag: 1 byte, 0x00 = not initialized, 0x01 = initialized.
pub const DC_ACTIVE_INDEX: u32 = 0x01D1_0000;
/// DCTPM: GUID (16 bytes) + DeviceInfo string.
pub const DCTPM_INDEX: u32 = 0x01D1_0001;
/// DCOV: CBOR-encoded credential metadata (version, RvInfo, PubKeyHash, KeyType).
pub const DCOV_INDEX: u32 = 0x01D1_0002;
/// HMAC Unique String: 32 bytes random seed for HMAC key derivation.
pub const HMAC_US_INDEX: u32 = 0x01D1_0003;
/// Device Key Unique String: 64 bytes (P-256) or 96 bytes (P-384) for key derivation.
pub const DEVICE_KEY_US_INDEX: u32 = 0x01D1_0004;
/// FDO Certificate (optional, not used in production).
pub const FDO_CERT_INDEX: u32 = 0x01D1_0005;

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
    /// Profile A (DCActive): Owner+Auth R/W, NoDA, PlatformCreate.
    A,
    /// Profile B (DCTPM, Unique Strings): Auth-only R/W, NoDA, PlatformCreate.
    B,
    /// Profile C (DCOV, FDO_Cert): Owner+Auth R/W, NoDA, no PlatformCreate.
    C,
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
