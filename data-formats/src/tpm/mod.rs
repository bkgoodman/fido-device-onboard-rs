// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause

//! TPM spec-compliant credential storage for FDO.
//!
//! Implements "Securing FDO Credentials in the TPM" using a single NV index
//! (DCTPM) for all FDO device credentials, and persistent handles for keys.
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
// NV Index Handle
// ============================================================

/// DCTPM: Single mandatory NV index for all FDO credentials (CBOR-encoded).
/// Contains: Magic, Active, Version, DeviceInfo, GUID, RvInfo, PubKeyHash,
/// DeviceKeyType, DeviceKeyHandle, HMACKeyHandle.
pub const DCTPM_INDEX: u32 = 0x01D1_0001;

/// Magic value identifying valid FDO DCTPM data. ASCII "FDO1" = 0x46444F31.
/// Readers MUST verify this before interpreting the CBOR structure.
pub const DCTPM_MAGIC: u32 = 0x4644_4F31;

// Optional provisioning-entity NV indices (not required for client interop).

/// HMAC Unique String: 32 bytes random seed for HMAC key derivation.
/// Only needed if using Primary keys with policy-based auth.
pub const HMAC_US_INDEX: u32 = 0x01D1_0003;
/// Device Key Unique String: 64 bytes (P-256) or 96 bytes (P-384) for key derivation.
/// Only needed if using Primary keys with policy-based auth.
pub const DEVICE_KEY_US_INDEX: u32 = 0x01D1_0004;

// ============================================================
// Persistent Object Handles (example values for testing)
// ============================================================

/// Device Attestation Key (ECC signing key) — default persistent handle.
/// Implementations MAY use any valid persistent handle; the chosen handle
/// is recorded in DCTPM.DeviceKeyHandle.
pub const DAK_HANDLE: u32 = 0x8102_0002;
/// HMAC key — default persistent handle.
/// Implementations MAY use any valid persistent handle; the chosen handle
/// is recorded in DCTPM.HMACKeyHandle.
pub const HMAC_KEY_HANDLE: u32 = 0x8102_0003;

// ============================================================
// NV Attribute Profiles
// ============================================================

/// NV index attribute profile, determining access controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvProfile {
    /// Profile B (Unique Strings): Auth-only R/W, NoDA, PlatformCreate.
    B,
    /// Profile C (DCTPM): Owner+Auth R/W, NoDA, no PlatformCreate.
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
