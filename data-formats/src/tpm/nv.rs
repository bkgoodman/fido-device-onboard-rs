// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause

//! NV index operations for FDO credential storage.

use std::convert::TryFrom;

use tss_esapi::{
    attributes::NvIndexAttributesBuilder,
    handles::{NvIndexHandle, NvIndexTpmHandle},
    interface_types::{
        algorithm::HashingAlgorithm,
        resource_handles::{NvAuth, Provision},
    },
    structures::{MaxNvBuffer, Name, NvPublic, NvPublicBuilder},
    Context,
};

use crate::errors::Error;

use super::{
    NvProfile, DCTPM_INDEX, DAK_HANDLE, HMAC_KEY_HANDLE,
    LEGACY_DC_ACTIVE_INDEX, LEGACY_DCOV_INDEX, LEGACY_FDO_CERT_INDEX,
};

/// Information read from TPM NV credential indices.
#[derive(Debug)]
pub struct NvCredentialInfo {
    /// True if consolidated DCTPM was found and decoded.
    pub has_dctpm: bool,
    /// Raw DCTPM CBOR bytes (consolidated array).
    pub raw_dctpm: Vec<u8>,
    /// DCTPM Magic value (should be 0x46444F31 = "FDO1").
    pub magic: u32,
    /// DCActive flag (true = device initialized). From consolidated DCTPM[1].
    pub active: bool,
    /// True if persistent DAK handle exists.
    pub has_dak: bool,
    /// True if persistent HMAC key handle exists.
    pub has_hmac_key: bool,
}

/// Build NV index attributes for a given profile.
///
/// DCTPM profile: Owner+Auth R/W, NoDA, PlatformCreate if available.
/// LegacyB profile: same attributes (retained for cleanup compatibility).
fn build_nv_attrs(
    profile: NvProfile,
    use_platform: bool,
) -> Result<tss_esapi::attributes::NvIndexAttributes, Error> {
    let mut builder = NvIndexAttributesBuilder::new();

    match profile {
        NvProfile::Dctpm | NvProfile::LegacyB => {
            builder = builder
                .with_owner_write(true)
                .with_auth_write(true)
                .with_owner_read(true)
                .with_auth_read(true)
                .with_no_da(true);
            if use_platform {
                builder = builder.with_platform_create(true);
            }
        }
    }

    builder.build().map_err(Error::from)
}

/// Auth handle for NV define operations.
fn define_auth(_profile: NvProfile, use_platform: bool) -> Provision {
    if use_platform {
        Provision::Platform
    } else {
        Provision::Owner
    }
}

/// Auth handle for NV read/write operations.
fn rw_auth(_profile: NvProfile, _nv_handle: NvIndexHandle) -> NvAuth {
    NvAuth::Owner
}

// ============================================================
// NV Index Management
// ============================================================

/// Define an NV index with the specified profile attributes.
/// Returns the NV index handle.
pub fn define_nv_space(
    ctx: &mut Context,
    index: u32,
    size: usize,
    profile: NvProfile,
    use_platform: bool,
) -> Result<NvIndexHandle, Error> {
    let attrs = build_nv_attrs(profile, use_platform)?;
    let nv_index = NvIndexTpmHandle::new(index).map_err(Error::from)?;

    let nv_public = NvPublicBuilder::new()
        .with_nv_index(nv_index)
        .with_index_name_algorithm(HashingAlgorithm::Sha256)
        .with_index_attributes(attrs)
        .with_data_area_size(size)
        .build()?;

    let auth = define_auth(profile, use_platform);
    ctx.execute_with_nullauth_session(|ctx| ctx.nv_define_space(auth, None, nv_public))
        .map_err(Error::from)
}

/// Write data to an NV index.
pub fn write_nv(
    ctx: &mut Context,
    nv_handle: NvIndexHandle,
    data: &[u8],
    profile: NvProfile,
) -> Result<(), Error> {
    let auth = rw_auth(profile, nv_handle);
    let buffer = MaxNvBuffer::try_from(data).map_err(Error::from)?;
    ctx.execute_with_nullauth_session(|ctx| ctx.nv_write(auth, nv_handle, buffer, 0))
        .map_err(Error::from)
}

/// Read data from an NV index.
pub fn read_nv(
    ctx: &mut Context,
    nv_handle: NvIndexHandle,
    size: u16,
    profile: NvProfile,
) -> Result<Vec<u8>, Error> {
    let auth = rw_auth(profile, nv_handle);
    let data = ctx
        .execute_with_nullauth_session(|ctx| ctx.nv_read(auth, nv_handle, size, 0))
        .map_err(Error::from)?;
    Ok(data.to_vec())
}

/// Read the NV public data and return (NvPublic, Name).
pub fn read_nv_public(
    ctx: &mut Context,
    index: u32,
) -> Result<(NvPublic, Name, NvIndexHandle), Error> {
    let nv_index = NvIndexTpmHandle::new(index).map_err(Error::from)?;
    let nv_handle = ctx
        .execute_without_session(|ctx| ctx.tr_from_tpm_public(nv_index.into()))
        .map_err(Error::from)?;
    let nv_handle: NvIndexHandle = nv_handle.into();
    let (nv_public, name) = ctx
        .execute_without_session(|ctx| ctx.nv_read_public(nv_handle))
        .map_err(Error::from)?;
    Ok((nv_public, name, nv_handle))
}

/// Undefine (delete) an NV index. Ignores errors if index doesn't exist.
pub fn undefine_nv_space(ctx: &mut Context, index: u32, use_platform: bool) {
    if let Ok((_, _, nv_handle)) = read_nv_public(ctx, index) {
        let auth = if use_platform {
            Provision::Platform
        } else {
            Provision::Owner
        };
        let _ = ctx.execute_with_nullauth_session(|ctx| ctx.nv_undefine_space(auth, nv_handle));
    }
}

/// Remove all FDO NV indices and persistent handles.
pub fn cleanup_fdo_state(ctx: &mut Context, use_platform: bool) {
    // Clean up current and legacy NV indices
    for index in &[
        DCTPM_INDEX,
        // Legacy indices from old multi-NV model
        LEGACY_DC_ACTIVE_INDEX,
        LEGACY_DCOV_INDEX,
        LEGACY_FDO_CERT_INDEX,
        0x01D1_0003, // legacy HMAC_US
        0x01D1_0004, // legacy DeviceKey_US
    ] {
        undefine_nv_space(ctx, *index, use_platform);
    }
    for handle in &[DAK_HANDLE, HMAC_KEY_HANDLE] {
        super::key::evict_persistent_handle(ctx, *handle);
    }
}

/// Read all FDO credential data from TPM NV indices.
///
/// Reads the consolidated DCTPM NV index (0x01D10001) which contains a CBOR
/// array: [Magic, Active, Version, DeviceInfo, GUID, RvInfo, PubKeyHash,
/// KeyType, DeviceKeyHandle, HMACKeyHandle].
pub fn read_nv_credentials(ctx: &mut Context) -> Result<NvCredentialInfo, Error> {
    let mut info = NvCredentialInfo {
        has_dctpm: false,
        raw_dctpm: Vec::new(),
        magic: 0,
        active: false,
        has_dak: false,
        has_hmac_key: false,
    };

    // Read consolidated DCTPM (OwnerRead)
    if let Ok((nv_public, _, nv_handle)) = read_nv_public(ctx, DCTPM_INDEX) {
        let size = nv_public.data_size() as u16;
        if let Ok(data) = read_nv(ctx, nv_handle, size, NvProfile::Dctpm) {
            if !data.is_empty() {
                info.raw_dctpm = data;
                info.has_dctpm = true;

                // Extract Magic [0] and Active [1] from consolidated DCTPM array
                if let Ok(cbor) = serde_cbor::from_slice::<serde_cbor::Value>(&info.raw_dctpm) {
                    if let serde_cbor::Value::Array(ref arr) = cbor {
                        if arr.len() >= 2 {
                            if let serde_cbor::Value::Integer(m) = &arr[0] {
                                info.magic = *m as u32;
                            }
                            if let serde_cbor::Value::Bool(active) = &arr[1] {
                                info.active = *active;
                            }
                        }
                    }
                }
            }
        }
    }

    // Check persistent key handles
    info.has_dak = super::key::persistent_handle_exists(ctx, DAK_HANDLE);
    info.has_hmac_key = super::key::persistent_handle_exists(ctx, HMAC_KEY_HANDLE);

    Ok(info)
}
