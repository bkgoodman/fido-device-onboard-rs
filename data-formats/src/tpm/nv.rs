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
    NvProfile, DAK_HANDLE, DCOV_INDEX, DCTPM_INDEX, DC_ACTIVE_INDEX, DEVICE_KEY_US_INDEX,
    FDO_CERT_INDEX, HMAC_KEY_HANDLE, HMAC_US_INDEX,
};

/// Information read from TPM NV credential indices.
#[derive(Debug)]
pub struct NvCredentialInfo {
    /// DCActive flag (true = device initialized).
    pub active: bool,
    /// Device GUID (16 bytes) from DCTPM.
    pub guid: [u8; 16],
    /// Device info string from DCTPM.
    pub device_info: String,
    /// True if DCOV NV index exists.
    pub has_dcov: bool,
    /// Raw DCOV content (CBOR-encoded).
    pub dcov_data: Vec<u8>,
    /// True if persistent DAK handle exists.
    pub has_dak: bool,
    /// True if persistent HMAC key handle exists.
    pub has_hmac_key: bool,
}

/// Build NV index attributes for a given profile.
///
/// If `use_platform` is false, Profile A/B indices use Owner hierarchy
/// instead of Platform (for Linux userspace where Platform is locked).
fn build_nv_attrs(
    profile: NvProfile,
    use_platform: bool,
) -> Result<tss_esapi::attributes::NvIndexAttributes, Error> {
    let mut builder = NvIndexAttributesBuilder::new();

    match profile {
        NvProfile::A => {
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
        NvProfile::B => {
            builder = builder
                .with_auth_write(true)
                .with_auth_read(true)
                .with_no_da(true);
            if use_platform {
                builder = builder.with_platform_create(true);
            }
        }
        NvProfile::C => {
            builder = builder
                .with_owner_write(true)
                .with_auth_write(true)
                .with_owner_read(true)
                .with_auth_read(true)
                .with_no_da(true);
            // Profile C: no PlatformCreate
        }
    }

    builder.build().map_err(Error::from)
}

/// Auth handle for NV define operations.
fn define_auth(profile: NvProfile, use_platform: bool) -> Provision {
    match profile {
        NvProfile::A | NvProfile::B => {
            if use_platform {
                Provision::Platform
            } else {
                Provision::Owner
            }
        }
        NvProfile::C => Provision::Owner,
    }
}

/// Auth handle for NV read/write operations.
fn rw_auth(profile: NvProfile, nv_handle: NvIndexHandle) -> NvAuth {
    match profile {
        NvProfile::A | NvProfile::C => NvAuth::Owner,
        NvProfile::B => NvAuth::NvIndex(nv_handle),
    }
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
    for index in &[
        DC_ACTIVE_INDEX,
        DCTPM_INDEX,
        DCOV_INDEX,
        HMAC_US_INDEX,
        DEVICE_KEY_US_INDEX,
        FDO_CERT_INDEX,
    ] {
        undefine_nv_space(ctx, *index, use_platform);
    }
    for handle in &[DAK_HANDLE, HMAC_KEY_HANDLE] {
        super::key::evict_persistent_handle(ctx, *handle);
    }
}

/// Read all FDO credential data from TPM NV indices.
pub fn read_nv_credentials(ctx: &mut Context) -> Result<NvCredentialInfo, Error> {
    let mut info = NvCredentialInfo {
        active: false,
        guid: [0u8; 16],
        device_info: String::new(),
        has_dcov: false,
        dcov_data: Vec::new(),
        has_dak: false,
        has_hmac_key: false,
    };

    // DCActive (Profile A: OwnerRead)
    if let Ok((nv_public, _, nv_handle)) = read_nv_public(ctx, DC_ACTIVE_INDEX) {
        let size = nv_public.data_size() as u16;
        if let Ok(data) = read_nv(ctx, nv_handle, size, NvProfile::A) {
            info.active = !data.is_empty() && data[0] == 0x01;
        }
    }

    // DCTPM (Profile B: AuthRead)
    if let Ok((nv_public, _, nv_handle)) = read_nv_public(ctx, DCTPM_INDEX) {
        let size = nv_public.data_size() as u16;
        if let Ok(data) = read_nv(ctx, nv_handle, size, NvProfile::B) {
            if data.len() >= 16 {
                info.guid.copy_from_slice(&data[..16]);
                info.device_info = String::from_utf8_lossy(&data[16..]).to_string();
            }
        }
    }

    // DCOV (Profile C: OwnerRead)
    if let Ok((nv_public, _, nv_handle)) = read_nv_public(ctx, DCOV_INDEX) {
        let size = nv_public.data_size() as u16;
        info.has_dcov = true;
        if let Ok(data) = read_nv(ctx, nv_handle, size, NvProfile::C) {
            info.dcov_data = data;
        }
    }

    // Check persistent key handles
    info.has_dak = super::key::persistent_handle_exists(ctx, DAK_HANDLE);
    info.has_hmac_key = super::key::persistent_handle_exists(ctx, HMAC_KEY_HANDLE);

    Ok(info)
}
