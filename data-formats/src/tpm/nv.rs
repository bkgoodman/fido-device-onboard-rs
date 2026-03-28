// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause

//! NV index operations for FDO credential storage.
//!
//! Consolidated single-NV-index model: all FDO credentials are stored in
//! a single DCTPM NV index as a CBOR structure with a magic header.

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
    NvProfile, DAK_HANDLE, DCTPM_INDEX, DEVICE_KEY_US_INDEX, HMAC_KEY_HANDLE, HMAC_US_INDEX,
};

/// Information read from TPM NV credential index.
#[derive(Debug)]
pub struct NvCredentialInfo {
    /// True if DCTPM NV index exists and contains data.
    pub has_dctpm: bool,
    /// Raw DCTPM CBOR content.
    pub raw_dctpm: Vec<u8>,
    /// DCTPM NV index size.
    pub dctpm_size: u16,
    /// HMAC Unique String NV index size (0 = not defined).
    pub hmac_us_size: u16,
    /// Device Key Unique String NV index size (0 = not defined).
    pub device_key_us_size: u16,
    /// True if persistent DAK handle exists.
    pub has_dak: bool,
    /// True if persistent HMAC key handle exists.
    pub has_hmac_key: bool,
}

/// Build NV index attributes for a given profile.
///
/// If `use_platform` is false, Profile B indices use Owner hierarchy
/// instead of Platform (for Linux userspace where Platform is locked).
fn build_nv_attrs(
    profile: NvProfile,
    use_platform: bool,
) -> Result<tss_esapi::attributes::NvIndexAttributes, Error> {
    let mut builder = NvIndexAttributesBuilder::new();

    match profile {
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
        NvProfile::B => {
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
        NvProfile::C => NvAuth::Owner,
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
    for index in &[DCTPM_INDEX, HMAC_US_INDEX, DEVICE_KEY_US_INDEX] {
        undefine_nv_space(ctx, *index, use_platform);
    }
    for handle in &[DAK_HANDLE, HMAC_KEY_HANDLE] {
        super::key::evict_persistent_handle(ctx, *handle);
    }
}

/// Read FDO credential data from the TPM DCTPM NV index.
pub fn read_nv_credentials(ctx: &mut Context) -> Result<NvCredentialInfo, Error> {
    let mut info = NvCredentialInfo {
        has_dctpm: false,
        raw_dctpm: Vec::new(),
        dctpm_size: 0,
        hmac_us_size: 0,
        device_key_us_size: 0,
        has_dak: false,
        has_hmac_key: false,
    };

    // DCTPM — single consolidated NV index (OwnerRead)
    if let Ok((nv_public, _, nv_handle)) = read_nv_public(ctx, DCTPM_INDEX) {
        let size = nv_public.data_size() as u16;
        info.dctpm_size = size;
        info.has_dctpm = true;
        if let Ok(data) = read_nv(ctx, nv_handle, size, NvProfile::C) {
            info.raw_dctpm = data;
        }
    }

    // HMAC_US (optional, provisioning-entity artifact)
    if let Ok((nv_public, _, _)) = read_nv_public(ctx, HMAC_US_INDEX) {
        info.hmac_us_size = nv_public.data_size() as u16;
    }

    // DeviceKey_US (optional, provisioning-entity artifact)
    if let Ok((nv_public, _, _)) = read_nv_public(ctx, DEVICE_KEY_US_INDEX) {
        info.device_key_us_size = nv_public.data_size() as u16;
    }

    // Check persistent key handles
    info.has_dak = super::key::persistent_handle_exists(ctx, DAK_HANDLE);
    info.has_hmac_key = super::key::persistent_handle_exists(ctx, HMAC_KEY_HANDLE);

    Ok(info)
}
