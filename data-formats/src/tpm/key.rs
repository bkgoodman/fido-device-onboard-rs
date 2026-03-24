// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause

//! TPM key management for FDO spec-compliant credential storage.
//!
//! Creates primary keys under the Endorsement hierarchy with unique strings
//! for deterministic derivation. Keys are persisted to spec-defined handles.

use std::convert::{TryFrom, TryInto};

use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    handles::{KeyHandle, NvIndexHandle, ObjectHandle, PersistentTpmHandle, TpmHandle},
    interface_types::{
        algorithm::HashingAlgorithm,
        ecc::EccCurve,
        resource_handles::{Hierarchy, Provision},
    },
    structures::{
        Digest, EccScheme, HashScheme, HmacScheme, KeyDerivationFunctionScheme, KeyedHashScheme,
        Public, PublicBuilder, PublicEccParameters, PublicKeyedHashParameters,
        SymmetricDefinitionObject,
    },
    traits::{Marshall, UnMarshall},
    Context,
};

use crate::errors::Error;

/// Generate a spec-compliant ECC signing key under the Endorsement hierarchy.
///
/// Key attributes: fixedTPM, fixedParent, sensitiveDataOrigin, signEncrypt.
/// If `auth_policy` is Some, sets userWithAuth=false and uses the policy digest
/// (spec-compliant: PolicyNV + PolicySecret). Otherwise uses userWithAuth=true.
///
/// Returns (transient KeyHandle, marshalled Public bytes).
pub fn generate_spec_ec_key(
    ctx: &mut Context,
    curve: EccCurve,
    hash_alg: HashingAlgorithm,
    unique_string: &[u8],
    auth_policy: Option<&Digest>,
) -> Result<(KeyHandle, Vec<u8>), Error> {
    let coord_size = unique_string.len() / 2;
    let x_bytes = &unique_string[..coord_size];
    let y_bytes = &unique_string[coord_size..];

    let use_policy = auth_policy.is_some();
    let obj_attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_sign_encrypt(true)
        .with_user_with_auth(!use_policy) // false when policy is provided
        .build()?;

    let mut builder = PublicBuilder::new()
        .with_public_algorithm(tss_esapi::interface_types::algorithm::PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(obj_attrs)
        .with_ecc_parameters(PublicEccParameters::new(
            SymmetricDefinitionObject::Null,
            EccScheme::EcDsa(HashScheme::new(hash_alg)),
            curve,
            KeyDerivationFunctionScheme::Null,
        ))
        .with_ecc_unique_identifier(tss_esapi::structures::EccPoint::new(
            tss_esapi::structures::EccParameter::try_from(x_bytes)?,
            tss_esapi::structures::EccParameter::try_from(y_bytes)?,
        ));

    if let Some(policy) = auth_policy {
        builder = builder.with_auth_policy(policy.clone());
    }

    let template = builder.build()?;

    let result = ctx.execute_with_nullauth_session(|ctx| {
        ctx.create_primary(Hierarchy::Endorsement, template, None, None, None, None)
    })?;

    let public_bytes = result.out_public.marshall()?;
    Ok((result.key_handle, public_bytes))
}

/// Generate a spec-compliant HMAC key under the Endorsement hierarchy.
///
/// If `auth_policy` is Some, sets userWithAuth=false (spec-compliant).
///
/// Returns a transient KeyHandle.
pub fn generate_spec_hmac_key(
    ctx: &mut Context,
    unique_string: &[u8],
    auth_policy: Option<&Digest>,
) -> Result<KeyHandle, Error> {
    let use_policy = auth_policy.is_some();
    let obj_attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_sign_encrypt(true)
        .with_user_with_auth(!use_policy)
        .build()?;

    let mut builder = PublicBuilder::new()
        .with_public_algorithm(tss_esapi::interface_types::algorithm::PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(obj_attrs)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Hmac {
            hmac_scheme: HmacScheme::new(HashingAlgorithm::Sha256),
        }))
        .with_keyed_hash_unique_identifier(Digest::try_from(unique_string)?);

    if let Some(policy) = auth_policy {
        builder = builder.with_auth_policy(policy.clone());
    }

    let template = builder.build()?;

    let result = ctx.execute_with_nullauth_session(|ctx| {
        ctx.create_primary(Hierarchy::Endorsement, template, None, None, None, None)
    })?;

    Ok(result.key_handle)
}

/// Persist a transient key to a permanent handle via TPM2_EvictControl.
pub fn persist_key(
    ctx: &mut Context,
    transient_handle: KeyHandle,
    persistent_handle: u32,
) -> Result<(), Error> {
    let persistent = PersistentTpmHandle::new(persistent_handle)?;
    ctx.execute_with_nullauth_session(|ctx| {
        ctx.evict_control(Provision::Owner, transient_handle.into(), persistent.into())
    })?;
    let _ = ctx.flush_context(transient_handle.into());
    Ok(())
}

/// Check if a persistent handle exists in the TPM.
pub fn persistent_handle_exists(ctx: &mut Context, handle: u32) -> bool {
    let persistent = match PersistentTpmHandle::new(handle) {
        Ok(h) => h,
        Err(_) => return false,
    };
    ctx.execute_without_session(|ctx| ctx.tr_from_tpm_public(persistent.into()))
        .is_ok()
}

/// Evict (remove) a persistent handle. Ignores errors.
pub fn evict_persistent_handle(ctx: &mut Context, handle: u32) {
    let persistent = match PersistentTpmHandle::new(handle) {
        Ok(h) => h,
        Err(_) => return,
    };
    if let Ok(object_handle) =
        ctx.execute_without_session(|ctx| ctx.tr_from_tpm_public(persistent.into()))
    {
        let _ = ctx.execute_with_nullauth_session(|ctx| {
            ctx.evict_control(Provision::Owner, object_handle, persistent.into())
        });
    }
}

/// Read the public key from a persistent handle.
pub fn read_persistent_public(ctx: &mut Context, handle: u32) -> Result<Vec<u8>, Error> {
    let persistent = PersistentTpmHandle::new(handle)?;
    let object_handle: ObjectHandle =
        ctx.execute_without_session(|ctx| ctx.tr_from_tpm_public(persistent.into()))?;
    let (public, _, _) =
        ctx.execute_without_session(|ctx| ctx.read_public(object_handle.into()))?;
    public.marshall().map_err(Error::from)
}

/// Load a persistent signing key and return it as a KeyHandle.
pub fn load_persistent_signing_key(ctx: &mut Context, handle: u32) -> Result<KeyHandle, Error> {
    let persistent = PersistentTpmHandle::new(handle)?;
    let object_handle: ObjectHandle =
        ctx.execute_without_session(|ctx| ctx.tr_from_tpm_public(persistent.into()))?;
    Ok(object_handle.into())
}

/// Sign a digest using a persistent key handle with policy session authorization.
///
/// If `us_nv_handle` is Some, uses PolicyNV+PolicySecret session (spec-compliant).
/// Otherwise falls back to null auth (password).
pub fn sign_with_persistent_key(
    ctx: &mut Context,
    key_handle: KeyHandle,
    digest: &[u8],
    us_nv_handle: Option<NvIndexHandle>,
) -> Result<tss_esapi::structures::Signature, Error> {
    let tpm_digest = Digest::try_from(digest)?;
    let validation: tss_esapi::structures::HashcheckTicket =
        tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
            tag: tss_esapi::constants::tss::TPM2_ST_HASHCHECK,
            hierarchy: tss_esapi::constants::tss::TPM2_RH_NULL,
            digest: Default::default(),
        }
        .try_into()?;

    if let Some(us_handle) = us_nv_handle {
        // Use policy session
        let (_, auth_session) = super::policy::create_fdo_key_policy_session(ctx, us_handle)?;
        ctx.execute_with_session(Some(auth_session), |ctx| {
            ctx.sign(
                key_handle,
                tpm_digest,
                tss_esapi::structures::SignatureScheme::Null,
                validation,
            )
        })
        .map_err(Error::from)
    } else {
        ctx.execute_with_nullauth_session(|ctx| {
            ctx.sign(
                key_handle,
                tpm_digest,
                tss_esapi::structures::SignatureScheme::Null,
                validation,
            )
        })
        .map_err(Error::from)
    }
}

/// Compute HMAC using a persistent HMAC key handle with policy session authorization.
///
/// If `us_nv_handle` is Some, uses PolicyNV+PolicySecret session (spec-compliant).
pub fn hmac_with_persistent_key(
    ctx: &mut Context,
    key_handle: KeyHandle,
    data: &[u8],
    us_nv_handle: Option<NvIndexHandle>,
) -> Result<Vec<u8>, Error> {
    let buffer = tss_esapi::structures::MaxBuffer::try_from(data)?;

    if let Some(us_handle) = us_nv_handle {
        let (_, auth_session) = super::policy::create_fdo_key_policy_session(ctx, us_handle)?;
        let result = ctx.execute_with_session(Some(auth_session), |ctx| {
            ctx.hmac(key_handle.into(), buffer, HashingAlgorithm::Sha256)
        })?;
        Ok(result.to_vec())
    } else {
        let result = ctx.execute_with_nullauth_session(|ctx| {
            ctx.hmac(key_handle.into(), buffer, HashingAlgorithm::Sha256)
        })?;
        Ok(result.to_vec())
    }
}

/// Extract the public key from TPM Public structure as DER bytes.
pub fn public_key_to_der(public_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    use openssl::{bn::BigNum, ec::EcGroup, ec::EcKey, nid::Nid, pkey::PKey};

    let public = Public::unmarshall(public_bytes)?;
    match public {
        Public::Ecc {
            parameters, unique, ..
        } => {
            let curve_nid = match parameters.ecc_curve() {
                EccCurve::NistP256 => Nid::X9_62_PRIME256V1,
                EccCurve::NistP384 => Nid::SECP384R1,
                _ => return Err(Error::UnsupportedAlgorithm),
            };
            let group = EcGroup::from_curve_name(curve_nid)?;
            let x = BigNum::from_slice(unique.x())?;
            let y = BigNum::from_slice(unique.y())?;
            let ec_key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)?;
            let pkey = PKey::from_ec_key(ec_key)?;
            pkey.public_key_to_der().map_err(Error::from)
        }
        _ => Err(Error::UnsupportedAlgorithm),
    }
}
