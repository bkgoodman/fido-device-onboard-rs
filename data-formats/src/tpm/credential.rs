// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause

//! TPM-backed DeviceCredential that reads from NV indices.
//!
//! This implements the DeviceCredential trait by loading credentials from
//! TPM NV indices (DCTPM, DCOV) and using persistent key handles
//! (DAK, HMAC key) with empty authValue for signing and HMAC.
//! Per spec Table 11, keys have userWithAuth=1, so no PolicyNV session
//! is needed — simple null-auth (empty password) is sufficient.

use crate::{
    constants::HashType,
    devicecredential::DeviceCredential,
    errors::Error,
    tpm::{self, key, nv},
    types::{Guid, HMac, Hash, RendezvousInfo},
    ProtocolVersion, Serializable,
};

use aws_nitro_enclaves_cose::{
    crypto::MessageDigest, crypto::SignatureAlgorithm, error::CoseError,
};
use tss_esapi::traits::UnMarshall;

/// A DeviceCredential backed by TPM NV indices and persistent keys.
#[derive(Debug)]
pub struct TpmDeviceCredential {
    pub active: bool,
    pub protver: ProtocolVersion,
    pub device_info: String,
    pub guid: Guid,
    pub rvinfo: RendezvousInfo,
    pub pubkey_hash: Hash,
}

/// DCTPM Magic value per spec.
const DCTPM_MAGIC: u32 = 0x46444F31; // "FDO1"

impl TpmDeviceCredential {
    /// Load a DeviceCredential from the consolidated DCTPM NV index.
    ///
    /// The DCTPM NV contains a CBOR array:
    ///   [Magic, Active, Version, DeviceInfo, GUID, RvInfo, PubKeyHash,
    ///    KeyType, DeviceKeyHandle, HMACKeyHandle]
    ///
    /// Returns None if the TPM has no FDO credentials provisioned.
    pub fn load_from_nv() -> Result<Option<Self>, Error> {
        let mut ctx = tpm::open_context()?;
        let info = nv::read_nv_credentials(&mut ctx)?;

        if !info.has_dctpm || info.raw_dctpm.is_empty() {
            log::debug!("No consolidated DCTPM NV found");
            return Ok(None);
        }
        if info.magic != DCTPM_MAGIC {
            log::warn!(
                "DCTPM magic mismatch: got 0x{:08X}, want 0x{:08X}",
                info.magic,
                DCTPM_MAGIC
            );
            return Ok(None);
        }
        if !info.active {
            log::debug!("DCTPM Active=false, skipping");
            return Ok(None);
        }
        if !info.has_dak || !info.has_hmac_key {
            log::debug!("Missing DAK or HMAC key persistent handles");
            return Ok(None);
        }

        // Decode consolidated DCTPM CBOR array:
        //   [0]=Magic, [1]=Active, [2]=Version, [3]=DeviceInfo, [4]=GUID,
        //   [5]=RvInfo, [6]=PubKeyHash, [7]=KeyType, [8]=DAKHandle, [9]=HMACHandle
        let dctpm: serde_cbor::Value =
            serde_cbor::from_slice(&info.raw_dctpm).map_err(Error::SerdeCborError)?;

        let arr = match &dctpm {
            serde_cbor::Value::Array(arr) if arr.len() >= 8 => arr,
            _ => return Err(Error::InconsistentValue("DCTPM: not a CBOR array or too short")),
        };

        // [2] Version
        let version = match &arr[2] {
            serde_cbor::Value::Integer(v) => *v as u16,
            _ => return Err(Error::InconsistentValue("DCTPM[2] version")),
        };
        let protver = match version {
            200 => ProtocolVersion::Version2_0,
            110 => ProtocolVersion::Version1_1,
            100 | 101 => ProtocolVersion::Version1_0,
            _ => return Err(Error::InconsistentValue("DCTPM version value")),
        };

        // [3] DeviceInfo
        let device_info = match &arr[3] {
            serde_cbor::Value::Text(s) => s.clone(),
            _ => return Err(Error::InconsistentValue("DCTPM[3] device_info")),
        };

        // [4] GUID (raw 16 bytes)
        let guid = match &arr[4] {
            serde_cbor::Value::Bytes(b) => {
                // Wrap raw bytes as CBOR bstr for Guid::deserialize_data
                let cbor_bstr =
                    serde_cbor::to_vec(&serde_cbor::Value::Bytes(b.clone()))
                        .map_err(Error::SerdeCborError)?;
                Guid::deserialize_data(&cbor_bstr)?
            }
            _ => return Err(Error::InconsistentValue("DCTPM[4] guid")),
        };

        // [5] RvInfo
        let rvinfo = match &arr[5] {
            serde_cbor::Value::Bytes(b) => RendezvousInfo::deserialize_data(b)?,
            other => {
                let rv_bytes = serde_cbor::to_vec(other).map_err(Error::SerdeCborError)?;
                RendezvousInfo::deserialize_data(&rv_bytes)?
            }
        };

        // [6] PubKeyHash
        let pubkey_hash = match &arr[6] {
            serde_cbor::Value::Bytes(b) => Hash::deserialize_data(b)?,
            other => {
                let h_bytes = serde_cbor::to_vec(other).map_err(Error::SerdeCborError)?;
                Hash::deserialize_data(&h_bytes)?
            }
        };

        log::info!(
            "Loaded DCTPM: version={}, device_info={}, guid loaded, active=true",
            version,
            device_info
        );

        Ok(Some(TpmDeviceCredential {
            active: true,
            protver,
            device_info,
            guid,
            rvinfo,
            pubkey_hash,
        }))
    }
}

impl DeviceCredential for TpmDeviceCredential {
    fn is_active(&self) -> bool {
        self.active
    }

    fn protocol_version(&self) -> ProtocolVersion {
        self.protver
    }

    fn device_info(&self) -> &str {
        &self.device_info
    }

    fn device_guid(&self) -> &Guid {
        &self.guid
    }

    fn rendezvous_info(&self) -> &RendezvousInfo {
        &self.rvinfo
    }

    fn manufacturer_pubkey_hash(&self) -> &Hash {
        &self.pubkey_hash
    }

    fn verify_hmac(&self, data: &[u8], hmac: &HMac) -> Result<(), Error> {
        // Compute HMAC using persistent HMAC key with empty authValue (null auth)
        let mut ctx = tpm::open_context()?;
        let hmac_handle = key::load_persistent_signing_key(&mut ctx, tpm::HMAC_KEY_HANDLE)?;
        let computed = key::hmac_with_persistent_key(&mut ctx, hmac_handle, data)?;
        let computed_hmac = HMac::from_digest(HashType::HmacSha256, computed)?;
        if hmac != &computed_hmac {
            Err(Error::IncorrectHash)
        } else {
            Ok(())
        }
    }

    fn get_signer(
        &self,
    ) -> Result<Box<dyn aws_nitro_enclaves_cose::crypto::SigningPrivateKey>, Error> {
        // Return a signer that uses the persistent DAK with empty authValue
        Ok(Box::new(TpmNullAuthSigner))
    }
}

/// A COSE signer that uses the persistent DAK with empty authValue (null auth).
/// Per spec Table 11, keys have userWithAuth=1, so no policy session is needed.
struct TpmNullAuthSigner;

impl std::fmt::Debug for TpmNullAuthSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TpmNullAuthSigner(DAK@0x{:08X})", tpm::DAK_HANDLE)
    }
}

impl aws_nitro_enclaves_cose::crypto::SigningPublicKey for TpmNullAuthSigner {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        // Read the DAK public to determine parameters
        let mut ctx = tpm::open_context()
            .map_err(|e| CoseError::UnsupportedError(format!("TPM context: {e}")))?;
        let public_bytes = tpm::key::read_persistent_public(&mut ctx, tpm::DAK_HANDLE)
            .map_err(|e| CoseError::UnsupportedError(format!("read DAK public: {e}")))?;
        let public = tss_esapi::structures::Public::unmarshall(&public_bytes)
            .map_err(|e| CoseError::UnsupportedError(format!("unmarshall: {e}")))?;

        match public {
            tss_esapi::structures::Public::Ecc { parameters, .. } => match parameters.ecc_curve() {
                tss_esapi::interface_types::ecc::EccCurve::NistP256 => {
                    Ok((SignatureAlgorithm::ES256, MessageDigest::Sha256))
                }
                tss_esapi::interface_types::ecc::EccCurve::NistP384 => {
                    Ok((SignatureAlgorithm::ES384, MessageDigest::Sha384))
                }
                _ => Err(CoseError::UnsupportedError("unsupported curve".into())),
            },
            _ => Err(CoseError::UnsupportedError("not ECC".into())),
        }
    }

    fn verify(&self, _digest: &[u8], _signature: &[u8]) -> Result<bool, CoseError> {
        unimplemented!("verify not needed for device credential")
    }
}

impl aws_nitro_enclaves_cose::crypto::SigningPrivateKey for TpmNullAuthSigner {
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError> {
        let mut ctx = tpm::open_context()
            .map_err(|e| CoseError::UnsupportedError(format!("TPM context: {e}")))?;
        let dak_handle = key::load_persistent_signing_key(&mut ctx, tpm::DAK_HANDLE)
            .map_err(|e| CoseError::UnsupportedError(format!("load DAK: {e}")))?;
        let signature = key::sign_with_persistent_key(&mut ctx, dak_handle, digest)
            .map_err(|e| CoseError::UnsupportedError(format!("TPM sign: {e}")))?;

        // Extract (r, s) from the EcDsa signature
        match signature {
            tss_esapi::structures::Signature::EcDsa(ecdsa_sig) => {
                let r = ecdsa_sig.signature_r().to_vec();
                let s = ecdsa_sig.signature_s().to_vec();

                // Determine key length from r coordinate size (P-256 = 32, P-384 = 48)
                let key_length = if r.len() <= 32 { 32 } else { 48 };

                // Convert (r, s) to concatenated COSE signature format
                let mut sig = vec![0u8; key_length * 2];
                let r_offset = key_length - r.len();
                sig[r_offset..r_offset + r.len()].copy_from_slice(&r);
                let s_offset = key_length - s.len() + key_length;
                sig[s_offset..s_offset + s.len()].copy_from_slice(&s);
                Ok(sig)
            }
            _ => Err(CoseError::UnsupportedError("not ECDSA signature".into())),
        }
    }
}
