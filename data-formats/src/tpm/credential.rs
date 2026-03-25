// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause

//! TPM-backed DeviceCredential that reads from NV indices.
//!
//! This implements the DeviceCredential trait by loading credentials from
//! TPM NV indices (DCActive, DCTPM, DCOV) and using persistent key handles
//! (DAK, HMAC key) with PolicyNV+PolicySecret sessions for signing and HMAC.

use crate::{
    constants::HashType,
    devicecredential::DeviceCredential,
    errors::Error,
    tpm::{self, nv, policy},
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

impl TpmDeviceCredential {
    /// Load a DeviceCredential from TPM NV indices.
    /// Returns None if the TPM has no FDO credentials provisioned.
    pub fn load_from_nv() -> Result<Option<Self>, Error> {
        let mut ctx = tpm::open_context()?;
        let info = nv::read_nv_credentials(&mut ctx)?;

        if !info.active {
            return Ok(None);
        }
        if !info.has_dak || !info.has_hmac_key {
            return Ok(None);
        }
        if !info.has_dcov || info.dcov_data.is_empty() {
            return Ok(None);
        }

        // Decode DCOV CBOR: array [version, rvinfo, pubkeyhash, keytype]
        let dcov: serde_cbor::Value =
            serde_cbor::from_slice(&info.dcov_data).map_err(|e| Error::SerdeCborError(e))?;

        let (protver, rvinfo, pubkey_hash) = match dcov {
            serde_cbor::Value::Array(ref arr) if arr.len() >= 3 => {
                let version = match &arr[0] {
                    serde_cbor::Value::Integer(v) => *v as u16,
                    _ => return Err(Error::InconsistentValue("DCOV version")),
                };
                let protver = match version {
                    200 => ProtocolVersion::Version2_0,
                    101 | 100 => ProtocolVersion::Version1_0,
                    110 => ProtocolVersion::Version1_1,
                    _ => return Err(Error::InconsistentValue("DCOV version value")),
                };

                // RvInfo: CBOR bytes that we deserialize
                let rvinfo = match &arr[1] {
                    serde_cbor::Value::Bytes(b) => RendezvousInfo::deserialize_data(b)?,
                    // Could also be an inline CBOR array
                    other => {
                        let rv_bytes =
                            serde_cbor::to_vec(other).map_err(|e| Error::SerdeCborError(e))?;
                        RendezvousInfo::deserialize_data(&rv_bytes)?
                    }
                };

                // PubKeyHash
                let pubkey_hash = match &arr[2] {
                    serde_cbor::Value::Bytes(b) => Hash::deserialize_data(b)?,
                    other => {
                        let h_bytes =
                            serde_cbor::to_vec(other).map_err(|e| Error::SerdeCborError(e))?;
                        Hash::deserialize_data(&h_bytes)?
                    }
                };

                (protver, rvinfo, pubkey_hash)
            }
            _ => return Err(Error::InconsistentValue("DCOV format")),
        };

        // Reconstruct GUID from raw bytes
        let guid_bytes = info.guid.to_vec();
        let guid = Guid::deserialize_data(
            &serde_cbor::to_vec(&serde_cbor::Value::Bytes(guid_bytes))
                .map_err(|e| Error::SerdeCborError(e))?,
        )?;

        Ok(Some(TpmDeviceCredential {
            active: info.active,
            protver,
            device_info: info.device_info,
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
        // Compute HMAC using persistent HMAC key with policy session
        let computed = policy::hmac_with_policy(tpm::HMAC_US_INDEX, tpm::HMAC_KEY_HANDLE, data)?;
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
        // Return a signer that uses the persistent DAK with policy session
        Ok(Box::new(TpmPolicySigner))
    }
}

/// A COSE signer that uses the persistent DAK with PolicyNV+PolicySecret.
struct TpmPolicySigner;

impl std::fmt::Debug for TpmPolicySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TpmPolicySigner(DAK@0x{:08X})", tpm::DAK_HANDLE)
    }
}

impl aws_nitro_enclaves_cose::crypto::SigningPublicKey for TpmPolicySigner {
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

impl aws_nitro_enclaves_cose::crypto::SigningPrivateKey for TpmPolicySigner {
    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, CoseError> {
        let (r, s) = policy::sign_with_policy(tpm::DEVICE_KEY_US_INDEX, tpm::DAK_HANDLE, digest)
            .map_err(|e| CoseError::UnsupportedError(format!("TPM sign: {e}")))?;

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
}
