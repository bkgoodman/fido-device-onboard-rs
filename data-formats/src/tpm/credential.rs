// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause

//! TPM-backed DeviceCredential that reads from the consolidated DCTPM NV index.
//!
//! This implements the DeviceCredential trait by loading credentials from
//! the single DCTPM NV index (CBOR-encoded with magic header) and using
//! persistent key handles for signing and HMAC.

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
    pub dak_handle: u32,
    pub hmac_handle: u32,
}

impl TpmDeviceCredential {
    /// Load a DeviceCredential from the TPM DCTPM NV index.
    /// Returns None if the TPM has no FDO credentials provisioned.
    pub fn load_from_nv() -> Result<Option<Self>, Error> {
        let mut ctx = tpm::open_context()?;
        let info = nv::read_nv_credentials(&mut ctx)?;

        if !info.has_dctpm || info.raw_dctpm.is_empty() {
            return Ok(None);
        }

        // Decode DCTPM CBOR: integer-keyed map
        // Keys: 0=Magic, 1=Active, 2=Version, 3=DeviceInfo, 4=GUID,
        //       5=RvInfo, 6=PubKeyHash, 7=KeyType, 8=DAKHandle, 9=HMACHandle
        let dctpm: serde_cbor::Value =
            serde_cbor::from_slice(&info.raw_dctpm).map_err(Error::SerdeCborError)?;

        let map = match &dctpm {
            serde_cbor::Value::Map(m) => m,
            _ => return Err(Error::InconsistentValue("DCTPM not a CBOR map")),
        };

        // Helper to get a value by integer key
        let get = |key: i128| -> Option<&serde_cbor::Value> {
            map.iter()
                .find(|(k, _)| matches!(k, serde_cbor::Value::Integer(i) if *i == key))
                .map(|(_, v)| v)
        };

        // Verify magic (key 0)
        let magic = match get(0) {
            Some(serde_cbor::Value::Integer(v)) => *v as u32,
            _ => return Err(Error::InconsistentValue("DCTPM missing magic")),
        };
        if magic != tpm::DCTPM_MAGIC {
            return Err(Error::InconsistentValue("DCTPM magic mismatch"));
        }

        // Active flag (key 1)
        let active = match get(1) {
            Some(serde_cbor::Value::Bool(v)) => *v,
            _ => false,
        };
        if !active {
            return Ok(None);
        }

        // Version (key 2)
        let version = match get(2) {
            Some(serde_cbor::Value::Integer(v)) => *v as u16,
            _ => return Err(Error::InconsistentValue("DCTPM missing version")),
        };
        let protver = match version {
            200 => ProtocolVersion::Version2_0,
            101 | 100 => ProtocolVersion::Version1_0,
            110 => ProtocolVersion::Version1_1,
            _ => return Err(Error::InconsistentValue("DCTPM version value")),
        };

        // DeviceInfo (key 3)
        let device_info = match get(3) {
            Some(serde_cbor::Value::Text(s)) => s.clone(),
            _ => String::new(),
        };

        // GUID (key 4)
        let guid = match get(4) {
            Some(serde_cbor::Value::Bytes(b)) if b.len() == 16 => {
                let guid_bytes = b.to_vec();
                Guid::deserialize_data(
                    &serde_cbor::to_vec(&serde_cbor::Value::Bytes(guid_bytes))
                        .map_err(Error::SerdeCborError)?,
                )?
            }
            _ => return Err(Error::InconsistentValue("DCTPM missing/invalid GUID")),
        };

        // RvInfo (key 5)
        let rvinfo = match get(5) {
            Some(val) => {
                let rv_bytes = serde_cbor::to_vec(val).map_err(Error::SerdeCborError)?;
                RendezvousInfo::deserialize_data(&rv_bytes)?
            }
            None => RendezvousInfo::deserialize_data(&serde_cbor::to_vec(
                &serde_cbor::Value::Array(vec![]),
            ).map_err(Error::SerdeCborError)?)?,
        };

        // PubKeyHash (key 6)
        let pubkey_hash = match get(6) {
            Some(val) => {
                let h_bytes = serde_cbor::to_vec(val).map_err(Error::SerdeCborError)?;
                Hash::deserialize_data(&h_bytes)?
            }
            None => return Err(Error::InconsistentValue("DCTPM missing pubkey hash")),
        };

        // DAKHandle (key 8), HMACHandle (key 9)
        let dak_handle = match get(8) {
            Some(serde_cbor::Value::Integer(v)) => *v as u32,
            _ => tpm::DAK_HANDLE,
        };
        let hmac_handle = match get(9) {
            Some(serde_cbor::Value::Integer(v)) => *v as u32,
            _ => tpm::HMAC_KEY_HANDLE,
        };

        Ok(Some(TpmDeviceCredential {
            active,
            protver,
            device_info,
            guid,
            rvinfo,
            pubkey_hash,
            dak_handle,
            hmac_handle,
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
        let computed =
            policy::hmac_with_policy(tpm::HMAC_US_INDEX, self.hmac_handle, data)?;
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
        Ok(Box::new(TpmPolicySigner {
            dak_handle: self.dak_handle,
        }))
    }
}

/// A COSE signer that uses the persistent DAK with PolicyNV+PolicySecret.
struct TpmPolicySigner {
    dak_handle: u32,
}

impl std::fmt::Debug for TpmPolicySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TpmPolicySigner(DAK@0x{:08X})", self.dak_handle)
    }
}

impl aws_nitro_enclaves_cose::crypto::SigningPublicKey for TpmPolicySigner {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        // Read the DAK public to determine parameters
        let mut ctx = tpm::open_context()
            .map_err(|e| CoseError::UnsupportedError(format!("TPM context: {e}")))?;
        let public_bytes = tpm::key::read_persistent_public(&mut ctx, self.dak_handle)
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
        let (r, s) =
            policy::sign_with_policy(tpm::DEVICE_KEY_US_INDEX, self.dak_handle, digest)
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
