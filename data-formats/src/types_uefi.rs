// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause
//
// UEFI-compatible FDO types (no_std, no openssl)
// These are the core types needed for TO1/TO2 protocol messages.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_repr::{Deserialize_repr, Serialize_repr};
use serde_tuple::{Deserialize_tuple, Serialize_tuple};

use crate::constants_uefi::HashType;

// ============================================================
// Guid - Device identifier (128-bit UUID)
// ============================================================
#[derive(Clone, PartialEq, Eq)]
pub struct Guid([u8; 16]);

impl Guid {
    pub fn new(bytes: [u8; 16]) -> Self {
        Guid(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl core::fmt::Debug for Guid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Format as UUID string
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3],
            self.0[4], self.0[5],
            self.0[6], self.0[7],
            self.0[8], self.0[9],
            self.0[10], self.0[11], self.0[12], self.0[13], self.0[14], self.0[15]
        )
    }
}

impl Serialize for Guid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Guid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: ByteBuf = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 16 {
            return Err(serde::de::Error::custom("Guid must be 16 bytes"));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(Guid(arr))
    }
}

// ============================================================
// Nonce - Random challenge value
// ============================================================
#[derive(Clone, PartialEq, Eq)]
pub struct Nonce(Vec<u8>);

impl Nonce {
    pub fn new(bytes: Vec<u8>) -> Self {
        Nonce(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for Nonce {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Nonce({} bytes)", self.0.len())
    }
}

impl Serialize for Nonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: ByteBuf = Deserialize::deserialize(deserializer)?;
        Ok(Nonce(bytes.into_vec()))
    }
}

// ============================================================
// Hash - Cryptographic hash value
// ============================================================
#[derive(Clone, Serialize_tuple, Deserialize_tuple)]
pub struct Hash {
    pub hash_type: HashType,
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

impl Hash {
    pub fn new(hash_type: HashType, value: Vec<u8>) -> Self {
        Hash { hash_type, value }
    }

    pub fn get_type(&self) -> HashType {
        self.hash_type
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl core::fmt::Debug for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Hash")
            .field("hash_type", &self.hash_type)
            .field("value_len", &self.value.len())
            .finish()
    }
}

// ============================================================
// SigInfo - Signature algorithm info
// ============================================================
#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct SigInfo {
    pub sig_type: i8,
    #[serde(with = "serde_bytes")]
    pub info: Vec<u8>,
}

impl SigInfo {
    pub fn new(sig_type: i8, info: Vec<u8>) -> Self {
        SigInfo { sig_type, info }
    }
}

// ============================================================
// CapabilityFlags - FDO 2.0 version negotiation
// ============================================================
#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct CapabilityFlags {
    #[serde(with = "serde_bytes")]
    pub flags: Vec<u8>,
    pub vendor_unique: Option<Vec<String>>,
}

impl CapabilityFlags {
    pub fn new_v20() -> Self {
        // FDO 2.0 capability flags: bit 1 set (0x02)
        CapabilityFlags {
            flags: vec![0x02],
            vendor_unique: None,
        }
    }

    pub fn from_flags(flags: Vec<u8>) -> Self {
        CapabilityFlags {
            flags,
            vendor_unique: None,
        }
    }
}

// ============================================================
// KexSuite - Key exchange suite
// ============================================================
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(i8)]
pub enum KexSuite {
    Ecdh256 = 1,
    Ecdh384 = 2,
    Asymkex2048 = 3,
    Asymkex3072 = 4,
}

// ============================================================
// CipherSuite - Encryption cipher suite
// ============================================================
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(i8)]
pub enum CipherSuite {
    A128Gcm = 1,
    A256Gcm = 2,
    Aes128Cbc = 3,
    Aes256Cbc = 4,
    AesCcm64_128_128 = 32,
    AesCcm64_128_256 = 33,
}

// ============================================================
// COSESign - COSE_Sign1 wrapper (opaque bytes for UEFI)
// ============================================================
#[derive(Debug, Clone)]
pub struct COSESign(pub Vec<u8>);

impl COSESign {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        COSESign(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for COSESign {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // COSE_Sign1 is a tagged CBOR structure - serialize as raw bytes
        serde_bytes::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for COSESign {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: ByteBuf = Deserialize::deserialize(deserializer)?;
        Ok(COSESign(bytes.into_vec()))
    }
}

// ============================================================
// HMac - HMAC value
// ============================================================
#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct HMac {
    pub hash_type: HashType,
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

impl HMac {
    pub fn new(hash_type: HashType, value: Vec<u8>) -> Self {
        HMac { hash_type, value }
    }
}

// ============================================================
// ServiceInfo - Key-value pairs for service info exchange
// ============================================================
#[derive(Debug, Clone, Default)]
pub struct ServiceInfo(pub Vec<(String, Vec<u8>)>);

impl ServiceInfo {
    pub fn new() -> Self {
        ServiceInfo(Vec::new())
    }

    pub fn add(&mut self, key: String, value: Vec<u8>) {
        self.0.push((key, value));
    }
}

impl Serialize for ServiceInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            seq.serialize_element(&(k, serde_bytes::Bytes::new(v)))?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for ServiceInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let items: Vec<(String, ByteBuf)> = Deserialize::deserialize(deserializer)?;
        Ok(ServiceInfo(
            items.into_iter().map(|(k, v)| (k, v.into_vec())).collect(),
        ))
    }
}

// ============================================================
// RendezvousInfo - Rendezvous server information
// ============================================================
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RendezvousInfo(pub Vec<Vec<RendezvousDirective>>);

#[derive(Debug, Clone, Serialize_tuple, Deserialize_tuple)]
pub struct RendezvousDirective {
    pub key: u8,
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

impl RendezvousInfo {
    pub fn new() -> Self {
        RendezvousInfo(Vec::new())
    }
}
