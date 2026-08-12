// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause
//
// UEFI-compatible FDO TO1/TO2 messages (no_std)

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};
use serde_tuple::{Deserialize_tuple, Serialize_tuple};

use crate::constants_uefi::MessageType;
use crate::types_uefi::{
    COSESign, CapabilityFlags, CipherSuite, Guid, HMac, Hash, KexSuite, Nonce,
    RendezvousInfo, ServiceInfo, SigInfo,
};

// ============================================================
// TO1 Messages (Types 30-33)
// ============================================================

/// TO1.HelloRV (Type 30) - Device initiates TO1
#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
pub struct TO1HelloRV {
    pub guid: Guid,
    pub a_signature_info: SigInfo,
    #[serde(with = "serde_bytes")]
    pub capability_flags: Vec<u8>,
}

impl TO1HelloRV {
    pub fn new(guid: Guid, sig_info: SigInfo, capability_flags: CapabilityFlags) -> Self {
        TO1HelloRV {
            guid,
            a_signature_info: sig_info,
            capability_flags: capability_flags.flags,
        }
    }

    pub fn message_type() -> MessageType {
        MessageType::TO1HelloRV
    }
}

/// TO1.HelloRVAck (Type 31) - Server acknowledges HelloRV
#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
pub struct TO1HelloRVAck {
    pub nonce4: Nonce,
    pub b_signature_info: SigInfo,
    #[serde(with = "serde_bytes")]
    pub capability_flags: Vec<u8>,
}

impl TO1HelloRVAck {
    pub fn message_type() -> MessageType {
        MessageType::TO1HelloRVAck
    }
}

/// TO1.ProveToRV (Type 32) - Device proves identity
#[derive(Debug)]
pub struct TO1ProveToRV(pub COSESign);

impl TO1ProveToRV {
    pub fn new(token: COSESign) -> Self {
        TO1ProveToRV(token)
    }

    pub fn message_type() -> MessageType {
        MessageType::TO1ProveToRV
    }
}

impl Serialize for TO1ProveToRV {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TO1ProveToRV {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(TO1ProveToRV(COSESign::deserialize(deserializer)?))
    }
}

/// TO1.RVRedirect (Type 33) - Server provides TO1d blob
#[derive(Debug)]
pub struct TO1RVRedirect(pub COSESign);

impl TO1RVRedirect {
    pub fn new(to1d: COSESign) -> Self {
        TO1RVRedirect(to1d)
    }

    pub fn into_to1d(self) -> COSESign {
        self.0
    }

    pub fn message_type() -> MessageType {
        MessageType::TO1RVRedirect
    }
}

impl Serialize for TO1RVRedirect {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TO1RVRedirect {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(TO1RVRedirect(COSESign::deserialize(deserializer)?))
    }
}

// ============================================================
// TO2 Messages (Types 80-91) - FDO 2.0 Device Proves First
// ============================================================

/// TO2.HelloDeviceProbe (Type 80) - Device initiates TO2
#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
pub struct TO2HelloDeviceProbe {
    pub capability_flags: CapabilityFlags,
    pub guid: Guid,
    pub max_device_message_size: u16,
    pub hash_types: Vec<i8>,
    #[serde(with = "serde_bytes")]
    pub sugar: Vec<u8>,
}

impl TO2HelloDeviceProbe {
    pub fn new(guid: Guid, capability_flags: CapabilityFlags, hash_types: Vec<i8>, sugar: Vec<u8>) -> Self {
        TO2HelloDeviceProbe {
            capability_flags,
            guid,
            max_device_message_size: u16::MAX,
            hash_types,
            sugar,
        }
    }

    pub fn message_type() -> MessageType {
        MessageType::TO2HelloDeviceProbe
    }
}

/// TO2.HelloDeviceAck20 (Type 81) - Owner acknowledges probe
#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
pub struct TO2HelloDeviceAck20 {
    pub capability_flags: CapabilityFlags,
    pub guid: Guid,
    pub max_owner_message_size: u16,
    pub kex_suites: Vec<KexSuite>,
    pub cipher_suites: Vec<CipherSuite>,
    pub nonce_to2_prove_dv_prep: Nonce,
    pub hash_prev: Hash,
}

impl TO2HelloDeviceAck20 {
    pub fn message_type() -> MessageType {
        MessageType::TO2HelloDeviceAck20
    }
}

/// TO2.ProveDevice20 (Type 82) - Device proves itself
#[derive(Debug)]
pub struct TO2ProveDevice20(pub COSESign);

impl TO2ProveDevice20 {
    pub fn new(token: COSESign) -> Self {
        TO2ProveDevice20(token)
    }

    pub fn message_type() -> MessageType {
        MessageType::TO2ProveDevice20
    }
}

impl Serialize for TO2ProveDevice20 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TO2ProveDevice20 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(TO2ProveDevice20(COSESign::deserialize(deserializer)?))
    }
}

/// TO2.ProveOVHdr20 (Type 83) - Owner proves OV header
#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
pub struct TO2ProveOVHdr20 {
    pub nonce_to2_prove_ov: Nonce,
    pub kex_suite_sel: KexSuite,
    pub cipher_suite_sel: CipherSuite,
    #[serde(with = "serde_bytes")]
    pub kex_a: Vec<u8>,
    pub num_ov_entries: u16,
    pub hmac: HMac,
    #[serde(with = "serde_bytes")]
    pub ov_header: Vec<u8>,
    pub delegate: Option<Vec<u8>>,
    pub cose_sign: COSESign,
}

impl TO2ProveOVHdr20 {
    pub fn message_type() -> MessageType {
        MessageType::TO2ProveOVHdr20
    }
}

/// TO2.GetOVNextEntry20 (Type 84) - Device requests OV entry
#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
pub struct TO2GetOVNextEntry20 {
    pub entry_num: u16,
}

impl TO2GetOVNextEntry20 {
    pub fn new(entry_num: u16) -> Self {
        TO2GetOVNextEntry20 { entry_num }
    }

    pub fn message_type() -> MessageType {
        MessageType::TO2GetOVNextEntry20
    }
}

/// TO2.OVNextEntry20 (Type 85) - Owner sends OV entry
#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
pub struct TO2OVNextEntry20 {
    pub entry_num: u16,
    #[serde(with = "serde_bytes")]
    pub ov_entry: Vec<u8>,
}

impl TO2OVNextEntry20 {
    pub fn message_type() -> MessageType {
        MessageType::TO2OVNextEntry20
    }
}

/// TO2.DeviceSvcInfoRdy20 (Type 86) - Device ready for service info
#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
pub struct TO2DeviceSvcInfoRdy20 {
    pub max_svc_info_sz: u16,
    pub hmac: HMac,
}

impl TO2DeviceSvcInfoRdy20 {
    pub fn new(max_svc_info_sz: u16, hmac: HMac) -> Self {
        TO2DeviceSvcInfoRdy20 { max_svc_info_sz, hmac }
    }

    pub fn message_type() -> MessageType {
        MessageType::TO2DeviceSvcInfoRdy20
    }
}

/// TO2.SetupDevice20 (Type 87) - Owner sets up device
#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
pub struct TO2SetupDevice20 {
    pub nonce_to2_setup_dv: Nonce,
    pub new_guid: Option<Guid>,
    pub rendezvous_info: RendezvousInfo,
}

impl TO2SetupDevice20 {
    pub fn message_type() -> MessageType {
        MessageType::TO2SetupDevice20
    }
}

/// TO2.DeviceSvcInfo20 (Type 88) - Device sends service info
#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
pub struct TO2DeviceSvcInfo20 {
    pub is_more: bool,
    pub service_info: ServiceInfo,
}

impl TO2DeviceSvcInfo20 {
    pub fn new(is_more: bool, service_info: ServiceInfo) -> Self {
        TO2DeviceSvcInfo20 { is_more, service_info }
    }

    pub fn message_type() -> MessageType {
        MessageType::TO2DeviceSvcInfo20
    }
}

/// TO2.OwnerSvcInfo20 (Type 89) - Owner sends service info
#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
pub struct TO2OwnerSvcInfo20 {
    pub is_more: bool,
    pub is_done: bool,
    pub service_info: ServiceInfo,
}

impl TO2OwnerSvcInfo20 {
    pub fn message_type() -> MessageType {
        MessageType::TO2OwnerSvcInfo20
    }
}

/// TO2.Done20 (Type 90) - Device signals completion
#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
pub struct TO2Done20 {
    pub nonce_to2_setup_dv: Nonce,
}

impl TO2Done20 {
    pub fn new(nonce: Nonce) -> Self {
        TO2Done20 { nonce_to2_setup_dv: nonce }
    }

    pub fn message_type() -> MessageType {
        MessageType::TO2Done20
    }
}

/// TO2.DoneAck20 (Type 91) - Owner acknowledges completion
#[derive(Debug, Serialize_tuple, Deserialize_tuple)]
pub struct TO2DoneAck20 {
    pub nonce_to2_prove_ov: Nonce,
}

impl TO2DoneAck20 {
    pub fn message_type() -> MessageType {
        MessageType::TO2DoneAck20
    }
}
