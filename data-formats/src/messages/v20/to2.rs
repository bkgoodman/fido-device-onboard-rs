// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause

// FDO 2.0 Transfer Ownership 2 (TO2) Protocol Messages
//
// Key difference from FDO 1.1: Device proves itself FIRST (anti-DoS).
//
// Flow: HelloDeviceProbe(80) -> HelloDeviceAck20(81) -> ProveDevice20(82) ->
//       ProveOVHdr20(83) -> GetOVNextEntry20(84) -> OVNextEntry20(85) ->
//       DeviceSvcInfoRdy20(86) -> SetupDevice20(87) -> DeviceSvcInfo20(88) ->
//       OwnerSvcInfo20(89) -> Done20(90) -> DoneAck20(91)

use serde::Deserialize;
use serde_tuple::Serialize_tuple;

use crate::simple_message_serializable;
use crate::{
    constants::MessageType,
    messages::{ClientMessage, EncryptionRequirement, Message, ServerMessage},
    ownershipvoucher::OwnershipVoucherEntry,
    types::{
        COSESign, CapabilityFlags, CipherSuite, Guid, HMac, Hash, KexSuite, Nonce, RendezvousInfo,
        ServiceInfo,
    },
};

pub(crate) const MAX_MESSAGE_SIZE: u16 = u16::MAX;

// ============================================================
// Type 80: TO2.HelloDeviceProbe (Device -> Owner)
// ============================================================
#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct HelloDeviceProbe {
    capability_flags: CapabilityFlags,
    guid: Guid,
    max_device_message_size: u16,
    hash_types: Vec<i8>, // HashType values (Sha256=-16, Sha384=-43)
    #[serde(with = "serde_bytes")]
    sugar: Vec<u8>, // 16 bytes random entropy
}

impl HelloDeviceProbe {
    pub fn new(
        guid: Guid,
        capability_flags: CapabilityFlags,
        hash_types: Vec<i8>,
        sugar: Vec<u8>,
    ) -> Self {
        HelloDeviceProbe {
            capability_flags,
            guid,
            max_device_message_size: MAX_MESSAGE_SIZE,
            hash_types,
            sugar,
        }
    }

    pub fn guid(&self) -> &Guid {
        &self.guid
    }

    pub fn capability_flags(&self) -> &CapabilityFlags {
        &self.capability_flags
    }
}

impl Message for HelloDeviceProbe {
    fn message_type() -> MessageType {
        MessageType::TO2HelloDeviceProbe
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        message_type.is_none()
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version2_0
    }
}

impl ClientMessage for HelloDeviceProbe {}

// ============================================================
// Type 81: TO2.HelloDeviceAck20 (Owner -> Device)
// ============================================================
#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct HelloDeviceAck20 {
    capability_flags: CapabilityFlags,
    guid: Guid,
    max_owner_message_size: u16,
    kex_suites: Vec<KexSuite>,
    cipher_suites: Vec<CipherSuite>,
    nonce_to2_prove_dv_prep: Nonce,
    hash_prev: Hash, // Hash of HelloDeviceProbe
}

impl HelloDeviceAck20 {
    pub fn capability_flags(&self) -> &CapabilityFlags {
        &self.capability_flags
    }

    pub fn guid(&self) -> &Guid {
        &self.guid
    }

    pub fn max_owner_message_size(&self) -> u16 {
        self.max_owner_message_size
    }

    pub fn kex_suites(&self) -> &[KexSuite] {
        &self.kex_suites
    }

    pub fn cipher_suites(&self) -> &[CipherSuite] {
        &self.cipher_suites
    }

    pub fn nonce_to2_prove_dv_prep(&self) -> &Nonce {
        &self.nonce_to2_prove_dv_prep
    }

    pub fn hash_prev(&self) -> &Hash {
        &self.hash_prev
    }
}

impl Message for HelloDeviceAck20 {
    fn message_type() -> MessageType {
        MessageType::TO2HelloDeviceAck20
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::TO2HelloDeviceProbe))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version2_0
    }
}

impl ServerMessage for HelloDeviceAck20 {}

// ============================================================
// Type 82: TO2.ProveDevice20 (Device -> Owner)
// This is a COSE_Sign1 wrapper. The payload (ProveDevice20Payload)
// is the EAT token signed by the device key.
// KEY DIFFERENCE: Device proves FIRST in FDO 2.0 (anti-DoS).
// ============================================================
#[derive(Debug)]
pub struct ProveDevice20(COSESign);

simple_message_serializable!(ProveDevice20, COSESign);

impl ProveDevice20 {
    pub fn new(token: COSESign) -> Self {
        ProveDevice20(token)
    }

    pub fn token(&self) -> &COSESign {
        &self.0
    }

    pub fn into_token(self) -> COSESign {
        self.0
    }
}

impl Message for ProveDevice20 {
    fn message_type() -> MessageType {
        MessageType::TO2ProveDevice20
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::TO2HelloDeviceAck20))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version2_0
    }
}

impl ClientMessage for ProveDevice20 {}

// ============================================================
// Type 83: TO2.ProveOVHdr20 (Owner -> Device)
// COSE_Sign1 wrapper. Owner proves ownership AFTER device verified.
// ============================================================
#[derive(Debug)]
pub struct ProveOVHdr20(COSESign);

simple_message_serializable!(ProveOVHdr20, COSESign);

impl ProveOVHdr20 {
    pub fn new(token: COSESign) -> Self {
        ProveOVHdr20(token)
    }

    pub fn token(&self) -> &COSESign {
        &self.0
    }

    pub fn into_token(self) -> COSESign {
        self.0
    }
}

impl Message for ProveOVHdr20 {
    fn message_type() -> MessageType {
        MessageType::TO2ProveOVHdr20
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::TO2ProveDevice20))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version2_0
    }
}

impl ServerMessage for ProveOVHdr20 {}

// ============================================================
// Type 84: TO2.GetOVNextEntry20 (Device -> Owner)
// ============================================================
#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct GetOVNextEntry20 {
    entry_num: u8,
}

impl GetOVNextEntry20 {
    pub fn new(entry_num: u8) -> Self {
        GetOVNextEntry20 { entry_num }
    }

    pub fn entry_num(&self) -> u8 {
        self.entry_num
    }
}

impl Message for GetOVNextEntry20 {
    fn message_type() -> MessageType {
        MessageType::TO2GetOVNextEntry20
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(
            message_type,
            Some(MessageType::TO2ProveOVHdr20) | Some(MessageType::TO2OVNextEntry20)
        )
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version2_0
    }
}

impl ClientMessage for GetOVNextEntry20 {}

// ============================================================
// Type 85: TO2.OVNextEntry20 (Owner -> Device)
// ============================================================
#[derive(Debug)]
pub struct OVNextEntry20 {
    entry_num: u8,
    entry: OwnershipVoucherEntry,
}

impl crate::Serializable for OVNextEntry20 {
    fn serialize_to_writer<W>(&self, writer: W) -> Result<(), crate::Error>
    where
        W: std::io::Write,
    {
        use crate::cborparser::{ParsedArrayBuilder, ParsedArraySize2};
        let entry_bytes = self.entry.serialize_data()?;
        let mut contents: ParsedArrayBuilder<ParsedArraySize2> = ParsedArrayBuilder::new();
        contents.set(0, &self.entry_num)?;
        contents.set(1, &serde_bytes::ByteBuf::from(entry_bytes))?;
        contents.build().serialize_to_writer(writer)
    }

    fn deserialize_from_reader<R>(reader: R) -> Result<Self, crate::Error>
    where
        R: std::io::Read,
    {
        // Go sends [entry_num, bstr(COSE_Sign1_bytes)]
        // The entry is a byte string wrapping the COSE-encoded voucher entry
        let (entry_num, entry_bytes): (u8, serde_bytes::ByteBuf) =
            ciborium::de::from_reader(reader)?;
        let entry = OwnershipVoucherEntry::deserialize_data(&entry_bytes)?;
        Ok(OVNextEntry20 { entry_num, entry })
    }
}

impl OVNextEntry20 {
    pub fn new(entry_num: u8, entry: OwnershipVoucherEntry) -> Self {
        OVNextEntry20 { entry_num, entry }
    }

    pub fn entry_num(&self) -> u8 {
        self.entry_num
    }

    pub fn entry(&self) -> &OwnershipVoucherEntry {
        &self.entry
    }

    pub fn into_entry(self) -> OwnershipVoucherEntry {
        self.entry
    }
}

impl Message for OVNextEntry20 {
    fn message_type() -> MessageType {
        MessageType::TO2OVNextEntry20
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::TO2GetOVNextEntry20))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version2_0
    }
}

impl ServerMessage for OVNextEntry20 {}

// ============================================================
// Type 86: TO2.DeviceSvcInfoRdy20 (Device -> Owner)
// ENCRYPTED. No HMAC here - moved to Done20.
// ============================================================
#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct DeviceSvcInfoRdy20 {
    max_owner_service_info_sz: Option<u16>,
}

impl DeviceSvcInfoRdy20 {
    pub fn new(max_owner_service_info_sz: Option<u16>) -> Self {
        DeviceSvcInfoRdy20 {
            max_owner_service_info_sz,
        }
    }
}

impl Message for DeviceSvcInfoRdy20 {
    fn message_type() -> MessageType {
        MessageType::TO2DeviceSvcInfoRdy20
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(
            message_type,
            Some(MessageType::TO2OVNextEntry20) | Some(MessageType::TO2ProveOVHdr20)
        )
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version2_0
    }
}

impl ClientMessage for DeviceSvcInfoRdy20 {}

// ============================================================
// Type 87: TO2.SetupDevice20 (Owner -> Device)
// ENCRYPTED. Provides replacement credentials.
// Custom Serializable to handle CBOR array encoding from Go.
// ============================================================
#[derive(Debug)]
pub struct SetupDevice20 {
    nonce_to2_setup_dv: Nonce,
    replacement_guid: Option<Guid>,
    replacement_rv_info: Option<RendezvousInfo>,
    max_device_service_info_sz: u16,
}

impl crate::Serializable for SetupDevice20 {
    fn deserialize_from_reader<R>(reader: R) -> Result<Self, crate::Error>
    where
        R: std::io::Read,
    {
        use crate::cborparser::{ParsedArray, ParsedArraySize4};
        let arr: ParsedArray<ParsedArraySize4> = ParsedArray::deserialize_from_reader(reader)?;
        Ok(Self {
            nonce_to2_setup_dv: arr.get(0)?,
            replacement_guid: arr.get(1)?,
            replacement_rv_info: arr.get(2)?,
            max_device_service_info_sz: arr.get(3)?,
        })
    }

    fn deserialize_data(data: &[u8]) -> Result<Self, crate::Error> {
        Self::deserialize_from_reader(data)
    }

    fn serialize_to_writer<W>(&self, writer: W) -> Result<(), crate::Error>
    where
        W: std::io::Write,
    {
        use crate::cborparser::{ParsedArrayBuilder, ParsedArraySize4};
        let mut arr = ParsedArrayBuilder::<ParsedArraySize4>::new();
        arr.set(0, &self.nonce_to2_setup_dv)?;
        arr.set(1, &self.replacement_guid)?;
        arr.set(2, &self.replacement_rv_info)?;
        arr.set(3, &self.max_device_service_info_sz)?;
        arr.build().serialize_to_writer(writer)
    }
}

impl SetupDevice20 {
    pub fn nonce_to2_setup_dv(&self) -> &Nonce {
        &self.nonce_to2_setup_dv
    }

    pub fn replacement_guid(&self) -> Option<&Guid> {
        self.replacement_guid.as_ref()
    }

    pub fn replacement_rv_info(&self) -> Option<&RendezvousInfo> {
        self.replacement_rv_info.as_ref()
    }

    pub fn max_device_service_info_sz(&self) -> u16 {
        self.max_device_service_info_sz
    }
}

impl Message for SetupDevice20 {
    fn message_type() -> MessageType {
        MessageType::TO2SetupDevice20
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::TO2DeviceSvcInfoRdy20))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version2_0
    }
}

impl ServerMessage for SetupDevice20 {}

// ============================================================
// Type 88: TO2.DeviceSvcInfo20 (Device -> Owner)
// ENCRYPTED. Device service info round.
// ============================================================
#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct DeviceSvcInfo20 {
    is_more_service_info: bool,
    service_info: ServiceInfo,
}

impl DeviceSvcInfo20 {
    pub fn new(is_more_service_info: bool, service_info: ServiceInfo) -> Self {
        DeviceSvcInfo20 {
            is_more_service_info,
            service_info,
        }
    }

    pub fn is_more_service_info(&self) -> bool {
        self.is_more_service_info
    }

    pub fn service_info(&self) -> &ServiceInfo {
        &self.service_info
    }
}

impl Message for DeviceSvcInfo20 {
    fn message_type() -> MessageType {
        MessageType::TO2DeviceSvcInfo20
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(
            message_type,
            Some(MessageType::TO2SetupDevice20) | Some(MessageType::TO2OwnerSvcInfo20)
        )
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version2_0
    }
}

impl ClientMessage for DeviceSvcInfo20 {}

// ============================================================
// Type 89: TO2.OwnerSvcInfo20 (Owner -> Device)
// ENCRYPTED. Owner service info round.
// ============================================================
#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct OwnerSvcInfo20 {
    is_more_service_info: bool,
    is_done: bool,
    service_info: ServiceInfo,
}

impl OwnerSvcInfo20 {
    pub fn is_more_service_info(&self) -> bool {
        self.is_more_service_info
    }

    pub fn is_done(&self) -> bool {
        self.is_done
    }

    pub fn service_info(&self) -> &ServiceInfo {
        &self.service_info
    }
}

impl Message for OwnerSvcInfo20 {
    fn message_type() -> MessageType {
        MessageType::TO2OwnerSvcInfo20
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::TO2DeviceSvcInfo20))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version2_0
    }
}

impl ServerMessage for OwnerSvcInfo20 {}

// ============================================================
// Type 90: TO2.Done20 (Device -> Owner)
// ENCRYPTED. ReplacementHMAC sent HERE (not in DeviceSvcInfoRdy20)
// so client can compute it after receiving GUID/RvInfo from SetupDevice20.
// ============================================================
#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct Done20 {
    nonce_to2_setup_dv: Nonce,
    replacement_hmac: Option<HMac>,
}

impl Done20 {
    pub fn new(nonce_to2_setup_dv: Nonce, replacement_hmac: Option<HMac>) -> Self {
        Done20 {
            nonce_to2_setup_dv,
            replacement_hmac,
        }
    }

    pub fn nonce_to2_setup_dv(&self) -> &Nonce {
        &self.nonce_to2_setup_dv
    }

    pub fn replacement_hmac(&self) -> Option<&HMac> {
        self.replacement_hmac.as_ref()
    }
}

impl Message for Done20 {
    fn message_type() -> MessageType {
        MessageType::TO2Done20
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(
            message_type,
            Some(MessageType::TO2OwnerSvcInfo20) | Some(MessageType::TO2SetupDevice20)
        )
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version2_0
    }
}

impl ClientMessage for Done20 {}

// ============================================================
// Type 91: TO2.DoneAck20 (Owner -> Device)
// ENCRYPTED. Owner acknowledges completion.
// ============================================================
#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct DoneAck20 {
    nonce_to2_prove_ov: Nonce,
}

impl DoneAck20 {
    pub fn nonce_to2_prove_ov(&self) -> &Nonce {
        &self.nonce_to2_prove_ov
    }
}

impl Message for DoneAck20 {
    fn message_type() -> MessageType {
        MessageType::TO2DoneAck20
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::TO2Done20))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version2_0
    }
}

impl ServerMessage for DoneAck20 {}
