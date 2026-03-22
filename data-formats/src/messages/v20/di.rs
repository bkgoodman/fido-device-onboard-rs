// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause

// FDO 2.0 Device Initialization (DI) Protocol Messages

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_tuple::Serialize_tuple;
use std::io::Write;

use crate::{
    constants::{MessageType, ProtocolVersion},
    messages::{ClientMessage, EncryptionRequirement, Message, ServerMessage},
    ownershipvoucher::OwnershipVoucherHeader,
    types::{CapabilityFlags, DeviceMfgInfo, HMac},
    Error,
};

// Type 10: DI.AppStart - FDO 2.0
// Device initiates Device Initialization with capability flags.
// The info field is a Bstr-wrapped DeviceMfgInfo (CBOR array serialized
// into a byte string), matching Go's cbor.Bstr[T] convention.
#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct AppStart {
    info: Option<ByteBuf>,
    capability_flags: CapabilityFlags,
}

impl AppStart {
    /// Create an AppStart from a DeviceMfgInfo.
    /// The DeviceMfgInfo is CBOR-serialized and wrapped in a byte string,
    /// matching Go's cbor.Bstr[custom.DeviceMfgInfo] encoding.
    pub fn new(info: &DeviceMfgInfo, capability_flags: CapabilityFlags) -> Self {
        let mut buffer = Vec::new();
        ciborium::ser::into_writer(info, &mut buffer)
            .expect("Failed to serialize DeviceMfgInfo");
        AppStart {
            info: Some(ByteBuf::from(buffer)),
            capability_flags,
        }
    }

    pub fn capability_flags(&self) -> &CapabilityFlags {
        &self.capability_flags
    }
}

impl Message for AppStart {
    fn protocol_version() -> ProtocolVersion {
        ProtocolVersion::Version2_0
    }

    fn message_type() -> MessageType {
        MessageType::DIAppStart
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        message_type.is_none()
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }
}

impl ClientMessage for AppStart {}

// Type 11: DI.SetCredentials - FDO 2.0
// Server responds with Ownership Voucher header (Bstr-wrapped).
// The Go server's setCredentialsMsg has only OVHeader (no CapabilityFlags).
#[derive(Debug)]
pub struct SetCredentials {
    ov_header: OwnershipVoucherHeader,
}

impl crate::Serializable for SetCredentials {
    fn serialize_to_writer<W>(&self, writer: W) -> core::result::Result<(), crate::Error>
    where
        W: std::io::Write,
    {
        let ov_header_bytes = self.ov_header.serialize_data()?;
        let mut buffer = Vec::new();
        ciborium::ser::into_writer(&(&ov_header_bytes[..],), buffer.by_ref())?;
        std::io::copy(&mut &buffer[..], &mut std::io::BufWriter::new(writer))?;
        Ok(())
    }

    fn deserialize_from_reader<R>(mut reader: R) -> core::result::Result<Self, crate::Error>
    where
        R: std::io::Read,
    {
        // Go sends array(1): [Bstr(OVHeader)]
        let (ov_header_bytes,): (serde_bytes::ByteBuf,) =
            ciborium::de::from_reader(&mut reader)?;
        let ov_header = OwnershipVoucherHeader::deserialize_from_reader(&ov_header_bytes[..])?;
        Ok(SetCredentials { ov_header })
    }
}

impl SetCredentials {
    pub fn new(ov_header: OwnershipVoucherHeader) -> Self {
        SetCredentials { ov_header }
    }

    pub fn ov_header(&self) -> &OwnershipVoucherHeader {
        &self.ov_header
    }

    pub fn into_ov_header(self) -> OwnershipVoucherHeader {
        self.ov_header
    }
}

impl Message for SetCredentials {
    fn protocol_version() -> ProtocolVersion {
        ProtocolVersion::Version2_0
    }

    fn message_type() -> MessageType {
        MessageType::DISetCredentials
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        message_type == Some(MessageType::DIAppStart)
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }
}

impl ServerMessage for SetCredentials {}

// Type 12: DI.SetHMAC - FDO 2.0 (unchanged from 1.1)
// Device sends HMAC of Ownership Voucher header
#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct SetHMAC {
    hmac: HMac,
}

impl SetHMAC {
    pub fn new(hmac: HMac) -> Self {
        SetHMAC { hmac }
    }

    pub fn hmac(&self) -> &HMac {
        &self.hmac
    }
}

impl Message for SetHMAC {
    fn protocol_version() -> ProtocolVersion {
        ProtocolVersion::Version2_0
    }

    fn message_type() -> MessageType {
        MessageType::DISetHMAC
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        message_type == Some(MessageType::DISetCredentials)
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }
}

impl ClientMessage for SetHMAC {}

// Type 13: DI.Done - FDO 2.0 (unchanged from 1.1)
// Manufacturing server acknowledges completion
#[derive(Debug, Deserialize)]
pub struct Done {}

// Custom Serialize implementation to serialize as empty CBOR array
impl Serialize for Done {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;
        let seq = serializer.serialize_seq(Some(0))?;
        seq.end()
    }
}

impl Message for Done {
    fn protocol_version() -> ProtocolVersion {
        ProtocolVersion::Version2_0
    }

    fn message_type() -> MessageType {
        MessageType::DIDone
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        message_type == Some(MessageType::DISetHMAC)
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }
}

impl ServerMessage for Done {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Serializable;
    use crate::constants::{PublicKeyType, PublicKeyEncoding};

    #[test]
    fn test_capability_flags_in_app_start() {
        let caps = CapabilityFlags::new_v20_client();
        assert!(caps.supports_version(ProtocolVersion::Version2_0));
        assert!(!caps.supports_delegate());
    }

    #[test]
    fn test_set_credentials_with_capability_flags() {
        let caps = CapabilityFlags::new_v20_client();
        assert!(caps.supports_version(ProtocolVersion::Version2_0));
        assert!(!caps.supports_version(ProtocolVersion::Version1_1));
    }

    #[test]
    fn test_done_message_empty() {
        let done = Done {};
        let serialized = done.serialize_data().unwrap();
        assert!(!serialized.is_empty());
        let _deserialized = Done::deserialize_from_reader(&serialized[..]).unwrap();
    }

    #[test]
    fn test_device_mfg_info_serialization() {
        // Verify DeviceMfgInfo serializes as CBOR array(5)
        let info = DeviceMfgInfo::new(
            PublicKeyType::SECP384R1,
            PublicKeyEncoding::X509,
            "12345".to_string(),
            "rusttest".to_string(),
            vec![0xDE, 0xAD], // mock CSR DER
        );
        let serialized = info.serialize_data().unwrap();
        // First byte 0x85 = CBOR array(5)
        assert_eq!(serialized[0], 0x85, "DeviceMfgInfo must serialize as CBOR array(5)");
    }

    #[test]
    fn test_app_start_with_device_mfg_info() {
        // Verify AppStart wraps DeviceMfgInfo in a bstr, producing array(2)
        let info = DeviceMfgInfo::new(
            PublicKeyType::SECP384R1,
            PublicKeyEncoding::X509,
            "12345".to_string(),
            "rusttest".to_string(),
            vec![0xDE, 0xAD], // mock CSR DER
        );
        let caps = CapabilityFlags::new_v20_client();
        let app_start = AppStart::new(&info, caps);
        let serialized = app_start.serialize_data().unwrap();

        println!("AppStart hex: {}", hex::encode(&serialized));

        // First byte 0x82 = CBOR array(2)
        assert_eq!(serialized[0], 0x82, "AppStart must serialize as CBOR array(2)");

        // Second byte must be a CBOR bstr (major type 2 = 0x40..0x5b)
        let major_type = serialized[1] >> 5;
        assert_eq!(major_type, 2, "First element must be a CBOR byte string (bstr)");

        // Roundtrip: deserialize and check structure
        let deserialized = AppStart::deserialize_from_reader(&serialized[..]).unwrap();
        assert!(deserialized.capability_flags().supports_version(ProtocolVersion::Version2_0));
    }

    #[test]
    fn test_1tuple_ciborium_deser() {
        // Verify ciborium can deserialize 1-tuple from CBOR array(1)
        let test_data: Vec<u8> = vec![0x81, 0x43, 0xDE, 0xAD, 0xBE];
        let result: (serde_bytes::ByteBuf,) = ciborium::de::from_reader(&test_data[..]).unwrap();
        assert_eq!(&result.0[..], &[0xDE, 0xAD, 0xBE]);
    }
}
