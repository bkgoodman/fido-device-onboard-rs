// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause

// FDO 2.0 Transfer Ownership 1 (TO1) Protocol Messages
//
// TO1 uses the SAME message types as FDO 1.1 (30-33) but adds
// CapabilityFlags as a trailing field to HelloRV and HelloRVAck.
// ProveToRV and RVRedirect are unchanged (COSE_Sign1 wrappers).

use serde::Deserialize;
use serde_tuple::Serialize_tuple;

use crate::simple_message_serializable;
use crate::{
    constants::MessageType,
    messages::{ClientMessage, EncryptionRequirement, Message, ServerMessage},
    types::{COSESign, CapabilityFlags, Guid, Nonce, SigInfo},
};

// Type 30: TO1.HelloRV - FDO 2.0
// Device initiates TO1. CapabilityFlags fields are FLATTENED
// (Go embeds CapabilityFlags, so Flags/VendorUnique are top-level fields).
#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct HelloRV {
    guid: Guid,
    a_signature_info: SigInfo,
    #[serde(with = "serde_bytes")]
    capability_flags: Vec<u8>,
    // VendorUnique omitted (skip_serializing_if not supported in Serialize_tuple
    // with trailing Option; Go's omitempty also omits it when nil)
}

impl HelloRV {
    pub fn new(guid: Guid, a_signature_info: SigInfo, capability_flags: CapabilityFlags) -> Self {
        HelloRV {
            guid,
            a_signature_info,
            capability_flags: capability_flags.flags,
        }
    }

    pub fn guid(&self) -> &Guid {
        &self.guid
    }

    pub fn a_signature_info(&self) -> &SigInfo {
        &self.a_signature_info
    }
}

impl Message for HelloRV {
    fn message_type() -> MessageType {
        MessageType::TO1HelloRV
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

impl ClientMessage for HelloRV {}

// Type 31: TO1.HelloRVAck - FDO 2.0
// Server acknowledges HelloRV. CapabilityFlags fields are FLATTENED.
// Array: [Nonce, SigInfo, Flags_bytes, VendorUnique_optional]
#[derive(Debug, Serialize_tuple)]
pub struct HelloRVAck {
    nonce4: Nonce,
    b_signature_info: SigInfo,
    #[serde(with = "serde_bytes")]
    capability_flags: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vendor_unique: Option<Vec<String>>,
}

impl<'de> serde::Deserialize<'de> for HelloRVAck {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = HelloRVAck;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a CBOR array of 3 or 4 elements for HelloRVAck")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<HelloRVAck, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let nonce4 = seq.next_element()?.ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let b_signature_info = seq.next_element()?.ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let flags: serde_bytes::ByteBuf = seq.next_element()?.ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let vendor_unique: Option<Vec<String>> = seq.next_element()?;
                Ok(HelloRVAck {
                    nonce4,
                    b_signature_info,
                    capability_flags: flags.into_vec(),
                    vendor_unique,
                })
            }
        }
        deserializer.deserialize_seq(Visitor)
    }
}

impl HelloRVAck {
    pub fn nonce4(&self) -> &Nonce {
        &self.nonce4
    }

    pub fn b_signature_info(&self) -> &SigInfo {
        &self.b_signature_info
    }
}

impl Message for HelloRVAck {
    fn message_type() -> MessageType {
        MessageType::TO1HelloRVAck
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::TO1HelloRV))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version2_0
    }
}

impl ServerMessage for HelloRVAck {}

// Types 32-33: ProveToRV and RVRedirect are identical to FDO 1.1
// (COSE_Sign1 wrappers with no structural changes).
// Re-export the v11 versions with v20 protocol_version wrappers.

#[derive(Debug)]
pub struct ProveToRV(COSESign);

simple_message_serializable!(ProveToRV, COSESign);

impl ProveToRV {
    pub fn new(token: COSESign) -> Self {
        ProveToRV(token)
    }

    pub fn token(&self) -> &COSESign {
        &self.0
    }
}

impl Message for ProveToRV {
    fn message_type() -> MessageType {
        MessageType::TO1ProveToRV
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::TO1HelloRVAck))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version2_0
    }
}

impl ClientMessage for ProveToRV {}

#[derive(Debug)]
pub struct RVRedirect(COSESign);

simple_message_serializable!(RVRedirect, COSESign);

impl RVRedirect {
    pub fn new(to1d: COSESign) -> Self {
        RVRedirect(to1d)
    }

    pub fn to1d(&self) -> &COSESign {
        &self.0
    }

    pub fn into_to1d(self) -> COSESign {
        self.0
    }
}

impl Message for RVRedirect {
    fn message_type() -> MessageType {
        MessageType::TO1RVRedirect
    }

    fn is_valid_previous_message(message_type: Option<MessageType>) -> bool {
        matches!(message_type, Some(MessageType::TO1ProveToRV))
    }

    fn encryption_requirement() -> Option<EncryptionRequirement> {
        Some(EncryptionRequirement::MustNotBeEncrypted)
    }

    fn protocol_version() -> crate::ProtocolVersion {
        crate::ProtocolVersion::Version2_0
    }
}

impl ServerMessage for RVRedirect {}
