// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause

// FDO 2.0 Transfer Ownership 1 (TO1) Protocol Messages
//
// TO1 uses the SAME message types as FDO 1.1 (30-33). In 2.0, HelloRV and
// HelloRVAck lead with CapabilityFlags and VendorCapFlags and no longer carry
// eASigInfo / eBSigInfo.
// ProveToRV and RVRedirect are unchanged (COSE_Sign1 wrappers).

use serde::Deserialize;
use serde_tuple::Serialize_tuple;

use crate::simple_message_serializable;
use crate::{
    constants::MessageType,
    messages::{ClientMessage, EncryptionRequirement, Message, ServerMessage},
    types::{COSESign, CapabilityFlags, Guid, Nonce},
};

// Type 30: TO1.HelloRV - FDO 2.0
// Spec: [CapabilityFlags, VendorCapFlags, Guid]
#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct HelloRV {
    #[serde(with = "serde_bytes")]
    capability_flags: Vec<u8>,
    vendor_cap_flags: Vec<String>,
    guid: Guid,
}

impl HelloRV {
    pub fn new(guid: Guid, capability_flags: CapabilityFlags) -> Self {
        let (capability_flags, vendor_cap_flags) = capability_flags.into_parts();
        HelloRV {
            capability_flags,
            vendor_cap_flags,
            guid,
        }
    }

    pub fn guid(&self) -> &Guid {
        &self.guid
    }

    pub fn capability_flags(&self) -> CapabilityFlags {
        CapabilityFlags::from_parts(&self.capability_flags, &self.vendor_cap_flags)
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
// Spec: [CapabilityFlags, VendorCapFlags, NonceTO1Proof]
#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct HelloRVAck {
    #[serde(with = "serde_bytes")]
    capability_flags: Vec<u8>,
    vendor_cap_flags: Vec<String>,
    nonce4: Nonce,
}

impl HelloRVAck {
    pub fn nonce4(&self) -> &Nonce {
        &self.nonce4
    }

    pub fn capability_flags(&self) -> CapabilityFlags {
        CapabilityFlags::from_parts(&self.capability_flags, &self.vendor_cap_flags)
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
pub struct RVRedirect {
    num_to1ds: u64,
    idx_to1ds: u64,
    to1ds: Vec<COSESign>,
}

// FDO 2.0 wire form: [numTo1ds, idxTo1ds, [to1d, ...]]
impl crate::Serializable for RVRedirect {
    fn deserialize_from_reader<R>(reader: R) -> Result<Self, crate::Error>
    where
        R: std::io::Read,
    {
        use crate::cborparser::{ParsedArray, ParsedArraySize3, ParsedArraySizeDynamic};
        let arr: ParsedArray<ParsedArraySize3> = ParsedArray::deserialize_from_reader(reader)?;
        let list: ParsedArray<ParsedArraySizeDynamic> =
            ParsedArray::deserialize_data(arr.get_raw(2))?;
        let mut to1ds = Vec::with_capacity(list.len());
        for i in 0..list.len() {
            to1ds.push(COSESign::deserialize_data(list.get_raw(i))?);
        }
        Ok(RVRedirect {
            num_to1ds: arr.get(0)?,
            idx_to1ds: arr.get(1)?,
            to1ds,
        })
    }

    fn serialize_to_writer<W>(&self, mut writer: W) -> Result<(), crate::Error>
    where
        W: std::io::Write,
    {
        let mut out = Vec::new();
        ciborium::ser::into_writer(&(self.num_to1ds, self.idx_to1ds), &mut out)?;
        out[0] = 0x83; // extend the 2-element header to 3; the list follows
        let len = self.to1ds.len();
        if len < 24 {
            out.push(0x80 | len as u8);
        } else {
            return Err(crate::Error::InconsistentValue("too many to1d blobs"));
        }
        for to1d in &self.to1ds {
            out.extend(to1d.serialize_data()?);
        }
        writer.write_all(&out)?;
        Ok(())
    }
}

impl RVRedirect {
    /// A redirect carrying a single rendezvous blob (no Delegation).
    pub fn new(to1d: COSESign) -> Self {
        RVRedirect {
            num_to1ds: 1,
            idx_to1ds: 0,
            to1ds: vec![to1d],
        }
    }

    /// Return the first rendezvous blob. Fetching further blobs with
    /// TO1.RVMore (Delegation only) is not supported.
    pub fn into_to1d(mut self) -> Result<COSESign, crate::Error> {
        if self.idx_to1ds != 0 || self.to1ds.is_empty() || self.num_to1ds < self.to1ds.len() as u64
        {
            return Err(crate::Error::InconsistentValue("malformed TO1.RVRedirect"));
        }
        Ok(self.to1ds.swap_remove(0))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{messages::v20::to2::HelloDeviceProbe, Serializable};

    // FDO 2.0 messages carrying capability flags must lead with
    // CapabilityFlags (bstr) and VendorCapFlags ([* tstr]) as separate elements.
    fn assert_caps_layout(serialized: &[u8], expected_len: usize) {
        let elems: Vec<ciborium::Value> = ciborium::de::from_reader(serialized).unwrap();
        assert_eq!(elems.len(), expected_len);
        assert!(
            elems[0].is_bytes(),
            "element 0 must be CapabilityFlags bstr"
        );
        assert!(
            elems[1].is_array(),
            "element 1 must be VendorCapFlags array"
        );
    }

    #[test]
    fn test_hello_rv_spec_layout() {
        let msg = HelloRV::new(Guid::new().unwrap(), CapabilityFlags::new_v20_client());
        let b = msg.serialize_data().unwrap();
        assert_caps_layout(&b, 3);
        let rt = HelloRV::deserialize_data(&b).unwrap();
        assert_eq!(rt.guid(), msg.guid());
    }

    #[test]
    fn test_hello_device_probe_spec_layout() {
        let msg = HelloDeviceProbe::new(
            Guid::new().unwrap(),
            CapabilityFlags::new_v20_client(),
            vec![-16],
            vec![0u8; 16],
        );
        assert_caps_layout(&msg.serialize_data().unwrap(), 6);
    }

    #[test]
    fn test_rv_redirect_malformed_rejected() {
        // [numTo1ds=1, idxTo1ds=0, []]: no blob
        let empty = RVRedirect::deserialize_data(&[0x83, 0x01, 0x00, 0x80]).unwrap();
        assert!(empty.into_to1d().is_err());
        // idxTo1ds != 0 (RVMore continuation) is not supported
        let cont = RVRedirect::deserialize_data(&[0x83, 0x02, 0x01, 0x80]).unwrap();
        assert!(cont.into_to1d().is_err());
    }

    #[test]
    fn test_to1d_payload_v11_and_v20() {
        use crate::constants::HashType;
        use crate::types::{Hash, TO1DataPayload};
        let hash = Hash::from_data(HashType::Sha256, b"to0d").unwrap();
        let v11 = serde_cbor::to_vec(&TO1DataPayload::new(vec![], hash.clone())).unwrap();
        assert_eq!(v11[0], 0x82);
        let p: TO1DataPayload = serde_cbor::from_slice(&v11).unwrap();
        assert!(p.delegate_chain().unwrap().is_none());

        // FDO 2.0: third element is bstr .cbor CertChainOrNull
        let mut v20 = v11.clone();
        v20[0] = 0x83;
        v20.extend_from_slice(&[0x41, 0xf6]); // bstr(null)
        let p: TO1DataPayload = serde_cbor::from_slice(&v20).unwrap();
        assert!(p.delegate_chain().unwrap().is_none());

        let mut v20d = v11;
        v20d[0] = 0x83;
        v20d.extend_from_slice(&[0x44, 0x81, 0x42, 0x30, 0x01]); // bstr([h'3001'])
        let p: TO1DataPayload = serde_cbor::from_slice(&v20d).unwrap();
        assert_eq!(
            p.delegate_chain().unwrap().unwrap()[0].as_ref(),
            &[0x30, 0x01]
        );
    }

    #[test]
    fn test_to2_errata1_layouts() {
        use crate::messages::v20::to2::{DeviceSvcInfo20, DeviceSvcInfoRdy20, Done20};
        use crate::types::ServiceInfo;
        let nonce = Nonce::new().unwrap();

        // 86: [null, maxOwnerServiceInfoSz, NonceTO2SetupDV_Prep]
        let b = DeviceSvcInfoRdy20::new(Some(1300), nonce.clone())
            .serialize_data()
            .unwrap();
        let v: Vec<serde_cbor::Value> = serde_cbor::from_slice(&b).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], serde_cbor::Value::Null);

        // 88: [null, IsMore, ServiceInfo]
        let b = DeviceSvcInfo20::new(false, ServiceInfo::new())
            .serialize_data()
            .unwrap();
        let v: Vec<serde_cbor::Value> = serde_cbor::from_slice(&b).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], serde_cbor::Value::Null);

        // 90: [NonceTO2ProveDv, ReplacementHMac]
        let b = Done20::new(nonce.clone(), None).serialize_data().unwrap();
        let v: Vec<serde_cbor::Value> = serde_cbor::from_slice(&b).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], serde_cbor::Value::Bytes(nonce.value().to_vec()));
    }
}
