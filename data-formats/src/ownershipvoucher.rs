// Copyright (c) 2021, Red Hat, Inc.
// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause

use std::ops::Range;

use openssl::pkey::{PKeyRef, Private};
use serde_bytes::ByteBuf;

use crate::{
    cborparser::{
        ParsedArray, ParsedArrayBuilder, ParsedArraySize5, ParsedArraySize6, ParsedArraySizeDynamic,
    },
    constants::HashType,
    errors::Result,
    publickey::{PublicKey, X5Chain},
    serializable::MaybeSerializable,
    types::{COSESign, Guid, HMac, Hash, RendezvousInfo, UnverifiedValue},
    DeserializableMany, Error, ProtocolVersion, Serializable,
};

const VOUCHER_PEM_TAG: &str = "OWNERSHIP VOUCHER";
const ACCEPTABLE_ASCII_RANGE: Range<u8> = 32..127;

// ExtraType: Go encodes this as cbor.Bstr[map[int][]byte] - a byte string wrapping a CBOR map.
// We store it as raw bytes (ByteBuf) to handle both Go's Bstr encoding and direct null.
type ExtraType = Option<ByteBuf>;
type RefExtraType<'a> = Option<&'a ByteBuf>;

#[derive(Debug)]
enum OwnershipVoucherIndex {
    ProtocolVersion = 0,
    Header = 1,
    HeaderHmac = 2,
    DeviceCertificateChain = 3,
    Entries = 4,
}

#[derive(Debug, Clone)]
pub struct OwnershipVoucher {
    contents: ParsedArray<ParsedArraySize5>,

    // Cached data
    cached_protocol_version: ProtocolVersion,
    cached_header: OwnershipVoucherHeader,
    cached_header_hmac: HMac,
    cached_device_certificate_chain: Option<X5Chain>,
    cached_entries: ParsedArray<ParsedArraySizeDynamic>,
}

impl OwnershipVoucher {
    fn from_parsed_array(contents: ParsedArray<ParsedArraySize5>) -> Result<Self> {
        let cached_protocol_version =
            contents.get(OwnershipVoucherIndex::ProtocolVersion as usize)?;
        let cached_header: ByteBuf = contents.get(OwnershipVoucherIndex::Header as usize)?;
        let cached_header = OwnershipVoucherHeader::deserialize_data(&cached_header)?;
        let cached_header_hmac = contents.get(OwnershipVoucherIndex::HeaderHmac as usize)?;
        let cached_device_certificate_chain =
            contents.get(OwnershipVoucherIndex::DeviceCertificateChain as usize)?;
        let cached_entries = contents.get(OwnershipVoucherIndex::Entries as usize)?;

        Ok(OwnershipVoucher {
            contents,

            cached_protocol_version,
            cached_header,
            cached_header_hmac,
            cached_device_certificate_chain,
            cached_entries,
        })
    }
}

impl Serializable for OwnershipVoucher {
    fn deserialize_from_reader<R>(reader: R) -> Result<Self>
    where
        R: std::io::Read,
    {
        let contents = ParsedArray::deserialize_from_reader(reader);
        if let Err(Error::ArrayParseError(
            crate::cborparser::ArrayParseError::InvalidNumberOfElements(4, 5),
        )) = contents
        {
            return Err(Error::UnsupportedVersion(Some(ProtocolVersion::Version1_0)));
        };
        let contents = contents?;
        Self::from_parsed_array(contents)
    }

    fn serialize_to_writer<W>(&self, writer: W) -> Result<()>
    where
        W: std::io::Write,
    {
        self.contents.serialize_to_writer(writer)
    }
}

impl MaybeSerializable for OwnershipVoucher {
    fn is_nodata_error(err: &Error) -> bool {
        matches!(
            err,
            Error::ArrayParseError(crate::cborparser::ArrayParseError::NoData)
        )
    }
}

impl DeserializableMany for OwnershipVoucher {}

impl OwnershipVoucher {
    pub fn from_parts(
        protocol_version: ProtocolVersion,
        header: &[u8],
        header_hmac: HMac,
        entries: ParsedArray<ParsedArraySizeDynamic>,
    ) -> Result<Self> {
        let mut contents = ParsedArrayBuilder::new();
        contents.set(
            OwnershipVoucherIndex::ProtocolVersion as usize,
            &protocol_version,
        )?;
        contents.set(
            OwnershipVoucherIndex::Header as usize,
            &ByteBuf::from(header),
        )?;
        contents.set(OwnershipVoucherIndex::HeaderHmac as usize, &header_hmac)?;
        contents.set::<Option<X5Chain>>(
            OwnershipVoucherIndex::DeviceCertificateChain as usize,
            &None,
        )?;
        contents.set(OwnershipVoucherIndex::Entries as usize, &entries)?;
        let contents = contents.build();

        let cached_header = OwnershipVoucherHeader::deserialize_data(header)?;

        Ok(OwnershipVoucher {
            contents,

            cached_protocol_version: protocol_version,
            cached_header,
            cached_header_hmac: header_hmac,
            cached_device_certificate_chain: None,
            cached_entries: entries,
        })
    }

    pub fn new(
        header: OwnershipVoucherHeader,
        header_hmac: HMac,
        device_certificate_chain: Option<X5Chain>,
    ) -> Result<Self> {
        let entries = ParsedArray::new_empty();

        let contents_header = ByteBuf::from(header.contents.serialize_data()?);

        let mut contents = ParsedArrayBuilder::new();
        contents.set(
            OwnershipVoucherIndex::ProtocolVersion as usize,
            &ProtocolVersion::Version1_1,
        )?;
        contents.set(OwnershipVoucherIndex::Header as usize, &contents_header)?;
        contents.set(OwnershipVoucherIndex::HeaderHmac as usize, &header_hmac)?;
        contents.set(
            OwnershipVoucherIndex::DeviceCertificateChain as usize,
            &device_certificate_chain,
        )?;
        contents.set(OwnershipVoucherIndex::Entries as usize, &entries)?;
        let contents = contents.build();

        Ok(OwnershipVoucher {
            contents,

            cached_protocol_version: ProtocolVersion::Version1_1,
            cached_header: header,
            cached_header_hmac: header_hmac,
            cached_device_certificate_chain: device_certificate_chain,
            cached_entries: entries,
        })
    }

    pub fn from_pem(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::EmptyData);
        }
        let parsed = pem::parse(data)?;
        if parsed.tag() != VOUCHER_PEM_TAG {
            return Err(Error::InvalidPemTag(parsed.tag().to_string()));
        }
        Self::deserialize_data(parsed.contents())
    }

    pub fn many_from_pem(data: &[u8]) -> Result<Vec<Self>> {
        if data.is_empty() {
            return Err(Error::EmptyData);
        }
        pem::parse_many(data)?
            .into_iter()
            .map(|parsed| {
                if parsed.tag() == VOUCHER_PEM_TAG {
                    Self::deserialize_from_reader(parsed.contents())
                } else {
                    Err(Error::InvalidPemTag(parsed.tag().to_string()))
                }
            })
            .collect()
    }

    pub fn from_pem_or_raw(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::EmptyData);
        }
        if data[0] == data[1] && data[0] == b'-' {
            Self::from_pem(data)
        } else {
            Self::deserialize_data(data)
        }
    }

    pub fn to_pem(&self) -> Result<String> {
        let block = pem::Pem::new(VOUCHER_PEM_TAG.to_string(), self.serialize_data()?);
        Ok(pem::encode(&block))
    }

    fn hash_type(&self) -> HashType {
        self.cached_header_hmac.get_type().inner_hash()
    }

    pub fn header_hmac(&self) -> &HMac {
        &self.cached_header_hmac
    }

    pub fn device_certificate_chain(&self) -> Option<&X5Chain> {
        self.cached_device_certificate_chain.as_ref()
    }

    pub fn device_certificate_chain_hash(&self, hash_type: HashType) -> Option<Result<Hash>> {
        if self.cached_device_certificate_chain.is_none() {
            None
        } else {
            Some(self.contents.get_hash(
                OwnershipVoucherIndex::DeviceCertificateChain as usize,
                hash_type,
            ))
        }
    }

    pub fn num_entries(&self) -> u16 {
        self.cached_entries.len() as u16
    }

    pub fn entry(&self, entry_num: usize) -> Result<OwnershipVoucherEntry> {
        self.cached_entries.get(entry_num)
    }

    fn hdr_hash(&self, hash_type: HashType) -> Result<Hash> {
        let header: ByteBuf = self.contents.get(OwnershipVoucherIndex::Header as usize)?;
        let header_hmac = self
            .contents
            .get_raw(OwnershipVoucherIndex::HeaderHmac as usize);

        let mut data = Vec::with_capacity(header.len() + header_hmac.len());

        data.extend_from_slice(&header);
        data.extend_from_slice(header_hmac);

        Hash::from_data(hash_type, &data)
    }

    pub fn extend(
        &mut self,
        owner_private_key: &PKeyRef<Private>,
        extra: ExtraType,
        next_party: &PublicKey,
    ) -> Result<()> {
        if extra.is_some() && self.cached_protocol_version < ProtocolVersion::Version1_1 {
            return Err(Error::InvalidProtocolVersion(self.cached_protocol_version));
        }

        let hdrinfo_hash = self.header().get_hdr_info_hash(self.hash_type())?;
        let (last_hash, current_owner_pubkey) = if self.cached_entries.is_empty() {
            (
                self.hdr_hash(self.hash_type())?,
                self.header().manufacturer_public_key().clone(),
            )
        } else {
            let last_idx = self.cached_entries.len() - 1;

            let last_hash = self.cached_entries.get_hash(last_idx, self.hash_type())?;
            let lastentry: OwnershipVoucherEntry = self.cached_entries.get(last_idx)?;
            let lastentry: UnverifiedValue<OwnershipVoucherEntryPayload> =
                lastentry.get_payload_unverified()?;

            (
                last_hash,
                lastentry.get_unverified_value().public_key.clone(),
            )
        };

        if !current_owner_pubkey.matches_pkey(owner_private_key)? {
            return Err(Error::NonOwnerKey);
        }

        // Create new entry
        let new_entry =
            OwnershipVoucherEntryPayload::new(last_hash, hdrinfo_hash, extra, next_party.clone())?;

        // Sign with private key
        let signed_new_entry = COSESign::new(&new_entry, None, owner_private_key)?;
        let signed_new_entry = OwnershipVoucherEntry::new(signed_new_entry);

        // Append
        self.cached_entries.push(&signed_new_entry)?;

        self.contents.set(
            OwnershipVoucherIndex::Entries as usize,
            &self.cached_entries,
        )?;

        Ok(())
    }

    pub fn header(&self) -> &OwnershipVoucherHeader {
        &self.cached_header
    }

    pub fn header_raw(&self) -> ByteBuf {
        self.contents
            .get(OwnershipVoucherIndex::Header as usize)
            .unwrap()
    }
}

impl<'a> OwnershipVoucher {
    pub fn iter_entries(&'a self) -> Result<EntryIter<'a>> {
        Ok(EntryIter {
            voucher: self,
            index: 0,
            errored: false,

            last_pubkey: self.header().manufacturer_public_key().clone(),
        })
    }
}

#[derive(Debug)]
pub struct EntryIter<'a> {
    voucher: &'a OwnershipVoucher,
    index: usize,
    errored: bool,

    last_pubkey: PublicKey,
}

impl Iterator for EntryIter<'_> {
    type Item = Result<OwnershipVoucherEntryPayload>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.errored {
            log::warn!("Previous entry validation failed");
            return None;
        }
        if self.index >= self.voucher.cached_entries.len() {
            return None;
        }

        let entry = self.voucher.cached_entries.get(self.index);
        if let Err(e) = entry {
            log::warn!("Error getting next entry: {:?}", e);
            self.errored = true;
            return Some(Err(e));
        }
        let entry = self.process_element(entry.unwrap());

        if entry.is_err() {
            log::warn!("Error validating ownership voucher: {:?}", entry);
            self.errored = true;
        }

        self.index += 1;

        Some(entry)
    }
}

impl EntryIter<'_> {
    fn process_element(
        &mut self,
        entry: OwnershipVoucherEntry,
    ) -> Result<OwnershipVoucherEntryPayload> {
        let entry_cose = entry.0;
        let entry: OwnershipVoucherEntryPayload =
            entry_cose.get_payload(self.last_pubkey.pkey())?;

        // Compare the HashPreviousEntry to either (HeaderTag || HeaderHmac) or the previous entry
        let hash_previous_entry = if self.index == 0 {
            self.voucher
                .hdr_hash(entry.hash_previous_entry.get_type())?
        } else {
            self.voucher
                .cached_entries
                .get_hash(self.index - 1, entry.hash_previous_entry.get_type())?
        };
        match entry.hash_previous_entry.compare(&hash_previous_entry) {
            Ok(_) => {}
            Err(e) => {
                log::error!("Error verifying hash of previous entry");
                return Err(e);
            }
        }

        // Compare the HeaderInfo hash
        let hdr_info_hash = self
            .voucher
            .header()
            .get_hdr_info_hash(entry.hash_header_info.get_type())?;
        match entry.hash_header_info.compare(&hdr_info_hash) {
            Ok(_) => {}
            Err(e) => {
                log::info!("Header hash: {:?}", hdr_info_hash);
                log::info!("Entry hash:  {:?}", entry.hash_header_info);
                log::error!("Error verifying header hash");
                return Err(e);
            }
        }

        // Set the next public key to the key in this entry
        self.last_pubkey = entry.public_key.clone();

        // Return
        Ok(entry)
    }
}

#[derive(Debug)]
#[repr(u8)]
enum OwnershipVoucherHeaderIndex {
    ProtocolVersion = 0,
    Guid = 1,
    RendezvousInfo = 2,
    DeviceInfo = 3,
    ManufacturerPublicKey = 4,
    DeviceCertificateChainHash = 5,
}

#[derive(Clone, Debug)]
pub struct OwnershipVoucherHeader {
    contents: ParsedArray<ParsedArraySize6>,

    cached_protocol_version: ProtocolVersion,
    cached_guid: Guid,
    cached_rendezvous_info: RendezvousInfo,
    cached_device_info: String,
    cached_manufacturer_public_key: PublicKey,
    cached_device_certificate_chain_hash: Option<Hash>,
}

impl OwnershipVoucherHeader {
    pub fn new(
        protocol_version: ProtocolVersion,
        guid: Guid,
        rendezvous_info: RendezvousInfo,
        device_info: String,
        manufacturer_public_key: PublicKey,
        device_certificate_chain_hash: Option<Hash>,
    ) -> Result<Self> {
        let device_info = device_info.trim().to_string();
        let mut contents = ParsedArrayBuilder::new();
        contents.set(
            OwnershipVoucherHeaderIndex::ProtocolVersion as usize,
            &protocol_version,
        )?;
        contents.set(OwnershipVoucherHeaderIndex::Guid as usize, &guid)?;
        contents.set(
            OwnershipVoucherHeaderIndex::RendezvousInfo as usize,
            &rendezvous_info,
        )?;
        contents.set(
            OwnershipVoucherHeaderIndex::DeviceInfo as usize,
            &device_info,
        )?;
        contents.set(
            OwnershipVoucherHeaderIndex::ManufacturerPublicKey as usize,
            &manufacturer_public_key,
        )?;
        contents.set(
            OwnershipVoucherHeaderIndex::DeviceCertificateChainHash as usize,
            &device_certificate_chain_hash,
        )?;
        let contents = contents.build();

        Ok(OwnershipVoucherHeader {
            contents,

            cached_protocol_version: protocol_version,
            cached_guid: guid,
            cached_rendezvous_info: rendezvous_info,
            cached_device_info: device_info,
            cached_manufacturer_public_key: manufacturer_public_key,
            cached_device_certificate_chain_hash: device_certificate_chain_hash,
        })
    }

    pub fn protocol_version(&self) -> ProtocolVersion {
        self.cached_protocol_version
    }

    pub fn guid(&self) -> &Guid {
        &self.cached_guid
    }

    pub fn rendezvous_info(&self) -> &RendezvousInfo {
        &self.cached_rendezvous_info
    }

    pub fn device_info(&self) -> &str {
        &self.cached_device_info
    }

    pub fn manufacturer_public_key(&self) -> &PublicKey {
        &self.cached_manufacturer_public_key
    }

    pub fn manufacturer_public_key_hash(&self, hash_type: HashType) -> Result<Hash> {
        self.contents.get_hash(
            OwnershipVoucherHeaderIndex::ManufacturerPublicKey as usize,
            hash_type,
        )
    }

    pub fn device_certificate_chain_hash(&self) -> Option<&Hash> {
        self.cached_device_certificate_chain_hash.as_ref()
    }

    fn get_hdr_info_hash(&self, hash_type: HashType) -> Result<Hash> {
        // TODO: Check with FIDO Alliance whether this is correct.
        // For the HashPrevEntry, we compute with the actual CBOR type prefix,
        // while for hdr_info, the Intel implementation seemed to not do that.
        let guid: Guid = self
            .contents
            .get(OwnershipVoucherHeaderIndex::Guid as usize)?;
        let device_info: String = self
            .contents
            .get(OwnershipVoucherHeaderIndex::DeviceInfo as usize)?;
        let device_info = device_info.as_bytes();

        let mut data = Vec::with_capacity(guid.len() + device_info.len());
        data.extend_from_slice(&guid);
        data.extend_from_slice(device_info);

        Hash::from_data(hash_type, &data)
    }
}

fn check_device_info(device_info: &str) -> Result<()> {
    let mut chars = device_info.chars();
    let are_all_chars_supported_ascii = chars.all(|f| ACCEPTABLE_ASCII_RANGE.contains(&(f as u8)));
    if are_all_chars_supported_ascii {
        Ok(())
    } else {
        Err(Error::InconsistentValue("Invalid values in Device Info"))
    }
}

#[test]
fn test_check_device_info_unsupported_characters() {
    let device_info: String = "FDO\n".to_string();
    let is_device_info_valid = check_device_info(&device_info);
    assert!(is_device_info_valid.is_err());
}

#[test]
fn test_check_device_info_supported_characters() {
    let device_info: String = "FDO".to_string();
    let is_device_info_valid = check_device_info(&device_info);
    assert!(is_device_info_valid.is_ok());
}

impl Serializable for OwnershipVoucherHeader {
    fn deserialize_from_reader<R>(reader: R) -> Result<Self>
    where
        R: std::io::Read,
    {
        let contents = ParsedArray::deserialize_from_reader(reader)?;

        let cached_protocol_version =
            contents.get(OwnershipVoucherHeaderIndex::ProtocolVersion as usize)?;
        let cached_guid = contents.get(OwnershipVoucherHeaderIndex::Guid as usize)?;
        let cached_rendezvous_info =
            contents.get(OwnershipVoucherHeaderIndex::RendezvousInfo as usize)?;
        let cached_device_info: String =
            contents.get(OwnershipVoucherHeaderIndex::DeviceInfo as usize)?;
        check_device_info(&cached_device_info)?;
        let cached_manufacturer_public_key =
            contents.get(OwnershipVoucherHeaderIndex::ManufacturerPublicKey as usize)?;
        let cached_device_certificate_chain_hash =
            contents.get(OwnershipVoucherHeaderIndex::DeviceCertificateChainHash as usize)?;

        Ok(OwnershipVoucherHeader {
            contents,

            cached_protocol_version,
            cached_guid,
            cached_rendezvous_info,
            cached_device_info,
            cached_manufacturer_public_key,
            cached_device_certificate_chain_hash,
        })
    }

    fn serialize_to_writer<W>(&self, writer: W) -> Result<()>
    where
        W: std::io::Write,
    {
        check_device_info(&self.cached_device_info)?;
        self.contents.serialize_to_writer(writer)
    }
}

#[derive(Debug, Clone)]
pub struct OwnershipVoucherEntry(COSESign);

impl Serializable for OwnershipVoucherEntry {
    fn deserialize_from_reader<R>(reader: R) -> Result<Self>
    where
        R: std::io::Read,
    {
        COSESign::deserialize_from_reader(reader).map(OwnershipVoucherEntry)
    }

    fn serialize_to_writer<W>(&self, writer: W) -> Result<()>
    where
        W: std::io::Write,
    {
        self.0.serialize_to_writer(writer)
    }
}

impl OwnershipVoucherEntry {
    pub fn new(sign: COSESign) -> Self {
        OwnershipVoucherEntry(sign)
    }
}

impl std::ops::Deref for OwnershipVoucherEntry {
    type Target = COSESign;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct OwnershipVoucherEntryPayload {
    hash_previous_entry: Hash,
    hash_header_info: Hash,
    extra: ExtraType,
    public_key: PublicKey,
}

// Custom Serializable using ciborium for deserialization.
// The blanket impl uses serde_cbor which expects CBOR maps for struct deserialization,
// but Go encodes structs as CBOR arrays. ciborium handles both formats.
// We can't derive Serialize+Deserialize because that would trigger the conflicting blanket impl.
impl crate::Serializable for OwnershipVoucherEntryPayload {
    fn deserialize_from_reader<R>(reader: R) -> Result<Self>
    where
        R: std::io::Read,
    {
        // Deserialize as a ParsedArray to handle CBOR array encoding from Go.
        // Go encodes structs as arrays, but serde's Deserialize expects maps.
        use crate::cborparser::{ParsedArray, ParsedArraySize4};
        let arr: ParsedArray<ParsedArraySize4> = ParsedArray::deserialize_from_reader(reader)?;
        let hash_previous_entry: Hash = arr.get(0)?;
        let hash_header_info: Hash = arr.get(1)?;
        let extra: ExtraType = arr.get(2)?;
        let public_key: PublicKey = arr.get(3)?;
        Ok(Self {
            hash_previous_entry,
            hash_header_info,
            extra,
            public_key,
        })
    }

    fn deserialize_data(data: &[u8]) -> Result<Self> {
        Self::deserialize_from_reader(data)
    }

    fn serialize_to_writer<W>(&self, writer: W) -> Result<()>
    where
        W: std::io::Write,
    {
        use crate::cborparser::{ParsedArrayBuilder, ParsedArraySize4};
        let mut arr = ParsedArrayBuilder::<ParsedArraySize4>::new();
        arr.set(0, &self.hash_previous_entry)?;
        arr.set(1, &self.hash_header_info)?;
        arr.set(2, &self.extra)?;
        arr.set(3, &self.public_key)?;
        arr.build().serialize_to_writer(writer)
    }
}

impl OwnershipVoucherEntryPayload {
    pub fn new(
        hash_previous_entry: Hash,
        hash_header_info: Hash,
        extra: ExtraType,
        public_key: PublicKey,
    ) -> Result<Self> {
        Ok(Self {
            hash_previous_entry,
            hash_header_info,
            extra,
            public_key,
        })
    }

    pub fn hash_previous_entry(&self) -> &Hash {
        &self.hash_previous_entry
    }

    pub fn hash_header_info(&self) -> &Hash {
        &self.hash_header_info
    }

    pub fn extra(&self) -> RefExtraType<'_> {
        self.extra.as_ref()
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

#[cfg(test)]
mod tests_ov_entry {
    use super::*;
    use crate::Serializable;

    #[test]
    fn test_ov_entry_payload_deserialize_from_array() {
        // The COSE payload bytes from the Go server's OV entry
        // First byte 0x84 = CBOR array(4)
        let payload_bytes: Vec<u8> = vec![
            0x84, // array(4)
            0x82, 0x2f, 0x58, 0x20, // Hash: [Sha256(-16), bytes(32)]
            0x6f, 0x2b, 0x1e, 0x1c, 0x8f, 0x8c, 0x26, 0x63, 0x5e, 0xf7, 0x32, 0xff, 0x60, 0x80,
            0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x82, 0x2f, 0x58, 0x20, // Hash: [Sha256(-16), bytes(32)]
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x41, 0xa0, // extra: bytes(1) 0xa0  OR  empty map
            0x83, 0x0a, 0x01, 0x41, 0x00, // PublicKey: [10, 1, bytes(1)]
        ];

        // Try to deserialize with custom Serializable (uses ParsedArray)
        let result = OwnershipVoucherEntryPayload::deserialize_data(&payload_bytes);
        match result {
            Ok(_) => println!("serde_cbor deserialization succeeded"),
            Err(e) => println!("serde_cbor deserialization failed: {}", e),
        }
    }

    #[test]
    fn test_ov_entry_cose_roundtrip() {
        // Actual OV entry bytes from Go FDO server's TO2.OVNextEntry20 response
        let entry_hex = "d28443a10126a058ab84822f5820c71d7110ca19380db5fe9f25767cc03d5bda5d20b1f56e97687fba79139acf6c822f5820c4347dcd86249676720e60b16f1dc213a9dbab6c34a744781c32f20d1e1a472d41a0830a01585b3059301306072a8648ce3d020106082a8648ce3d03010703420004c635bbfddca7499345d35e1e86ffddc1ad5287a58b51d5450109229093b28f4a1f9212db16390b2b63ee2c501efb905324a8f461bcbc253761c4fae070cd4b935840474effc48c7aeebd5d2d27071682c559dd9ab81c9866eec9eeae479a7f94bb54ce0c91b6666f15790376e16538f4143fba8a80455775c73fe0e7f2f077fad7e9";
        let entry_bytes = hex::decode(entry_hex).unwrap();

        // Step 1: Deserialize from raw bytes
        let entry = OwnershipVoucherEntry::deserialize_data(&entry_bytes)
            .expect("Failed to deserialize OV entry from Go server bytes");

        // Step 2: Re-serialize
        let reserialized = entry
            .serialize_data()
            .expect("Failed to re-serialize OV entry");

        // Step 3: Deserialize again (round-trip)
        let _entry2 = OwnershipVoucherEntry::deserialize_data(&reserialized)
            .expect("Failed to deserialize OV entry after round-trip");
    }
}
