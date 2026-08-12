// Copyright (c) 2021, Red Hat, Inc.
// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause

use std::convert::TryFrom;
use std::str::FromStr;

use crate::{errors::Result, Error};

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use openssl::hash::MessageDigest;
use serde_repr::{Deserialize_repr, Serialize_repr};

mod serviceinfo_names;

pub use serviceinfo_names::{FdoServiceInfoModule, ServiceInfoModule, StandardServiceInfoModule};

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, PartialEq, Eq, PartialOrd)]
#[repr(u16)]
#[non_exhaustive]
pub enum ProtocolVersion {
    Version1_0 = 100,
    Version1_1 = 101,
    Version2_0 = 200,
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", *self as u16)
    }
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, PartialEq, Eq)]
#[repr(i8)]
#[non_exhaustive]
pub enum HashType {
    Sha256 = -16,
    Sha384 = -43,
    HmacSha256 = 5,
    HmacSha384 = 6,
}

impl FromStr for HashType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "sha256" => Ok(HashType::Sha256),
            "sha384" => Ok(HashType::Sha384),
            _ => Err(Error::InconsistentValue("Invalid digest name")),
        }
    }
}

impl TryFrom<HashType> for MessageDigest {
    type Error = Error;

    fn try_from(ht: HashType) -> Result<MessageDigest> {
        match ht {
            HashType::Sha256 => Ok(MessageDigest::sha256()),
            HashType::Sha384 => Ok(MessageDigest::sha384()),
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }
}

impl HashType {
    pub fn get_md(&self) -> MessageDigest {
        match self {
            HashType::Sha256 => MessageDigest::sha256(),
            HashType::Sha384 => MessageDigest::sha384(),
            HashType::HmacSha256 => MessageDigest::sha256(),
            HashType::HmacSha384 => MessageDigest::sha384(),
        }
    }

    pub fn digest_size(&self) -> usize {
        match self {
            HashType::Sha256 => 32,
            HashType::Sha384 => 48,
            HashType::HmacSha256 => 32,
            HashType::HmacSha384 => 48,
        }
    }

    pub fn inner_hash(&self) -> HashType {
        match self {
            HashType::Sha256 => HashType::Sha256,
            HashType::Sha384 => HashType::Sha384,
            HashType::HmacSha256 => HashType::Sha256,
            HashType::HmacSha384 => HashType::Sha384,
        }
    }
}

impl TryFrom<MessageDigest> for HashType {
    type Error = Error;

    fn try_from(md: MessageDigest) -> Result<HashType> {
        #[allow(clippy::match_single_binding)]
        match md.type_() {
            // TODO
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }
}

const RS256: i16 = -257;
const RS384: i16 = -258;

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, Eq, PartialEq)]
#[repr(i16)]
#[non_exhaustive]
pub enum DeviceSigType {
    StSECP256R1 = (aws_nitro_enclaves_cose::crypto::SignatureAlgorithm::ES256 as i16),
    StSECP384R1 = (aws_nitro_enclaves_cose::crypto::SignatureAlgorithm::ES384 as i16),
    StRSA2048 = RS256,
    StRSA3072 = RS384,
    StEPID10 = 90,
    StEPID11 = 91,
    StEPID20 = 92,
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(i16)]
#[non_exhaustive]
pub enum PublicKeyType {
    Rsa2048RESTR = 1,
    RsaPkcs = 5,
    RsaPss = 6,
    SECP256R1 = 10,
    SECP384R1 = 11,
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
#[non_exhaustive]
pub enum PublicKeyEncoding {
    Crypto = 0,
    X509 = 1,
    X5CHAIN = 2,
    Cosekey = 3,
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
//#[derive(PartialEq, Eq)]
#[repr(i64)]
#[non_exhaustive]
pub enum HeaderKeys {
    EatNonce = 10,

    CUPHNonce = 256,
    CUPHOwnerPubKey = 257,
    CUPHDelegateChain = 258,
    EUPHNonce = -259,

    EatFDO = -257,
}

// EAT UEID claim key = 256 per the EAT specification.
// This is the same numeric value as CUPHNonce, but they live in different
// CBOR maps (EAT payload vs COSE unprotected header), so there's no conflict
// at the wire level. We use a raw constant instead of an enum variant.
pub const EAT_UEID_CLAIM_KEY: i64 = 256;

impl HeaderKeys {
    pub(crate) fn cbor_value(&self) -> serde_cbor::Value {
        serde_cbor::Value::Integer(*self as i128)
    }
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(i64)]
#[non_exhaustive]
pub enum CryptoTypes {
    CoseAES128CBC = -17760703, // IANA Pending
    CoseAES128CTR = -17760704, // IANA Pending
    CoseAES256CBC = -17760705, // IANA Pending
    CoseAES256CTR = -17760706, // IANA Pending
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
#[non_exhaustive]
pub enum TransportProtocol {
    Tcp = 1,
    Tls = 2,
    Http = 3,
    CoAP = 4,
    Https = 5,
    CoAPS = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RendezvousVariable {
    DeviceOnly,
    OwnerOnly,
    IPAddress,
    DevicePort,
    OwnerPort,
    Dns,
    ServerCertHash,
    CaCertHash,
    UserInput,
    WifiSsid,
    WifiPw,
    Medium,
    Protocol,
    Delaysec,
    Bypass,
    //Extended,
    Unknown(u8),
}

impl RendezvousVariable {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => RendezvousVariable::DeviceOnly,
            1 => RendezvousVariable::OwnerOnly,
            2 => RendezvousVariable::IPAddress,
            3 => RendezvousVariable::DevicePort,
            4 => RendezvousVariable::OwnerPort,
            5 => RendezvousVariable::Dns,
            6 => RendezvousVariable::ServerCertHash,
            7 => RendezvousVariable::CaCertHash,
            8 => RendezvousVariable::UserInput,
            9 => RendezvousVariable::WifiSsid,
            10 => RendezvousVariable::WifiPw,
            11 => RendezvousVariable::Medium,
            12 => RendezvousVariable::Protocol,
            13 => RendezvousVariable::Delaysec,
            14 => RendezvousVariable::Bypass,
            other => RendezvousVariable::Unknown(other),
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            RendezvousVariable::DeviceOnly => 0,
            RendezvousVariable::OwnerOnly => 1,
            RendezvousVariable::IPAddress => 2,
            RendezvousVariable::DevicePort => 3,
            RendezvousVariable::OwnerPort => 4,
            RendezvousVariable::Dns => 5,
            RendezvousVariable::ServerCertHash => 6,
            RendezvousVariable::CaCertHash => 7,
            RendezvousVariable::UserInput => 8,
            RendezvousVariable::WifiSsid => 9,
            RendezvousVariable::WifiPw => 10,
            RendezvousVariable::Medium => 11,
            RendezvousVariable::Protocol => 12,
            RendezvousVariable::Delaysec => 13,
            RendezvousVariable::Bypass => 14,
            RendezvousVariable::Unknown(v) => v,
        }
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self, RendezvousVariable::Unknown(_))
    }
}

impl serde::Serialize for RendezvousVariable {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(self.to_u8())
    }
}

impl<'de> serde::Deserialize<'de> for RendezvousVariable {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = u8::deserialize(deserializer)?;
        Ok(RendezvousVariable::from_u8(v))
    }
}

impl RendezvousVariable {
    fn name(&self) -> &'static str {
        match self {
            RendezvousVariable::DeviceOnly => "device-only",
            RendezvousVariable::OwnerOnly => "owner-only",
            RendezvousVariable::IPAddress => "ip-address",
            RendezvousVariable::DevicePort => "device-port",
            RendezvousVariable::OwnerPort => "owner-port",
            RendezvousVariable::Dns => "dns",
            RendezvousVariable::ServerCertHash => "server-cert-hash",
            RendezvousVariable::CaCertHash => "ca-cert-hash",
            RendezvousVariable::UserInput => "user-input",
            RendezvousVariable::WifiSsid => "wifi-ssid",
            RendezvousVariable::WifiPw => "wifi-pw",
            RendezvousVariable::Medium => "medium",
            RendezvousVariable::Protocol => "protocol",
            RendezvousVariable::Delaysec => "delay-sec",
            RendezvousVariable::Bypass => "bypass",
            RendezvousVariable::Unknown(_) => "unknown",
        }
    }

    pub fn value_from_human_to_machine(&self, val: serde_cbor::Value) -> Result<serde_cbor::Value> {
        Ok(match self {
            // These are just markers: their existence means they're true
            RendezvousVariable::DeviceOnly
            | RendezvousVariable::OwnerOnly
            | RendezvousVariable::UserInput
            | RendezvousVariable::Bypass => serde_cbor::Value::Null,

            // These are integers
            RendezvousVariable::DevicePort
            | RendezvousVariable::OwnerPort
            | RendezvousVariable::Delaysec => match val {
                serde_cbor::Value::Integer(i) => serde_cbor::Value::Integer(i),
                _ => return Err(Error::InconsistentValue(self.name())),
            },

            // These are strings
            RendezvousVariable::Dns | RendezvousVariable::WifiSsid | RendezvousVariable::WifiPw => {
                match val {
                    serde_cbor::Value::Text(t) => serde_cbor::Value::Text(t),
                    _ => return Err(Error::InconsistentValue(self.name())),
                }
            }

            // Slightly more complicated values
            RendezvousVariable::Protocol => match val {
                serde_cbor::Value::Text(v) => {
                    serde_cbor::value::to_value(RendezvousProtocolValue::from_str(&v)?)?
                }
                _ => return Err(Error::InconsistentValue("protocol (type)")),
            },

            RendezvousVariable::IPAddress => match val {
                serde_cbor::Value::Text(v) => {
                    let addr = std::net::IpAddr::from_str(&v)
                        .map_err(|_| Error::InconsistentValue(self.name()))?;
                    serde_cbor::Value::Bytes(match addr {
                        std::net::IpAddr::V4(v) => v.octets().to_vec(),
                        std::net::IpAddr::V6(v) => v.octets().to_vec(),
                    })
                }
                _ => return Err(Error::InconsistentValue(self.name())),
            },

            // TODO
            RendezvousVariable::ServerCertHash => {
                return Err(Error::NotImplemented("ServerCertHash"))
            }
            RendezvousVariable::CaCertHash => return Err(Error::NotImplemented("CaCertHash")),
            RendezvousVariable::Medium => return Err(Error::NotImplemented("Medium")),
            RendezvousVariable::Unknown(_) => {
                return Err(Error::NotImplemented("unknown RVVariable"))
            }
        })
    }
}

impl FromStr for RendezvousVariable {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(match &s.to_lowercase()[..] {
            "deviceonly" | "device_only" => RendezvousVariable::DeviceOnly,
            "owneronly" | "owner_only" => RendezvousVariable::OwnerOnly,
            "ipaddress" | "ip_address" | "ip" => RendezvousVariable::IPAddress,
            "deviceport" | "device_port" => RendezvousVariable::DevicePort,
            "ownerport" | "owner_port" => RendezvousVariable::OwnerPort,
            "dns" => RendezvousVariable::Dns,
            "servercerthash" | "server_cert_hash" => RendezvousVariable::ServerCertHash,
            "cacerthash" | "ca_cert_hash" => RendezvousVariable::CaCertHash,
            "userinput" | "user_input" => RendezvousVariable::UserInput,
            "wifissid" | "wifi_ssid" => RendezvousVariable::WifiSsid,
            "wifipw" | "wifi_pw" => RendezvousVariable::WifiPw,
            "medium" => RendezvousVariable::Medium,
            "protocol" => RendezvousVariable::Protocol,
            "delaysec" | "delay_sec" | "delay" => RendezvousVariable::Delaysec,
            "bypass" => RendezvousVariable::Bypass,
            //"extended" => RendezvousVariable::Extended,
            _ => return Err(Error::InconsistentValue("variable-name")),
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum RendezvousProtocolValue {
    Rest = 0,
    Http = 1,
    Https = 2,
    Tcp = 3,
    Tls = 4,
    CoAPTCP = 5,
    CoAPUDP = 6,
}

impl FromStr for RendezvousProtocolValue {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(match &s.to_lowercase()[..] {
            "rest" => RendezvousProtocolValue::Rest,
            "http" => RendezvousProtocolValue::Http,
            "https" => RendezvousProtocolValue::Https,
            "tcp" => RendezvousProtocolValue::Tcp,
            "tls" => RendezvousProtocolValue::Tls,
            "coaptcp" => RendezvousProtocolValue::CoAPTCP,
            "coapudp" => RendezvousProtocolValue::CoAPUDP,
            _ => return Err(Error::InconsistentValue("protocol")),
        })
    }
}

impl RendezvousProtocolValue {
    pub(crate) fn default_port(&self) -> Option<u32> {
        match self {
            RendezvousProtocolValue::Http => Some(80),
            RendezvousProtocolValue::Https => Some(443),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, FromPrimitive, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum MessageType {
    Invalid = 0,

    // Device Initialization
    DIAppStart = 10,
    DISetCredentials = 11,
    DISetHMAC = 12,
    DIDone = 13,
    // Transfer Ownership protocol 0 (TO0)
    TO0Hello = 20,
    TO0HelloAck = 21,
    TO0OwnerSign = 22,
    TO0AcceptOwner = 23,
    // Transfer Ownership protocol 1 (TO1)
    TO1HelloRV = 30,
    TO1HelloRVAck = 31,
    TO1ProveToRV = 32,
    TO1RVRedirect = 33,
    // Transfer Ownership protocol 2 (TO2) - FDO 1.1
    TO2HelloDevice = 60,
    TO2ProveOVHdr = 61,
    TO2GetOVNextEntry = 62,
    TO2OVNextEntry = 63,
    TO2ProveDevice = 64,
    TO2SetupDevice = 65,
    TO2DeviceServiceInfoReady = 66,
    TO2OwnerServiceInfoReady = 67,
    TO2DeviceServiceInfo = 68,
    TO2OwnerServiceInfo = 69,
    TO2Done = 70,
    TO2Done2 = 71,

    // Transfer Ownership protocol 2 (TO2) - FDO 2.0
    TO2HelloDeviceProbe = 80,
    TO2HelloDeviceAck20 = 81,
    TO2ProveDevice20 = 82,
    TO2ProveOVHdr20 = 83,
    TO2GetOVNextEntry20 = 84,
    TO2OVNextEntry20 = 85,
    TO2DeviceSvcInfoRdy20 = 86,
    TO2SetupDevice20 = 87,
    TO2DeviceSvcInfo20 = 88,
    TO2OwnerSvcInfo20 = 89,
    TO2Done20 = 90,
    TO2DoneAck20 = 91,

    // Custom: DIUN
    DIUNConnect = 210,
    DIUNAccept = 211,
    DIUNRequestKeyParameters = 212,
    DIUNProvideKeyParameters = 213,
    DIUNProvideKey = 214,
    DIUNDone = 215,

    // Error
    Error = 255,
}

impl TryFrom<u8> for MessageType {
    type Error = ();

    fn try_from(value: u8) -> std::result::Result<Self, ()> {
        match MessageType::from_u8(value) {
            Some(v) => Ok(v),
            None => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, PartialEq)]
#[repr(u16)]
#[non_exhaustive]
pub enum ErrorCode {
    InvalidOwnershipVoucher = 2,
    InvalidOwnerSignBody = 3,
    InvalidIPAddress = 4,
    InvalidGUID = 5,
    ResourceNotFound = 6,
    MessageBodyError = 100,
    InvalidMessageError = 101,
    CredReuseError = 102,
    InternalServerError = 500,
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, PartialEq, Eq)]
#[repr(i8)]
#[non_exhaustive]
pub enum MfgStringType {
    SerialNumber = 0,
    MACAddress = 1,
}

impl FromStr for MfgStringType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(match &s.to_lowercase()[..] {
            "serialnumber" | "serial_number" => MfgStringType::SerialNumber,
            "macaddress" | "mac_address" => MfgStringType::MACAddress,
            _ => return Err(Error::InconsistentValue("mfg-string-type")),
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, PartialEq, Eq)]
#[repr(i8)]
#[non_exhaustive]
pub enum KeyStorageType {
    FileSystem = 0,
    Tpm = 1,
}

impl FromStr for KeyStorageType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(match &s.to_lowercase()[..] {
            "filesystem" => KeyStorageType::FileSystem,
            "tpm" => KeyStorageType::Tpm,
            _ => return Err(Error::InconsistentValue("storage-type")),
        })
    }
}
