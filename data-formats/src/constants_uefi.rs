// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause
//
// UEFI-compatible FDO constants (no_std)

use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, PartialEq, Eq, PartialOrd)]
#[repr(u16)]
#[non_exhaustive]
pub enum ProtocolVersion {
    Version1_0 = 100,
    Version1_1 = 101,
    Version2_0 = 200,
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

impl HashType {
    pub fn digest_size(&self) -> usize {
        match self {
            HashType::Sha256 | HashType::HmacSha256 => 32,
            HashType::Sha384 | HashType::HmacSha384 => 48,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum MessageType {
    // TO1 messages (30-33)
    TO1HelloRV = 30,
    TO1HelloRVAck = 31,
    TO1ProveToRV = 32,
    TO1RVRedirect = 33,

    // TO2 messages - FDO 2.0 (80-91)
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

    // Error
    Error = 255,
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum RendezvousVariable {
    DeviceOnly = 0,
    OwnerOnly = 1,
    IPAddress = 2,
    DevicePort = 3,
    OwnerPort = 4,
    Dns = 5,
    ServerCertHash = 6,
    CaCertHash = 7,
    UserInput = 8,
    WifiSsid = 9,
    WifiPw = 10,
    Medium = 11,
    Protocol = 12,
    Delaysec = 13,
    Bypass = 14,
}

// Device signature types (COSE algorithm IDs)
#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr, PartialEq, Eq)]
#[repr(i16)]
#[non_exhaustive]
pub enum DeviceSigType {
    ES256 = -7,   // ECDSA w/ SHA-256
    ES384 = -35,  // ECDSA w/ SHA-384
    RS256 = -257, // RSASSA-PKCS1-v1_5 w/ SHA-256
    RS384 = -258, // RSASSA-PKCS1-v1_5 w/ SHA-384
}
