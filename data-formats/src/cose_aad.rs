// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause

//! COSE_Sign1 domain separation via external_aad.
//!
//! Provides pre-computed AAD constants and helpers for building
//! COSE Sig_structure with external_aad, following the FDO 2.0
//! domain separation convention (RFC 9052 Section 4.3).
//!
//! Each AAD value is the CBOR encoding of:
//!   FDOExternalAAD = [FDODomainTag]
//!   FDODomainTag = tstr

use serde_bytes::ByteBuf;

use crate::errors::Error;

/// Compute the CBOR encoding of [tag] (a one-element CBOR array of tstr).
/// This matches the Go FDO server's `mustEncodeDomainAAD`.
fn encode_domain_aad(tag: &str) -> Vec<u8> {
    serde_cbor::to_vec(&vec![tag]).expect("CBOR encoding of AAD tag must succeed")
}

// AAD constants matching go-fdo/cose/aad.go

/// TO0.OwnerSign (to1d) and OV entry signing
pub fn aad_owner_sign() -> Vec<u8> {
    encode_domain_aad("FDO-TO0-OwnerSign-v1")
}

/// TO1.ProveToRV
pub fn aad_prove_to_rv() -> Vec<u8> {
    encode_domain_aad("FDO-TO1-ProveToRV-v1")
}

/// TO2.ProveDevice / TO2.ProveDevice20
pub fn aad_prove_device() -> Vec<u8> {
    encode_domain_aad("FDO-TO2-ProveDevice-v1")
}

/// TO2.ProveOVHdr / TO2.ProveOVHdr20
pub fn aad_prove_ov_hdr() -> Vec<u8> {
    encode_domain_aad("FDO-TO2-ProveOVHdr-v1")
}

/// Ownership Voucher entry
pub fn aad_ov_entry() -> Vec<u8> {
    encode_domain_aad("FDO-OVEntry-v1")
}

/// Build a COSE Sig_structure for Sign1 with external_aad.
///
/// Produces: `["Signature1", body_protected, external_aad, payload]`
/// encoded as a CBOR array (RFC 9052 Section 4.4).
///
/// For COSE_Sign1, the `sign_protected` field is omitted (per RFC 9052),
/// so the structure is 4 elements, not 5.
pub fn sig1_structure_bytes(
    body_protected: &[u8],
    external_aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, Error> {
    let structure = (
        "Signature1",
        ByteBuf::from(body_protected.to_vec()),
        ByteBuf::from(external_aad.to_vec()),
        ByteBuf::from(payload.to_vec()),
    );
    Ok(serde_cbor::to_vec(&structure)?)
}

/// Serialize a protected header map containing just the signature algorithm.
/// Replicates the crate-private `map_to_empty_or_serialized` from aws-nitro-enclaves-cose.
pub fn serialize_protected_header(sig_alg_cbor_id: i8) -> Result<Vec<u8>, Error> {
    use std::collections::BTreeMap;
    let mut map = BTreeMap::new();
    map.insert(
        serde_cbor::Value::Integer(1),
        serde_cbor::Value::Integer(sig_alg_cbor_id as i128),
    );
    Ok(serde_cbor::to_vec(&map)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aad_encoding() {
        // The Go server encodes ["FDO-TO1-ProveToRV-v1"] as CBOR array of 1 tstr.
        // Verify we produce valid CBOR.
        let aad = aad_prove_to_rv();
        let decoded: Vec<String> = serde_cbor::from_slice(&aad).unwrap();
        assert_eq!(decoded, vec!["FDO-TO1-ProveToRV-v1"]);
    }

    #[test]
    fn test_sig1_structure() {
        let protected = vec![0xa1, 0x01, 0x26]; // {1: -7} (ES256)
        let aad = b"test-aad";
        let payload = b"test-payload";

        let result = sig1_structure_bytes(&protected, aad, payload).unwrap();
        // Should be a 4-element CBOR array: ["Signature1", h'a10126', h'746573742d616164', h'746573742d7061796c6f6164']
        let decoded: (String, ByteBuf, ByteBuf, ByteBuf) = serde_cbor::from_slice(&result).unwrap();
        assert_eq!(decoded.0, "Signature1");
        assert_eq!(decoded.1.as_ref(), &protected);
        assert_eq!(decoded.2.as_ref(), aad);
        assert_eq!(decoded.3.as_ref(), payload);
    }

    #[test]
    fn test_protected_header_es256() {
        let header = serialize_protected_header(-7).unwrap(); // ES256
        assert_eq!(header, vec![0xa1, 0x01, 0x26]);
    }

    #[test]
    fn test_protected_header_es384() {
        let header = serialize_protected_header(-35).unwrap(); // ES384
        assert_eq!(header, vec![0xa1, 0x01, 0x38, 0x22]);
    }
}
