// Copyright (c) 2021, Red Hat, Inc.
// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause

use std::{borrow::Borrow, env, fs, path::PathBuf, process::Command, thread, time};

use anyhow::{anyhow, bail, Context, Result};
use rand::Rng;
use thiserror::Error;

use fdo_data_formats::{
    cborparser::ParsedArray,
    constants::{
        DeviceSigType, ErrorCode, MessageType, RendezvousProtocolValue, TransportProtocol,
    },
    enhanced_types::{RendezvousInterpretedDirective, RendezvousInterpreterSide},
    messages,
    ownershipvoucher::{OwnershipVoucher, OwnershipVoucherHeader},
    types::{
        new_eat, COSESign, CipherSuite, EATokenPayload, HMac, KexSuite, KeyDeriveSide, KeyExchange,
        Nonce, PayloadCreating, SigInfo, TO1DataPayload, TO2AddressEntry, UnverifiedValue,
    },
    DeviceCredential, ProtocolVersion, Serializable,
};
use fdo_http_wrapper::client::{RequestResult, ServiceClient};
use fdo_util::device_credential_locations;
use fdo_util::device_credential_locations::UsableDeviceCredentialLocation;

mod serviceinfo;

/// No-op credential location for TPM-backed credentials.
/// Deactivation is handled by writing DCActive=0x00 to NV.
struct TpmCredentialLocation;

impl std::fmt::Debug for TpmCredentialLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TpmCredentialLocation(NV)")
    }
}

impl device_credential_locations::DeviceCredentialLocation for TpmCredentialLocation {
    fn resolve(&self) -> Option<Result<Box<dyn UsableDeviceCredentialLocation>, anyhow::Error>> {
        Some(Ok(Box::new(TpmCredentialLocation)))
    }
}

impl UsableDeviceCredentialLocation for TpmCredentialLocation {
    fn read(&self) -> Result<Box<dyn DeviceCredential>, anyhow::Error> {
        unreachable!("TPM credentials are loaded separately")
    }

    fn deactivate(&self) -> Result<(), anyhow::Error> {
        // For TPM credentials, deactivation means setting DCActive to 0x00.
        // For credential reuse, we skip deactivation.
        log::info!("TPM credential deactivation (no-op for credential reuse)");
        Ok(())
    }
}

const DEVICE_ONBOARDING_EXECUTED_MARKER_FILE: &str = "/etc/device_onboarding_performed";

fn marker_file_location() -> PathBuf {
    if let Ok(path) = env::var("DEVICE_ONBOARDING_EXECUTED_MARKER_FILE_PATH") {
        PathBuf::from(path)
    } else {
        PathBuf::from(DEVICE_ONBOARDING_EXECUTED_MARKER_FILE)
    }
}

// Rendezvous delays related variables
const RV_DEFAULT_DELAY_SEC: f32 = 120.0;
const RV_DEFAULT_DELAY_OFFSET: f32 = 30.0;
const RV_USER_DEFINED_DELAY_OFFSET: f32 = 0.25;

// Encapsulates errors caused during TO1/TO2
#[derive(Debug)]
struct ErrorResult {
    e_code: ErrorCode,
    e_string: &'static str,
    message: MessageType,
    error: anyhow::Error,
}

impl ErrorResult {
    fn new(
        e_code: ErrorCode,
        e_string: &'static str,
        message: MessageType,
        error: anyhow::Error,
    ) -> Self {
        ErrorResult {
            e_code,
            e_string,
            message,
            error,
        }
    }
}

#[derive(Error, Debug)]
enum ClientError {
    #[error("Error in the response result")]
    Response(ErrorResult),
    #[error("Error with the request")]
    Request(ErrorResult),
}

async fn send_client_error(
    client: &mut fdo_http_wrapper::client::ServiceClient,
    error: &ErrorResult,
) {
    let message = messages::v11::ErrorMessage::new(
        error.e_code,
        error.message,
        error.e_string.to_string(),
        uuid::Uuid::new_v4().as_u128(),
    );
    log::trace!("{:?}", &message);
    let _: RequestResult<messages::v11::ErrorMessage> = client.send_request(message, None).await;
}

fn mark_device_onboarding_executed() -> Result<()> {
    fs::write(marker_file_location(), "executed").context("Error creating executed marker file")
}

fn get_to2_urls(entries: &[TO2AddressEntry]) -> Vec<String> {
    let mut urls = Vec::new();

    for addr_entry in entries {
        let prot_text = match addr_entry.protocol() {
            TransportProtocol::Http => "http",
            TransportProtocol::Https => "https",
            _ => continue,
        };
        if let Some(dns_name) = addr_entry.dns() {
            urls.push(format!(
                "{}://{}:{}",
                prot_text,
                dns_name,
                addr_entry.port()
            ));
        }
        if let Some(ip_address) = addr_entry.ip() {
            urls.push(format!(
                "{}://{}:{}",
                prot_text,
                ip_address,
                addr_entry.port()
            ));
        }
    }

    urls
}

async fn get_client_list(rv_entry: &RendezvousInterpretedDirective) -> Result<Vec<ServiceClient>> {
    log::trace!("Getting client list from rv_entry {:?}", rv_entry);
    let mut service_client_list = Vec::new();

    let urls = rv_entry.get_urls();
    if urls.is_empty() {
        log::trace!("No URLs found");
    }
    if rv_entry.bypass {
        bail!("Rendezvous Bypass is not yet implemented");
    }
    if rv_entry.wifi_ssid.is_some() {
        bail!("Rendezvous WiFi configuration is not yet implemented");
    }
    if rv_entry.user_input {
        bail!("Rendezvous User Input is not yet implemented");
    }
    if rv_entry.protocol != RendezvousProtocolValue::Http
        && rv_entry.protocol != RendezvousProtocolValue::Https
    {
        bail!("Non-HTTP(S) protocol is not implemented");
    }
    for url in &urls {
        service_client_list.push(fdo_http_wrapper::client::ServiceClient::new(
            ProtocolVersion::Version2_0,
            url,
        ));
    }
    log::trace!("Client list: {:?}", service_client_list);
    Ok(service_client_list)
}

/// TO1: Sends HelloRV (with CapabilityFlags), Receives HelloRVAck, creates EAT token
async fn perform_hellorv(
    devcred: &dyn DeviceCredential,
    client: &mut ServiceClient,
) -> Result<COSESign, ClientError> {
    use fdo_data_formats::types::CapabilityFlags;

    let sig_type = DeviceSigType::StSECP384R1;

    let hello_rv = messages::v20::to1::HelloRV::new(
        devcred.device_guid().clone(),
        SigInfo::new(sig_type, vec![]),
        CapabilityFlags::new_v20_client(),
    );
    let hello_rv_ack: RequestResult<messages::v20::to1::HelloRVAck> =
        client.send_request(hello_rv, None).await;
    let hello_rv_ack = hello_rv_ack.context("Error sending HelloRV").map_err(|e| {
        ClientError::Request(ErrorResult::new(
            ErrorCode::InternalServerError,
            "Error sending HelloRV",
            MessageType::TO1HelloRV,
            e,
        ))
    })?;
    log::trace!("HelloRVAck: {:?}", hello_rv_ack);

    let b_sig_info = hello_rv_ack.b_signature_info();
    if b_sig_info.sig_type() != sig_type {
        return Err(ClientError::Response(ErrorResult::new(
            ErrorCode::InvalidMessageError,
            "Unsupported sig type returned",
            MessageType::TO1HelloRVAck,
            anyhow!("Unsupported sig type returned"),
        )));
    }
    let nonce4 = hello_rv_ack.nonce4();

    // Create EAT token signed with device key
    let eat: EATokenPayload<PayloadCreating> =
        new_eat::<bool>(None, nonce4.clone(), devcred.device_guid().clone())
            .context("Error creating EATokenPayload")
            .map_err(|e| {
                ClientError::Request(ErrorResult::new(
                    ErrorCode::InternalServerError,
                    "Error creating EATokenPayload",
                    MessageType::TO1HelloRVAck,
                    e,
                ))
            })?;
    let signer = devcred
        .get_signer()
        .context("Error getting Cose signer")
        .map_err(|e| {
            ClientError::Response(ErrorResult::new(
                ErrorCode::InternalServerError,
                "Error getting Cose signer",
                MessageType::TO1HelloRVAck,
                e,
            ))
        })?;
    let token = COSESign::from_eat_with_aad(
        eat,
        None,
        signer.as_ref(),
        &fdo_data_formats::cose_aad::aad_prove_to_rv(),
    )
    .context("Error signing new token")
    .map_err(|e| {
        ClientError::Response(ErrorResult::new(
            ErrorCode::InternalServerError,
            "Error signing new token",
            MessageType::TO1HelloRVAck,
            e,
        ))
    })?;
    Ok(token)
}

/// TO1: Sends ProveToRV, Receives RVRedirect (TO1D blob)
async fn perform_provetorv(
    token: COSESign,
    client: &mut ServiceClient,
) -> Result<COSESign, ClientError> {
    let prove_to_rv = messages::v20::to1::ProveToRV::new(token);
    let rv_redirect: RequestResult<messages::v20::to1::RVRedirect> =
        client.send_request(prove_to_rv, None).await;
    let rv_redirect = rv_redirect
        .context("Error proving self to rendezvous server")
        .map_err(|e| {
            ClientError::Response(ErrorResult::new(
                ErrorCode::InvalidMessageError,
                "Error proving self to rendezvous server",
                MessageType::TO1RVRedirect,
                e,
            ))
        })?;
    Ok(rv_redirect.into_to1d())
}

async fn perform_to1(
    devcred: &dyn DeviceCredential,
    client: &mut ServiceClient,
) -> Result<COSESign> {
    log::trace!(
        "Starting TO1 with credential {:?} and client {:?}",
        devcred,
        client
    );

    // Send: HelloRV, Receive: HelloRVAck
    let token = match perform_hellorv(devcred, client).await {
        Ok(token) => token,
        Err(e) => match e {
            ClientError::Request(e) => {
                send_client_error(client, &e).await;
                bail!(e.error);
            }
            ClientError::Response(e) => {
                send_client_error(client, &e).await;
                bail!(e.error);
            }
        },
    };

    // Send: ProveToRV, Receive: RVRedirect
    match perform_provetorv(token, client).await {
        Ok(to1d) => Ok(to1d),
        Err(e) => match e {
            ClientError::Request(e) => {
                send_client_error(client, &e).await;
                bail!(e.error);
            }
            ClientError::Response(e) => {
                send_client_error(client, &e).await;
                bail!(e.error);
            }
        },
    }
}

fn get_rv_info(devcred: &dyn DeviceCredential) -> Result<Vec<RendezvousInterpretedDirective>> {
    // Debug: Show raw RV info
    let rv_raw = devcred.rendezvous_info();
    log::info!("Raw RV info directives: {:?}", rv_raw.values());

    let rv_info = rv_raw
        .to_interpreted(RendezvousInterpreterSide::Device)
        .context("Error parsing rendezvous directives")?;
    if rv_info.is_empty() {
        bail!("No rendezvous information found that's usable for the device");
    }
    log::trace!("Rendezvous info: {:?}", rv_info);
    Ok(rv_info)
}

async fn get_to1d(
    devcred: &dyn DeviceCredential,
    mut client_list: Vec<ServiceClient>,
) -> Result<COSESign> {
    for client in client_list.as_mut_slice() {
        match perform_to1(devcred, client)
            .await
            .context("Error performing TO1")
        {
            Ok(to1) => {
                return Ok(to1);
            }
            Err(e) => {
                log::error!("{} with {:?}", e, client);
                continue;
            }
        }
    }
    bail!("Couldn't get TO1 from any Rendezvous server!")
}

// =====================================================================
// FDO 2.0 TO2 Protocol Implementation (Device Proves First)
//
// Flow: HelloDeviceProbe(80) -> HelloDeviceAck20(81) ->
//       ProveDevice20(82) -> ProveOVHdr20(83) ->
//       GetOVNextEntry20(84) -> OVNextEntry20(85) [loop] ->
//       DeviceSvcInfoRdy20(86) -> SetupDevice20(87) [encrypted] ->
//       DeviceSvcInfo20(88) <-> OwnerSvcInfo20(89) [encrypted loop] ->
//       Done20(90) -> DoneAck20(91) [encrypted]
// =====================================================================

async fn get_ov_entries_v20(
    client: &mut ServiceClient,
    num_entries: u16,
) -> Result<ParsedArray<fdo_data_formats::cborparser::ParsedArraySizeDynamic>> {
    let mut entries = ParsedArray::new_empty();

    for entry_num in 0..num_entries {
        let entry_result: RequestResult<messages::v20::to2::OVNextEntry20> = client
            .send_request(
                messages::v20::to2::GetOVNextEntry20::new(entry_num as u8),
                None,
            )
            .await;
        let entry_result =
            entry_result.with_context(|| format!("Error getting OV entry num {entry_num}"))?;

        if entry_result.entry_num() as u16 != entry_num {
            bail!(
                "Owner returned OV entry {}, when we asked for {}",
                entry_result.entry_num(),
                entry_num
            );
        }

        let entry = entry_result.into_entry();
        entries
            .push(&entry)
            .context("Error adding Ownership Voucher entry")?;
    }

    Ok(entries)
}

async fn _get_nonce(message_type: MessageType) -> Result<Nonce, ClientError> {
    Nonce::new().context("Error generating nonce").map_err(|e| {
        ClientError::Response(ErrorResult::new(
            ErrorCode::InternalServerError,
            "Error generating nonce",
            message_type,
            e,
        ))
    })
}

async fn perform_to2(
    devcredloc: &dyn UsableDeviceCredentialLocation,
    devcred: &dyn DeviceCredential,
    url: &str,
    to1d: &COSESign,
) -> Result<bool> {
    use fdo_data_formats::constants::HashType as FdoHashType;
    use fdo_data_formats::types::{
        CapabilityFlags, TO2ProveDevice20Payload, TO2ProveOVHdr20Payload,
    };

    log::info!("Performing TO2 protocol (FDO 2.0), URL: {:?}", url);

    let mut client = fdo_http_wrapper::client::ServiceClient::new(ProtocolVersion::Version2_0, url);

    let kexsuite = KexSuite::Ecdh384;
    let ciphersuite = CipherSuite::A256Gcm;
    let _sigtype = DeviceSigType::StSECP384R1;

    // -------------------------------------------------------
    // Step 1: HelloDeviceProbe(80) -> HelloDeviceAck20(81)
    // -------------------------------------------------------
    let mut sugar = [0u8; 16];
    openssl::rand::rand_bytes(&mut sugar).context("Error generating random sugar")?;

    let hello_probe = messages::v20::to2::HelloDeviceProbe::new(
        devcred.device_guid().clone(),
        CapabilityFlags::new_v20_client(),
        vec![FdoHashType::Sha256 as i8, FdoHashType::Sha384 as i8],
        sugar.to_vec(),
    );

    // Serialize the probe for hash-binding later
    let _hello_probe_bytes = hello_probe
        .serialize_data()
        .context("Error serializing HelloDeviceProbe for hash binding")?;

    let hello_ack: RequestResult<messages::v20::to2::HelloDeviceAck20> =
        client.send_request(hello_probe, None).await;
    let hello_ack = hello_ack.context("Error sending HelloDeviceProbe")?;
    log::trace!("HelloDeviceAck20: {:?}", hello_ack);

    let nonce_to2_prove_dv_prep = hello_ack.nonce_to2_prove_dv_prep().clone();

    // Serialize the ack for hash-binding in ProveDevice20
    let hello_ack_bytes = hello_ack
        .serialize_data()
        .context("Error serializing HelloDeviceAck20 for hash binding")?;

    // -------------------------------------------------------
    // Step 2: ProveDevice20(82) -> ProveOVHdr20(83)
    //         DEVICE PROVES FIRST (key FDO 2.0 change)
    // -------------------------------------------------------

    // Generate device-side key exchange parameter A
    let a_key_exchange =
        KeyExchange::new(kexsuite).context("Error creating device-side key exchange")?;
    let xa_public = a_key_exchange
        .get_public()
        .context("Error getting device key exchange public")?;

    // Compute hash of HelloDeviceAck20 for binding
    let hash_prev2 =
        fdo_data_formats::types::Hash::from_data(FdoHashType::Sha384, &hello_ack_bytes)
            .context("Error computing hash of HelloDeviceAck20")?;

    // Build ProveDevice20 payload.
    // NonceTO2ProveOVPrep echoes the server's NonceTO2ProveDVPrep (anti-replay).
    let prove_device_payload = TO2ProveDevice20Payload::new(
        kexsuite,
        ciphersuite,
        xa_public,
        nonce_to2_prove_dv_prep.clone(), // echo server's nonce
        hash_prev2,
    );

    // FDO 2.0: ProveDevice20 is a plain COSE Sign1 (NOT an EAT).
    // The payload is ProveDevice20Payload directly, not wrapped in EAT claims.
    let signer = devcred
        .get_signer()
        .context("Error getting device signer")?;
    let prove_device_token = COSESign::new_with_aad(
        &prove_device_payload,
        None,
        signer.as_ref(),
        &fdo_data_formats::cose_aad::aad_prove_device(),
    )
    .context("Error signing ProveDevice20")?;

    let prove_device_msg = messages::v20::to2::ProveDevice20::new(prove_device_token);
    let prove_ov_hdr: RequestResult<messages::v20::to2::ProveOVHdr20> =
        client.send_request(prove_device_msg, None).await;
    let prove_ov_hdr = prove_ov_hdr.context("Error sending ProveDevice20")?;
    let prove_ov_hdr = prove_ov_hdr.into_token();

    // Parse the ProveOVHdr20 payload (unverified until we get OV entries)
    let prove_ov_hdr_payload: UnverifiedValue<TO2ProveOVHdr20Payload> = prove_ov_hdr
        .get_payload_unverified()
        .context("Error parsing ProveOVHdr20 payload")?;

    log::trace!("ProveOVHdr20 payload: {:?}", prove_ov_hdr_payload);

    // Verify the server echoed our nonce back
    if &nonce_to2_prove_dv_prep
        != prove_ov_hdr_payload
            .get_unverified_value()
            .nonce_to2_prove_ov()
    {
        bail!("Nonce mismatch in ProveOVHdr20");
    }

    // Verify HMAC of ownership voucher header
    {
        let ov_hdr_vec = prove_ov_hdr_payload.get_unverified_value().ov_header();
        let ov_hdr_hmac = prove_ov_hdr_payload.get_unverified_value().hmac();
        devcred
            .verify_hmac(ov_hdr_vec, ov_hdr_hmac)
            .context("Error verifying OV header HMAC")?;
        log::trace!("OV header HMAC validated");
    }

    // Validate manufacturer public key hash
    {
        let header_bytes = prove_ov_hdr_payload.get_unverified_value().ov_header();
        let header = OwnershipVoucherHeader::deserialize_data(header_bytes)
            .context("Error deserializing OV header")?;
        let pubkey_hash = header
            .manufacturer_public_key_hash(devcred.manufacturer_pubkey_hash().get_type())
            .context("Error computing manufacturer pubkey hash")?;
        devcred
            .manufacturer_pubkey_hash()
            .compare(&pubkey_hash)
            .context("Manufacturer public key hash mismatch")?;
    }

    let header_hmac = prove_ov_hdr_payload.get_unverified_value().hmac().clone();

    // -------------------------------------------------------
    // Step 3: GetOVNextEntry20(84) -> OVNextEntry20(85) [loop]
    //         Retrieve and verify full ownership voucher
    // -------------------------------------------------------
    let ov_entries = get_ov_entries_v20(
        &mut client,
        prove_ov_hdr_payload.get_unverified_value().num_ov_entries(),
    )
    .await
    .context("Error getting OV entries")?;

    let ownership_voucher = {
        let header = prove_ov_hdr_payload.get_unverified_value().ov_header();
        OwnershipVoucher::from_parts(ProtocolVersion::Version2_0, header, header_hmac, ov_entries)
    }
    .context("Error reconstructing Ownership Voucher")?;

    log::trace!("Reconstructed ownership voucher: {:?}", ownership_voucher);

    // Validate the full voucher chain
    let ov_owner_entry = ownership_voucher
        .iter_entries()
        .context("Error initializing OV entry iterator")?
        .last()
        .context("Error validating ownership voucher")?
        .context("No OV entries found")?;

    // Determine which key to use for ProveOVHdr20 signature verification.
    // If a delegate chain is present (COSE unprotected header key 258),
    // verify the chain roots at the OV owner and use the delegate leaf key.
    // Otherwise, use the OV owner's key directly.
    #[cfg(feature = "delegate_support")]
    let delegate_pkey: Option<openssl::pkey::PKey<openssl::pkey::Public>> = {
        // Check if header 258 exists (already confirmed above)
        let has_delegate = prove_ov_hdr
            .get_unprotected_raw()
            .contains("has_delegate(258)=true");

        if has_delegate {
            // Parse raw bytes manually since PublicKey Deserialize can't handle Go's X5Chain encoding
            let cose_bytes = prove_ov_hdr
                .serialize_data()
                .context("Error serializing COSE for delegate extraction")?;
            use fdo_data_formats::cborparser::{
                ParsedArray, ParsedArraySize3, ParsedArraySize4, ParsedArraySizeDynamic,
            };
            let cose_arr: ParsedArray<ParsedArraySize4> =
                ParsedArray::deserialize_data(&cose_bytes)?;
            let map_bytes = cose_arr.get_raw(1);
            let map_items: ParsedArray<ParsedArraySizeDynamic> =
                ParsedArray::deserialize_data(map_bytes)?;

            let mut result = None;
            let num_items = map_items.len();
            for idx in (0..num_items).step_by(2) {
                let kb = map_items.get_raw(idx);
                if let Ok(ki) = serde_cbor::from_slice::<i64>(kb) {
                    if ki == 258 && idx + 1 < num_items {
                        let pk_bytes = map_items.get_raw(idx + 1);
                        let pk_arr: ParsedArray<ParsedArraySize3> =
                            ParsedArray::deserialize_data(pk_bytes)?;
                        let body_bytes = pk_arr.get_raw(2);
                        let cert_ders: Vec<serde_bytes::ByteBuf> =
                            serde_cbor::from_slice(body_bytes)?;
                        if let Some(leaf_der) = cert_ders.first() {
                            let leaf_cert = openssl::x509::X509::from_der(leaf_der)?;
                            result = Some(leaf_cert.public_key()?);
                            log::info!(
                                "Delegate chain found ({} certs), using leaf cert key",
                                cert_ders.len()
                            );

                            // Validate root against OV owner
                            if let Some(root_der) = cert_ders.last() {
                                let root_cert = openssl::x509::X509::from_der(root_der)?;
                                if root_cert
                                    .verify(ov_owner_entry.public_key().pkey())
                                    .unwrap_or(false)
                                {
                                    log::info!("Delegate chain root verified against OV owner");
                                } else {
                                    log::warn!("Delegate chain root NOT signed by OV owner");
                                }
                            }

                            // Validate intermediate signatures
                            for ci in 0..cert_ders.len().saturating_sub(1) {
                                let child = openssl::x509::X509::from_der(&cert_ders[ci])?;
                                let parent = openssl::x509::X509::from_der(&cert_ders[ci + 1])?;
                                let parent_key = parent.public_key()?;
                                if !child.verify(&parent_key).unwrap_or(false) {
                                    log::warn!(
                                        "Delegate chain: cert {} not signed by cert {}",
                                        ci,
                                        ci + 1
                                    );
                                }
                            }
                        }
                        break;
                    }
                }
            }
            result
        } else {
            None
        }
    };

    #[cfg(not(feature = "delegate_support"))]
    let delegate_pkey: Option<openssl::pkey::PKey<openssl::pkey::Public>> = None;

    let signature_key: &openssl::pkey::PKeyRef<openssl::pkey::Public> = match &delegate_pkey {
        Some(dpk) => dpk.as_ref(),
        None => ov_owner_entry.public_key().pkey(),
    };

    // Verify ProveOVHdr20 COSE signature
    let _prove_ov_hdr_payload: TO2ProveOVHdr20Payload = prove_ov_hdr
        .get_payload_with_aad(
            signature_key,
            &fdo_data_formats::cose_aad::aad_prove_ov_hdr(),
        )
        .context("Error validating ProveOVHdr20 signature")?;

    // Verify TO1D was signed by current owner (always use OV owner key, not delegate)
    to1d.verify_with_aad(
        ov_owner_entry.public_key().pkey(),
        &fdo_data_formats::cose_aad::aad_owner_sign(),
    )
    .context("Error validating TO1D signature")?;

    log::info!("Ownership voucher validated successfully");

    // -------------------------------------------------------
    // Step 4: Key derivation
    //         In FDO 2.0: device sent xA in ProveDevice20,
    //         server sent xB in ProveOVHdr20. Derive session keys.
    // -------------------------------------------------------
    let non_interoperable_kdf_required = client.non_interoperable_kdf_required().unwrap_or(false);

    let xb_key_exchange = _prove_ov_hdr_payload.xb_key_exchange();
    let new_keys = a_key_exchange
        .derive_key(
            // In FDO 2.0: device sends A, server sends B.
            // Go constructs shared secret as [sharedECDH, B_random, A_random].
            // Using OwnerService side makes Rust put OTHER(B) random first, then OUR(A).
            KeyDeriveSide::OwnerService,
            ciphersuite,
            xb_key_exchange,
            non_interoperable_kdf_required,
        )
        .context("Error performing key derivation")?;
    let new_keys = fdo_http_wrapper::EncryptionKeys::from_derived(ciphersuite, new_keys);

    // -------------------------------------------------------
    // Step 5: DeviceSvcInfoRdy20(86) -> SetupDevice20(87)
    //         ENCRYPTED from here on. No HMAC yet (moved to Done20).
    //         Set encryption keys BEFORE sending (request must be encrypted).
    // -------------------------------------------------------
    client.set_encryption_keys(new_keys);
    let svc_info_rdy = messages::v20::to2::DeviceSvcInfoRdy20::new(None);
    let setup_device: RequestResult<messages::v20::to2::SetupDevice20> =
        client.send_request(svc_info_rdy, None).await;
    let setup_device = setup_device.context("Error sending DeviceSvcInfoRdy20")?;

    log::trace!("SetupDevice20: {:?}", setup_device);

    let nonce_to2_setup_dv = setup_device.nonce_to2_setup_dv().clone();

    // -------------------------------------------------------
    // Step 6: ServiceInfo exchange
    //         DeviceSvcInfo20(88) <-> OwnerSvcInfo20(89) [encrypted loop]
    // -------------------------------------------------------
    let reboot_required = serviceinfo::perform_to2_serviceinfos(&mut client)
        .await
        .context("Error performing ServiceInfo exchange")?;

    log::trace!("ServiceInfo complete, reboot_required: {reboot_required}");

    // -------------------------------------------------------
    // Step 7: Done20(90) -> DoneAck20(91)
    //         HMAC sent HERE (after receiving replacement GUID/RvInfo)
    // -------------------------------------------------------

    // Mark onboarding performed
    mark_device_onboarding_executed().context("Error creating device onboarding marker file")?;

    // Deactivate credential
    devcredloc
        .deactivate()
        .context("Error deactivating device credential")?;

    // Compute replacement HMAC (or None for credential reuse)
    // For credential reuse (-reuse-cred), send None
    let replacement_hmac: Option<HMac> = None;

    let done20 = messages::v20::to2::Done20::new(nonce_to2_setup_dv, replacement_hmac);
    let done_ack: RequestResult<messages::v20::to2::DoneAck20> =
        client.send_request(done20, None).await;
    let done_ack = done_ack.context("Error sending Done20")?;

    // Verify the nonce from ProveDevice20 came back
    if &nonce_to2_prove_dv_prep != done_ack.nonce_to2_prove_ov() {
        bail!("Nonce mismatch in DoneAck20");
    }

    log::info!("TO2 protocol complete (FDO 2.0)");
    Ok(reboot_required)
}

fn get_delay_between_retries(rv_entry_delay: u32) -> u64 {
    let mut rng = rand::thread_rng();
    let rv_delay_sec: f32 = if rv_entry_delay == 0 {
        rng.gen_range(
            RV_DEFAULT_DELAY_SEC - RV_DEFAULT_DELAY_OFFSET
                ..=RV_DEFAULT_DELAY_SEC + RV_DEFAULT_DELAY_OFFSET,
        )
    } else {
        let lower_delay = rv_entry_delay as f32 * (1.0 - RV_USER_DEFINED_DELAY_OFFSET);
        let upper_delay = rv_entry_delay as f32 * (1.0 + RV_USER_DEFINED_DELAY_OFFSET);
        rng.gen_range(lower_delay..=upper_delay)
    };
    rv_delay_sec as u64
}

fn sleep_between_retries(rv_entry_delay: u32) {
    let rv_delay_sec = get_delay_between_retries(rv_entry_delay);
    let sleep_time = time::Duration::from_secs(rv_delay_sec);
    log::trace!("Sleeping for {} seconds", rv_delay_sec);
    thread::sleep(sleep_time);
}

#[tokio::main]
async fn main() -> Result<()> {
    fdo_util::add_version!();
    fdo_http_wrapper::init_logging();

    if !fdo_data_formats::interoperable_kdf_available()
        && std::env::var("ALLOW_NONINTEROPERABLE_KDF").is_err()
    {
        bail!("Provide environment ALLOW_NONINTEROPERABLE_KDF=1 to enable interoperable KDF");
    }

    let marker_file = marker_file_location();
    if marker_file.exists() {
        log::info!(
            "Device Onboarding marker file {:?} exists, not rerunning FDO onboarding",
            marker_file
        );
        return Ok(());
    }

    // Try loading credentials from TPM NV indices first (spec-compliant path).
    // Falls back to filesystem credentials if TPM has no FDO state.
    #[cfg(feature = "tpm_support")]
    let tpm_dc = {
        match fdo_data_formats::tpm::credential::TpmDeviceCredential::load_from_nv() {
            Ok(Some(dc)) => {
                log::info!("Found device credential in TPM NV indices");
                Some(dc)
            }
            Ok(None) => {
                log::debug!("No FDO credentials in TPM, falling back to filesystem");
                None
            }
            Err(e) => {
                log::debug!(
                    "Error reading TPM NV credentials: {:?}, falling back to filesystem",
                    e
                );
                None
            }
        }
    };
    #[cfg(not(feature = "tpm_support"))]
    let tpm_dc: Option<fdo_data_formats::devicecredential::file::FileDeviceCredential> = None;

    // Use TPM credential if available, otherwise fall back to filesystem
    let (dc, devcred_loc): (
        Box<dyn fdo_data_formats::DeviceCredential>,
        Box<dyn UsableDeviceCredentialLocation>,
    ) = if let Some(tpm_cred) = tpm_dc {
        (Box::new(tpm_cred), Box::new(TpmCredentialLocation))
    } else {
        let devcred_location = match device_credential_locations::find() {
            None => {
                log::info!("No usable device credential located, skipping Device Onboarding");
                return Ok(());
            }
            Some(Err(e)) => {
                log::error!("Error opening device credential: {:?}", e);
                return Err(e)
                    .context("Error getting device credential at any of the known locations");
            }
            Some(Ok(dc)) => dc,
        };

        log::info!("Found device credential at {:?}", devcred_location);
        let cred = devcred_location
            .read()
            .context("Error reading device credential")?;
        (cred, devcred_location)
    };

    log::trace!("Device credential: {:?}", dc);

    if !dc.is_active() {
        log::info!("Device credential deactivated, skipping Device Onboarding");
        return Ok(());
    }
    if dc.protocol_version() != ProtocolVersion::Version2_0
        && dc.protocol_version() != ProtocolVersion::Version1_1
        && dc.protocol_version() != ProtocolVersion::Version1_0
    {
        bail!(
            "Device credential protocol version {} not supported (FDO 2.0 only)",
            dc.protocol_version()
        );
    }

    // Get rv entries
    let rv_info = get_rv_info(dc.as_ref())?;

    let mut onboarding_performed = false;
    let mut reboot_si_required = false;
    let mut rv_entry_delay = 0;

    loop {
        for rv_entry in rv_info.iter() {
            rv_entry_delay = rv_entry.delay;

            let client_list = match get_client_list(rv_entry).await {
                Ok(client_list) => client_list,
                Err(e) => {
                    log::error!(
                        "Error {:?} getting usable rendezvous client list from rv_entry {:?}",
                        e,
                        rv_entry
                    );
                    continue;
                }
            };

            // Get owner info
            let to1d = get_to1d(dc.as_ref(), client_list).await;
            let to1d = match to1d {
                Ok(to1d) => to1d,
                Err(e) => {
                    log::error!(
                        "Error {:?} getting usable To1d from rv_entry {:?}",
                        e,
                        rv_entry
                    );
                    continue;
                }
            };

            let to1d_payload: UnverifiedValue<TO1DataPayload> = match to1d.get_payload_unverified()
            {
                Ok(to1d_payload) => to1d_payload,
                Err(e) => {
                    log::trace!(
                        "Error getting TO1 payload unverified {:?} with rv_entry {:?}",
                        e,
                        rv_entry
                    );
                    continue;
                }
            };

            // Contact owner and perform ownership transfer
            let to2_addresses = to1d_payload.get_unverified_value().to2_addresses();
            let to2_addresses = get_to2_urls(to2_addresses);
            log::info!("Got TO2 addresses: {:?}", to2_addresses);

            if to2_addresses.is_empty() {
                log::trace!(
                    "No valid TO2 addresses received with rv_entry {:?}",
                    rv_entry
                );
                continue;
            }

            for to2_address in to2_addresses {
                match perform_to2(devcred_loc.borrow(), dc.as_ref(), &to2_address, &to1d)
                    .await
                    .context("Error performing TO2 ownership protocol")
                {
                    Ok(maybe_reboot) => {
                        onboarding_performed = true;
                        if !reboot_si_required {
                            reboot_si_required = maybe_reboot;
                        }
                        break;
                    }
                    Err(e) => {
                        log::error!("{:?} with TO2 address {}", e, to2_address);
                        continue;
                    }
                }
            }
            if onboarding_performed {
                break;
            }
        }
        if onboarding_performed {
            break;
        } else {
            sleep_between_retries(rv_entry_delay);
        }
    }
    log::info!("Secure Device Onboarding DONE");
    log::info!("Reboot required? {}", reboot_si_required);
    if reboot_si_required {
        Command::new("systemctl")
            .arg("reboot")
            .spawn()
            .expect("Reboot failed")
            .wait()?;
    }
    Ok(())
}
