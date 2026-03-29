// Copyright (c) 2021, Red Hat, Inc.
// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use regex::Regex;
use std::io::{BufRead, BufReader};
use std::path::Path;
#[cfg(feature = "tpm_support")]
use std::{convert::TryFrom, convert::TryInto};
use std::{env, fs, str::FromStr};

use fdo_data_formats::{
    constants::{
        HashType, HeaderKeys, KeyStorageType, MfgStringType, PublicKeyEncoding, PublicKeyType,
    },
    devicecredential::{file::KeyStorage, FileDeviceCredential},
    enhanced_types::X5Bag,
    messages,
    publickey::PublicKey,
    types::{
        CborSimpleType, CipherSuite, DeviceMfgInfo, Guid, HMac, Hash, KexSuite, KeyDeriveSide,
        KeyExchange, Nonce, RendezvousInfo,
    },
    ProtocolVersion, Serializable,
};
use fdo_http_wrapper::{
    client::{RequestResult, ServiceClient},
    EncryptionKeys,
};
#[cfg(feature = "tpm_support")]
use openssl::{bn::BigNum, rsa::Rsa};
use openssl::{
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
    x509::{X509NameBuilder, X509ReqBuilder},
};

use fdo_util::{device_credential_locations, device_identification};
#[cfg(feature = "tpm_support")]
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    interface_types::algorithm::HashingAlgorithm,
    structures::PublicBuilder,
    traits::{Marshall, UnMarshall},
};

const DEVICE_CREDENTIAL_FILESYSTEM_PATH: &str = "/etc/device-credentials";

#[derive(Parser, Debug)]
struct MainArguments {
    #[clap(subcommand)]
    command: Option<Commands>,
    #[clap(flatten)]
    noplaindi_default: DefaultToEnvVariables,
}

#[derive(Args, Debug)]
struct DefaultToEnvVariables {}

#[derive(Subcommand, Debug)]
#[clap(group = clap::ArgGroup::new("main_commands").multiple(false))]
enum Commands {
    /// Simple Device Initialization mode, implies insecure DIUN Public Key Verification Mode
    PlainDI(PlainDIArgs),
    /// Allows to choose a DIUN Public Key Verification Mode for Device Initialization
    NoPlainDI(NoPlainDIArgs),
}

#[derive(Args, Debug)]
struct PlainDIArgs {
    /// URL of the manufacturing server
    #[clap(long, short)]
    manufacturing_server_url: String,

    /// Device Identification string type.
    /// Available values: SerialNumber or MACAddress (requires iface selection with --iface).
    #[clap(long)]
    mfg_string_type: MfgStringType,
    /// iface name for the MACAddress Device Identification string type.
    #[clap(long)]
    iface: Option<String>,

    /// Key reference.
    /// Available values: filesystem, tpm.
    #[clap(long)]
    key_ref: String,

    /// FDO protocol version to use (101 for FDO 1.01, 110 for FDO 1.1, 200 for FDO 2.0)
    #[clap(long, default_value = "110")]
    fdo_version: u32,
}

#[derive(Args, Debug)]
#[clap(group = clap::ArgGroup::new("diun_pub_key").multiple(false).required(true))]
struct NoPlainDIArgs {
    /// URL of the manufacturing server.
    #[arg(long, short)]
    manufacturing_server_url: String,

    /// X509 certificate-based DIUN Public Key Verification Mode.
    /// Requires path to certificate.
    #[clap(long, group = "diun_pub_key", value_name = "PATH")]
    rootcerts: Option<String>,
    /// Hash-based DIUN Public Key Verification Mode.
    /// Available values: sha256, sha384.
    #[clap(long, group = "diun_pub_key", value_name = "HASH_TYPE")]
    hash: Option<String>,
    /// Insecure DIUN Public Key Verification Mode.
    #[clap(long, group = "diun_pub_key")]
    insecure: bool,

    /// iface name for the MACAddress Device Identification string type.
    #[clap(long)]
    iface: Option<String>,

    /// FDO protocol version to use (101 for FDO 1.01, 110 for FDO 1.1, 200 for FDO 2.0)
    #[clap(long, default_value = "110")]
    fdo_version: u32,
}

async fn perform_diun(
    client: &mut ServiceClient,
    pub_key_verification: DiunPublicKeyVerificationMode,
) -> Result<(KeyReference, MfgStringType)> {
    log::info!("Performing DIUN");

    let nonce_diun_1 = Nonce::new().context("Error generating diun_nonce_1")?;
    let kexsuite = KexSuite::Ecdh384;
    let ciphersuite = CipherSuite::A256Gcm;
    let key_exchange = KeyExchange::new(kexsuite).context("Error initializing key exchange")?;

    // Send: Connect, Receive: Accept
    let accept: RequestResult<messages::v11::diun::Accept> = client
        .send_request(
            messages::v11::diun::Connect::new(
                nonce_diun_1.clone(),
                kexsuite,
                ciphersuite,
                key_exchange
                    .get_public()
                    .context("Error serializing public key exchange bit")?,
            ),
            None,
        )
        .await;
    let accept = accept.context("Error sending Connect")?.into_token();
    log::debug!("DIUN Accept token: {:?}", accept);
    let diun_pubchain = accept
        .get_unprotected_value::<PublicKey>(HeaderKeys::CUPHOwnerPubKey)
        .context("Error getting diun_pubkey")?
        .context("No DIUN public key provided")?;
    log::debug!("Validating DIUN public chain: {:?}", diun_pubchain);
    let diun_pubchain = diun_pubchain
        .chain()
        .context("Error getting diun_pubkey: no chain")?;

    let non_interoperable_kdf_required = client
        .non_interoperable_kdf_required()
        .ok_or_else(|| anyhow::anyhow!("Error getting non-interoperable KDF requirement"))?;

    let diun_pubkey = match pub_key_verification {
        DiunPublicKeyVerificationMode::Hash(hash) => diun_pubchain.verify_from_digest(&hash),
        DiunPublicKeyVerificationMode::Certs(bag) => diun_pubchain.verify_from_x5bag(&bag),
        DiunPublicKeyVerificationMode::Insecure => {
            diun_pubchain.insecure_verify_without_root_verification()
        }
    }
    .context("Error getting DIUN leaf key")?;
    log::debug!("DIUN public key: {:?}", diun_pubkey);
    let diun_pubkey = diun_pubkey
        .public_key()
        .context("Error getting DIUN public key")?;

    let nonce_diun_1_from_server: Nonce = accept
        .get_protected_value(HeaderKeys::CUPHNonce, &diun_pubkey)
        .context("Error getting nonce from reply")?
        .context("No nonce provided by server")?;
    if nonce_diun_1 != nonce_diun_1_from_server {
        bail!("Nonce from server did not match challenge");
    }
    let accept_payload: messages::v11::diun::AcceptPayload = accept
        .get_payload(&diun_pubkey)
        .context("Error parsing Accept payload")?;
    log::debug!("Accept payload: {:?}", accept_payload);
    let new_keys = key_exchange
        .derive_key(
            KeyDeriveSide::Device,
            ciphersuite,
            accept_payload.key_exchange(),
            non_interoperable_kdf_required,
        )
        .context("Error performing key derivation")?;
    let new_keys = EncryptionKeys::from_derived(ciphersuite, new_keys);
    log::debug!("Derived new keys: {:?}", new_keys);

    let key_parameters: RequestResult<messages::v11::diun::ProvideKeyParameters> = client
        .send_request(
            messages::v11::diun::RequestKeyParameters::new(None),
            Some(new_keys),
        )
        .await;
    let key_parameters = key_parameters.context("Error requesting key parameters")?;
    log::debug!("Key parameters: {:?}", key_parameters);

    let key_ref = KeyReference::get_new_key(
        *key_parameters.key_type(),
        key_parameters.key_storage_types_allowed(),
    )
    .await
    .context("Error getting new key")?;

    let done: RequestResult<messages::v11::diun::Done> = client
        .send_request(
            messages::v11::diun::ProvideKey::new(
                key_ref
                    .get_public_key_as_der()
                    .context("Error getting public key from key reference")?,
                key_ref.get_public_key_storage_type(),
            ),
            None,
        )
        .await;
    let done = done.context("Error sending ProvideKey")?;
    Ok((key_ref, done.mfg_string_type()))
}

async fn perform_di(
    client: &mut ServiceClient,
    key_reference: KeyReference,
    mfg_string_type: MfgStringType,
    iface: Option<String>,
    protocol_version: ProtocolVersion,
) -> Result<()> {
    let mfg_info = get_mfg_info(mfg_string_type, iface)
        .await
        .context("Error building MFG string")?;

    match protocol_version {
        ProtocolVersion::Version2_0 => perform_di_v20(client, key_reference, mfg_info).await,
        _ => perform_di_v11(client, key_reference, mfg_info).await,
    }
}

async fn perform_di_v11(
    client: &mut ServiceClient,
    mut key_reference: KeyReference,
    mfg_info: CborSimpleType,
) -> Result<()> {
    let set_credentials: RequestResult<messages::v11::di::SetCredentials> = client
        .send_request(messages::v11::di::AppStart::new(mfg_info)?, None)
        .await;
    let set_credentials = set_credentials.context("Error sending AppStart")?;
    let ov_header = set_credentials.into_ov_header();
    let ov_header_buf = ov_header
        .serialize_data()
        .context("Error serializing Ownership Voucher header")?;
    let ov_header_hmac = key_reference
        .perform_hmac(&ov_header_buf)
        .context("Error computing HMac over Ownership Voucher Header")?;
    let manufacturer_public_key_hash = ov_header
        .manufacturer_public_key_hash(HashType::Sha384)
        .context("Error getting manufacturer public key hash")?;

    key_reference
        .save_to_credential(
            ov_header.device_info().to_string(),
            ov_header.guid().clone(),
            ov_header.rendezvous_info().clone(),
            manufacturer_public_key_hash,
            ProtocolVersion::Version1_1,
        )
        .context("Error saving key reference to credential")?;

    let done: RequestResult<messages::v11::di::Done> = client
        .send_request(messages::v11::di::SetHMAC::new(ov_header_hmac), None)
        .await;
    done.context("Error sending SetHmac")?;

    Ok(())
}

async fn perform_di_v20(
    client: &mut ServiceClient,
    mut key_reference: KeyReference,
    mfg_info: CborSimpleType,
) -> Result<()> {
    use fdo_data_formats::types::CapabilityFlags;

    // Determine key type from the signing key
    let key_type = key_reference
        .get_public_key_type()
        .context("Error determining public key type")?;

    // Generate a CSR using the device's signing key
    let csr_der = key_reference
        .generate_csr()
        .context("Error generating CSR for DeviceMfgInfo")?;

    // Extract serial number and device info from mfg_info
    let (serial_number, device_info) = match &mfg_info {
        CborSimpleType::Text(s) => (s.clone(), s.clone()),
        _ => ("unknown".to_string(), "unknown".to_string()),
    };

    // Build DeviceMfgInfo matching Go's custom.DeviceMfgInfo
    let device_mfg_info = DeviceMfgInfo::new(
        key_type,
        PublicKeyEncoding::X509,
        serial_number,
        device_info,
        csr_der,
    );

    let capability_flags = CapabilityFlags::new_v20_client();
    let app_start = messages::v20::di::AppStart::new(&device_mfg_info, capability_flags);

    let set_credentials: RequestResult<messages::v20::di::SetCredentials> =
        client.send_request(app_start, None).await;
    let set_credentials = set_credentials.context("Error sending AppStart")?;

    let ov_header = set_credentials.into_ov_header();
    let ov_header_buf = ov_header
        .serialize_data()
        .context("Error serializing Ownership Voucher header")?;
    let ov_header_hmac = key_reference
        .perform_hmac(&ov_header_buf)
        .context("Error computing HMac over Ownership Voucher Header")?;
    let manufacturer_public_key_hash = ov_header
        .manufacturer_public_key_hash(HashType::Sha384)
        .context("Error getting manufacturer public key hash")?;

    key_reference
        .save_to_credential(
            ov_header.device_info().to_string(),
            ov_header.guid().clone(),
            ov_header.rendezvous_info().clone(),
            manufacturer_public_key_hash,
            ProtocolVersion::Version2_0,
        )
        .context("Error saving key reference to credential")?;

    let done: RequestResult<messages::v20::di::Done> = client
        .send_request(messages::v20::di::SetHMAC::new(ov_header_hmac), None)
        .await;
    done.context("Error sending SetHmac")?;

    Ok(())
}

#[derive(Debug, Clone)]
enum DiunPublicKeyVerificationMode {
    Hash(Hash),
    Certs(X5Bag),
    Insecure,
}

impl DiunPublicKeyVerificationMode {
    fn get_from_env() -> Result<Self> {
        if let Ok(rootcerts_path) = env::var("DIUN_PUB_KEY_ROOTCERTS") {
            let bag = get_X5Bag_from_rootcerts_path(rootcerts_path)?;
            Ok(DiunPublicKeyVerificationMode::Certs(bag))
        } else if let Ok(hash) = env::var("DIUN_PUB_KEY_HASH") {
            Ok(DiunPublicKeyVerificationMode::Hash(
                Hash::from_str(&hash).context("Error parsing DIUN_PUB_KEY_HASH as hash")?,
            ))
        } else if env::var("DIUN_PUB_KEY_INSECURE").is_ok() {
            Ok(DiunPublicKeyVerificationMode::Insecure)
        } else {
            bail!("No DIUN root key verification variables set")
        }
    }
}

#[allow(non_snake_case)]
fn get_X5Bag_from_rootcerts_path(rootcerts_path: String) -> Result<X5Bag> {
    let certs = fs::read(rootcerts_path).context("Error reading DIUN_PUB_KEY_ROOTCERTS")?;
    let certs = openssl::x509::X509::stack_from_pem(&certs)
        .context("Error parsing DIUN_PUB_KEY_ROOTCERTS as X509 stack")?;
    X5Bag::with_certs(certs).context("Error building DIUN_PUB_KEY_ROOTCERTS bag")
}

#[tokio::main]
async fn main() -> Result<()> {
    fdo_util::add_version!();
    fdo_http_wrapper::init_logging();

    match device_credential_locations::find() {
        None => {
            log::info!("No usable device credential located, performing Device Onboarding");
        }
        Some(Err(e)) => {
            log::error!("Error opening device credential: {:?}", e);
            return Err(e).context("Error getting device credential at any of the known locations");
        }
        Some(Ok(dc)) => {
            log::info!("Found device credential at {:?}", dc);
            let dc = dc.read().context("Error reading device credential")?;
            log::trace!("Device credential: {:?}", dc);

            if dc.is_active() {
                log::info!("Device credential already active");
                return Ok(());
            }
        }
    };

    let url: String;
    let diun_pub_key_verification: DiunPublicKeyVerificationMode;
    let mfg_string_type: MfgStringType;
    let keyref: KeyReference;
    let mut iface: Option<String> = None;
    let mut client: ServiceClient;
    let protocol_ver: ProtocolVersion;

    let args: MainArguments = clap::Parser::parse();
    if let Some(command) = args.command {
        log::debug!("Handling commands");
        match command {
            Commands::PlainDI(args) => {
                url = args.manufacturing_server_url;

                mfg_string_type = args.mfg_string_type;
                if mfg_string_type == MfgStringType::MACAddress {
                    // user provided iface
                    if args.iface.is_some() {
                        iface = args.iface;
                    } else {
                        // If user has not selected any specific iface then default iface will be used
                        match get_default_network_iface() {
                            Ok(Some(result)) => {
                                iface = Some(result);
                                log::info!("Default network interface found: {iface:#?}");
                            }
                            Err(error) => {
                                bail!("Error retrieving default network interface: {error}");
                            }
                            Ok(None) => {
                                bail!("Error retrieving default network interface, unknown reason");
                            }
                        }
                    }
                }

                keyref = KeyReference::str_key(args.key_ref)
                    .await
                    .context("Error determining key for DI")?;

                // Convert fdo_version to ProtocolVersion
                let protocol_version = match args.fdo_version {
                    101 => ProtocolVersion::Version1_0,
                    110 => ProtocolVersion::Version1_1,
                    200 => ProtocolVersion::Version2_0,
                    _ => bail!(
                        "Invalid FDO version: {}. Valid values are 101, 110, or 200",
                        args.fdo_version
                    ),
                };
                client = ServiceClient::new(protocol_version, &url);
                protocol_ver = protocol_version;
            }
            Commands::NoPlainDI(args) => {
                url = args.manufacturing_server_url;

                if let Some(rootcerts) = args.rootcerts {
                    let bag = get_X5Bag_from_rootcerts_path(rootcerts)?;
                    diun_pub_key_verification = DiunPublicKeyVerificationMode::Certs(bag);
                } else if let Some(input_hash) = args.hash {
                    let hash = Hash::from_str(&input_hash)
                        .context(format!("Error parsing '{input_hash}' as hash"))?;
                    diun_pub_key_verification = DiunPublicKeyVerificationMode::Hash(hash);
                } else if args.insecure {
                    diun_pub_key_verification = DiunPublicKeyVerificationMode::Insecure;
                } else {
                    bail!("No DIUN root key verification methods set");
                }

                log::debug!("Performing DIUN");

                // Convert fdo_version to ProtocolVersion
                let protocol_version = match args.fdo_version {
                    101 => ProtocolVersion::Version1_0,
                    110 => ProtocolVersion::Version1_1,
                    200 => ProtocolVersion::Version2_0,
                    _ => bail!(
                        "Invalid FDO version: {}. Valid values are 101, 110, or 200",
                        args.fdo_version
                    ),
                };
                client = ServiceClient::new(protocol_version, &url);
                protocol_ver = protocol_version;

                (keyref, mfg_string_type) = perform_diun(&mut client, diun_pub_key_verification)
                    .await
                    .context("Error performing DIUN")?;
                if mfg_string_type == MfgStringType::MACAddress {
                    // user provided iface
                    if args.iface.is_some() {
                        iface = args.iface;
                    } else {
                        // If user has not selected any specific iface then default iface will be used
                        match get_default_network_iface() {
                            Ok(Some(result)) => {
                                iface = Some(result);
                                log::info!("Default network interface found: {iface:#?}");
                            }
                            Err(error) => {
                                bail!("Error retrieving default network interface: {error}");
                            }
                            Ok(None) => {
                                bail!("Error retrieving default network interface, unknown reason");
                            }
                        }
                    }
                }
            }
        }
    } else {
        log::debug!("Reading env variables by default");

        url = env::var("MANUFACTURING_SERVER_URL")
            .context("Please provide MANUFACTURING_SERVER_URL")?;

        // Parse FDO version from environment (defaults to 1.1)
        let fdo_version: u32 = env::var("FDO_VERSION")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(110);
        protocol_ver = match fdo_version {
            101 => ProtocolVersion::Version1_0,
            110 => ProtocolVersion::Version1_1,
            200 => ProtocolVersion::Version2_0,
            _ => bail!(
                "Invalid FDO_VERSION: {}. Valid values are 101, 110, or 200",
                fdo_version
            ),
        };
        client = ServiceClient::new(protocol_ver, &url);

        let use_plain_di = match env::var("USE_PLAIN_DI") {
            Ok(val) => val == "true",
            Err(_) => false,
        };

        diun_pub_key_verification = if use_plain_di {
            DiunPublicKeyVerificationMode::Insecure
        } else {
            DiunPublicKeyVerificationMode::get_from_env()
                .context("Error determining how to verify DIUN public key")?
        };
        if use_plain_di {
            let env_mfg_string_type =
                env::var("DI_MFG_STRING_TYPE").unwrap_or_else(|_| String::from("serialnumber"));
            mfg_string_type = MfgStringType::from_str(&env_mfg_string_type).with_context(|| {
                format!("Unsupported MFG string type {env_mfg_string_type} requested")
            })?;
            if mfg_string_type == MfgStringType::MACAddress {
                iface = match env::var("DI_MFG_STRING_TYPE_MAC_IFACE") {
                    Ok(iface) => Some(iface),
                    Err(_) => match get_default_network_iface() {
                        Ok(Some(result)) => {
                            log::info!("Default network interface found: {result:#?}");
                            Some(result)
                        }
                        Err(error) => {
                            bail!("Error determining default network interface: {error}");
                        }
                        Ok(None) => {
                            bail!("Error determining default network interface, reason unknown");
                        }
                    },
                };
            }
            keyref = KeyReference::env_key()
                .await
                .context("Error determining key for DI")?;
        } else {
            // For !use_plain_di we also need to get the iface if given it to us
            // since the mfg_string_type will be determined in the manufacturing server
            // and it might request MACAddress as the mfg_string_type. What it cannot do
            // is select the iface for the client, so we must set it ahead of time.
            // This can be by setting DI_MFG_STRING_TYPE_MAC_IFACE env variable to required interface
            // or else default active network interface will be assigned.
            if let Ok(iface_var) = env::var("DI_MFG_STRING_TYPE_MAC_IFACE") {
                iface = Some(iface_var);
            }
            (keyref, mfg_string_type) = perform_diun(&mut client, diun_pub_key_verification)
                .await
                .context("Error performing DIUN")?;
            if mfg_string_type == MfgStringType::MACAddress && iface.is_none() {
                match get_default_network_iface() {
                    Ok(Some(result)) => {
                        iface = Some(result);
                        log::info!("Default network interface found: {iface:#?}");
                    }
                    Err(error) => {
                        bail!("Error retrieving default network interface: {error}");
                    }
                    Ok(None) => {
                        bail!("Error retrieving default network interface, unknown reason");
                    }
                }
            }
        }
    }

    log::debug!(
        "Performing Device Initialization, with key reference {:?} and MFG String Type {:?}",
        &keyref,
        &mfg_string_type
    );

    perform_di(&mut client, keyref, mfg_string_type, iface, protocol_ver)
        .await
        .context("Error performing DI")
}

async fn get_mfg_info(
    mfg_string_type: MfgStringType,
    iface: Option<String>,
) -> Result<CborSimpleType> {
    if let Some(mfg_info) = env::var_os("MANUFACTURING_INFO") {
        return Ok(CborSimpleType::Text(mfg_info.into_string().unwrap()));
    }
    log::debug!("mfg_string_type '{mfg_string_type:?}' requested");
    let mfg_iden = match mfg_string_type {
        MfgStringType::SerialNumber => {
            fs::read_to_string("/sys/devices/virtual/dmi/id/product_serial")
                .or_else(|_| fs::read_to_string("/sys/devices/virtual/dmi/id/chassis_serial"))
                .context("Error determining system serial number")?
        }
        MfgStringType::MACAddress => {
            let given_iface = iface.context("No iface provided")?;
            if !Path::new(&format!("/sys/class/net/{given_iface}")).exists() {
                bail!(format!("The iface '{given_iface}' is not available"));
            }
            let mac = fs::read_to_string(format!("/sys/class/net/{given_iface}/address"))
                .context("Error reading MAC address")?;
            let mac = mac.as_str().trim();
            let re = Regex::new(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")?;
            if !re.is_match(mac) || mac.eq("00:00:00:00:00:00") {
                bail!(format!(
                    "Invalid MAC address '{mac}' for iface '{given_iface}'"
                ));
            }
            mac.to_string()
        }
        _ => bail!("Unsupported MFG string type {mfg_string_type:?} requested"),
    };
    // check that the identifier is sound
    device_identification::check_device_identifier(&mfg_iden)?;
    Ok(CborSimpleType::Text(mfg_iden))
}

/// Extract the CertificationRequestInfo (TBS) bytes from a DER-encoded CSR.
/// CSR DER = SEQUENCE { CertificationRequestInfo, SignatureAlgorithm, Signature }
/// Returns the raw DER bytes of the first element (CertificationRequestInfo).
#[cfg(feature = "tpm_support")]
fn extract_tbs_from_csr_der(csr_der: &[u8]) -> Result<Vec<u8>> {
    // The outer structure is a SEQUENCE. We need to skip the SEQUENCE tag+length
    // and then read the first element (which is the CertificationRequestInfo SEQUENCE).
    let (_, content) = parse_der_tag_length(csr_der).context("Error parsing outer CSR SEQUENCE")?;
    let (tbs_len, _) = parse_der_tag_length(content).context("Error parsing TBS element")?;
    // tbs_len is the total length of the TBS element including tag+length
    Ok(content[..tbs_len].to_vec())
}

/// Parse a DER tag+length, return (total element size including tag+length, content start).
#[cfg(feature = "tpm_support")]
fn parse_der_tag_length(data: &[u8]) -> Result<(usize, &[u8])> {
    if data.is_empty() {
        bail!("Empty DER data");
    }
    // Skip the tag byte
    let mut pos = 1;
    if pos >= data.len() {
        bail!("DER data too short for length");
    }
    let length_byte = data[pos];
    pos += 1;
    let content_length = if length_byte & 0x80 == 0 {
        // Short form
        length_byte as usize
    } else {
        // Long form
        let num_bytes = (length_byte & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > 4 {
            bail!("Invalid DER length encoding");
        }
        let mut len: usize = 0;
        for _ in 0..num_bytes {
            if pos >= data.len() {
                bail!("DER data too short for length bytes");
            }
            len = (len << 8) | (data[pos] as usize);
            pos += 1;
        }
        len
    };
    let total_element_size = pos + content_length;
    if total_element_size > data.len() {
        bail!("DER element extends past data");
    }
    Ok((total_element_size, &data[pos..]))
}

/// Convert ECDSA (r, s) values to DER-encoded signature.
/// ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
#[cfg(feature = "tpm_support")]
fn ecdsa_sig_to_der(r: &[u8], s: &[u8]) -> Result<Vec<u8>> {
    use openssl::bn::BigNum;
    use openssl::ecdsa::EcdsaSig;

    let r_bn = BigNum::from_slice(r).context("Error creating r BigNum")?;
    let s_bn = BigNum::from_slice(s).context("Error creating s BigNum")?;
    let sig = EcdsaSig::from_private_components(r_bn, s_bn).context("Error creating EcdsaSig")?;
    sig.to_der().context("Error encoding ECDSA sig to DER")
}

/// Assemble a complete CSR DER from TBS bytes, DER-encoded signature, and key info.
/// CertificationRequest ::= SEQUENCE {
///     certificationRequestInfo  CertificationRequestInfo,
///     signatureAlgorithm        AlgorithmIdentifier,
///     signature                 BIT STRING
/// }
#[cfg(feature = "tpm_support")]
fn assemble_csr_der(
    tbs_bytes: &[u8],
    sig_der: &[u8],
    signing_pub: &tss_esapi::structures::Public,
) -> Result<Vec<u8>> {
    // Determine the signature algorithm OID
    let sig_alg_der = match signing_pub {
        tss_esapi::structures::Public::Ecc { parameters, .. } => {
            match parameters.ecc_curve() {
                tss_esapi::interface_types::ecc::EccCurve::NistP256 => {
                    // ecdsa-with-SHA256: OID 1.2.840.10045.4.3.2
                    // SEQUENCE { OID 1.2.840.10045.4.3.2 }
                    vec![
                        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
                    ]
                }
                tss_esapi::interface_types::ecc::EccCurve::NistP384 => {
                    // ecdsa-with-SHA384: OID 1.2.840.10045.4.3.3
                    vec![
                        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03,
                    ]
                }
                _ => bail!("Unsupported curve for CSR assembly"),
            }
        }
        _ => bail!("Unsupported key type for CSR assembly"),
    };

    // BIT STRING wrapping for the signature: 0x03 <length> 0x00 <sig_der>
    let bit_string_content_len = 1 + sig_der.len(); // 0x00 unused-bits byte + sig
    let mut bit_string = vec![0x03];
    encode_der_length(&mut bit_string, bit_string_content_len);
    bit_string.push(0x00); // zero unused bits
    bit_string.extend_from_slice(sig_der);

    // Outer SEQUENCE
    let inner_len = tbs_bytes.len() + sig_alg_der.len() + bit_string.len();
    let mut csr = vec![0x30]; // SEQUENCE tag
    encode_der_length(&mut csr, inner_len);
    csr.extend_from_slice(tbs_bytes);
    csr.extend_from_slice(&sig_alg_der);
    csr.extend_from_slice(&bit_string);

    Ok(csr)
}

/// Encode a DER length value.
#[cfg(feature = "tpm_support")]
fn encode_der_length(buf: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        buf.push(length as u8);
    } else if length < 0x100 {
        buf.push(0x81);
        buf.push(length as u8);
    } else if length < 0x10000 {
        buf.push(0x82);
        buf.push((length >> 8) as u8);
        buf.push(length as u8);
    } else {
        buf.push(0x83);
        buf.push((length >> 16) as u8);
        buf.push((length >> 8) as u8);
        buf.push(length as u8);
    }
}

#[derive(Debug)]
enum KeyReference {
    FileSystem {
        sign_key: PKey<Private>,
        hmac_key: Vec<u8>,
    },
    #[cfg(feature = "tpm_support")]
    SemiTpm {
        tss_context: Box<tss_esapi::Context>,
        primary_handle: tss_esapi::handles::KeyHandle,

        // KeyStorage data
        signing_public: Vec<u8>,
        signing_private: Vec<u8>,
        hmac_public: Vec<u8>,
        hmac_private: Vec<u8>,
    },
    /// Spec-compliant TPM: keys in persistent handles, credentials in NV indices.
    #[cfg(feature = "tpm_support")]
    SpecTpm {
        tss_context: Box<tss_esapi::Context>,
        /// Persistent DAK handle for signing.
        dak_handle: tss_esapi::handles::KeyHandle,
        /// Persistent HMAC key handle.
        hmac_handle: tss_esapi::handles::KeyHandle,
        /// Marshalled public key bytes.
        public_bytes: Vec<u8>,
        /// Whether to use Platform hierarchy for NV (vs Owner).
        use_platform: bool,
        /// DeviceKey Unique String NV handle (for policy session auth).
        dk_us_nv_handle: tss_esapi::handles::NvIndexHandle,
        /// HMAC Unique String NV handle (for policy session auth).
        hmac_us_nv_handle: tss_esapi::handles::NvIndexHandle,
    },
}

#[cfg(feature = "tpm_support")]
fn semi_tpm_hmac_key_template(keytype: PublicKeyType) -> Result<tss_esapi::structures::Public> {
    let hash_algo = match keytype {
        PublicKeyType::SECP256R1 => HashingAlgorithm::Sha256,
        PublicKeyType::SECP384R1 => HashingAlgorithm::Sha384,
        _ => bail!("Unsupported key type {:?}", keytype),
    };
    let primary_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_restricted(false)
        .with_sign_encrypt(true)
        .with_user_with_auth(true)
        .build()
        .context("Error creating object attributes")?;
    PublicBuilder::new()
        .with_object_attributes(primary_attributes)
        .with_public_algorithm(tss_esapi::interface_types::algorithm::PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(
            tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
        )
        .with_keyed_hash_parameters(tss_esapi::structures::PublicKeyedHashParameters::new(
            tss_esapi::structures::KeyedHashScheme::Hmac {
                hmac_scheme: tss_esapi::structures::HmacScheme::new(hash_algo),
            },
        ))
        .with_keyed_hash_unique_identifier(Default::default())
        .build()
        .context("Error creating public template")
}

#[cfg(feature = "tpm_support")]
fn semi_tpm_signing_key_template(key_type: PublicKeyType) -> Result<tss_esapi::structures::Public> {
    let primary_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true)
        .with_sensitive_data_origin(true)
        .with_restricted(false)
        .with_sign_encrypt(true)
        .build()
        .context("Error creating object attributes")?;
    let builder = PublicBuilder::new().with_object_attributes(primary_attributes);

    match key_type {
        PublicKeyType::SECP256R1 | PublicKeyType::SECP384R1 => {
            let (curve, hash_algo) = match key_type {
                PublicKeyType::SECP256R1 => (
                    tss_esapi::interface_types::ecc::EccCurve::NistP256,
                    HashingAlgorithm::Sha256,
                ),
                PublicKeyType::SECP384R1 => (
                    tss_esapi::interface_types::ecc::EccCurve::NistP384,
                    HashingAlgorithm::Sha384,
                ),
                _ => unreachable!(),
            };
            builder
                .with_public_algorithm(tss_esapi::interface_types::algorithm::PublicAlgorithm::Ecc)
                .with_name_hashing_algorithm(
                    tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
                )
                .with_ecc_parameters(tss_esapi::structures::PublicEccParameters::new(
                    tss_esapi::structures::SymmetricDefinitionObject::Null,
                    tss_esapi::structures::EccScheme::EcDsa(
                        tss_esapi::structures::HashScheme::new(hash_algo),
                    ),
                    curve,
                    tss_esapi::structures::KeyDerivationFunctionScheme::Null,
                ))
                .with_ecc_unique_identifier(Default::default())
        }
        _ => bail!("Unsupported key type {:?}", key_type),
    }
    .build()
    .context("Error creating public template")
}

impl KeyReference {
    async fn get_new_key_filesystem(keytype: PublicKeyType) -> Result<Self> {
        let mut hmac_key_buf = [0; 32];
        openssl::rand::rand_bytes(&mut hmac_key_buf).context("Error creating random HMAC key")?;
        let hmac_key_buf = hmac_key_buf;

        match keytype {
            PublicKeyType::SECP256R1 | PublicKeyType::SECP384R1 => {
                let curve_name = match keytype {
                    PublicKeyType::SECP256R1 => Nid::X9_62_PRIME256V1,
                    PublicKeyType::SECP384R1 => Nid::SECP384R1,
                    // This is already filtered above
                    _ => unreachable!(),
                };
                let group =
                    EcGroup::from_curve_name(curve_name).context("Error getting curve group")?;
                let sign_key =
                    PKey::from_ec_key(EcKey::generate(&group).context("Error generating EC key")?)
                        .context("Error creating EC key")?;
                Ok(KeyReference::FileSystem {
                    sign_key,
                    hmac_key: hmac_key_buf.to_vec(),
                })
            }
            _ => bail!("Key type not supported"),
        }
    }

    #[cfg(feature = "tpm_support")]
    async fn get_new_key_tpm(keytype: PublicKeyType) -> Result<Self> {
        let tcti_conf = match tss_esapi::tcti_ldr::TctiNameConf::from_environment_variable() {
            Ok(conf) => conf,
            Err(_) => {
                let kernel_rm = tss_esapi::tcti_ldr::DeviceConfig::from_str("/dev/tpmrm0");
                tss_esapi::tcti_ldr::TctiNameConf::Device(
                    kernel_rm.expect("Error initializing Kernel RM"),
                )
            }
        };
        let mut tss_context =
            tss_esapi::Context::new(tcti_conf).context("Error initializing the TPM context")?;

        let primary_template =
            fdo_data_formats::devicecredential::file::semi_tpm_primary_key_template()
                .context("Error creating TPM Primary Key template")?;
        log::trace!("Primary key template: {:?}", primary_template);
        let signing_template = semi_tpm_signing_key_template(keytype)
            .context("Error creating TPM Signing key template")?;
        log::trace!("Signing key template: {:?}", signing_template);
        let hmac_template =
            semi_tpm_hmac_key_template(keytype).context("Error creating TPM hmac key template")?;
        log::trace!("HMAC key template: {:?}", hmac_template);

        let primary_handle = tss_context
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(
                    tss_esapi::interface_types::resource_handles::Hierarchy::Owner,
                    primary_template,
                    None,
                    None,
                    None,
                    None,
                )
            })
            .context("Error creating primary key")?
            .key_handle;

        let signing_key_result = tss_context
            .execute_with_nullauth_session(|ctx| {
                ctx.create(primary_handle, signing_template, None, None, None, None)
            })
            .context("Error creating signing key")?;
        let hmac_key_result = tss_context
            .execute_with_nullauth_session(|ctx| {
                ctx.create(primary_handle, hmac_template, None, None, None, None)
            })
            .context("Error creating HMAC key")?;

        Ok(Self::SemiTpm {
            tss_context: Box::new(tss_context),
            primary_handle,
            signing_public: signing_key_result
                .out_public
                .marshall()
                .context("Error marshalling Signing Public")?,
            signing_private: signing_key_result.out_private.to_vec(),
            hmac_public: hmac_key_result
                .out_public
                .marshall()
                .context("Error marshalling Hmac Public")?,
            hmac_private: hmac_key_result.out_private.to_vec(),
        })
    }

    /// Spec-compliant TPM key generation: creates primary keys under Endorsement
    /// hierarchy with unique strings, persists to spec-defined handles, provisions
    /// NV indices for credential storage. No file written.
    #[cfg(feature = "tpm_support")]
    async fn get_new_key_tpm_spec(keytype: PublicKeyType) -> Result<Self> {
        use fdo_data_formats::tpm::{self, key, nv, policy};

        let mut ctx = tpm::open_context().context("Error opening TPM context")?;
        let use_platform = false; // Linux userspace: Platform hierarchy locked

        // Step 1: Cleanup any prior FDO state
        nv::cleanup_fdo_state(&mut ctx, use_platform);
        log::info!("Cleaned up prior FDO TPM state");

        // Step 2: Determine curve parameters
        let (curve, hash_alg, coord_size) = match keytype {
            PublicKeyType::SECP256R1 => (
                tss_esapi::interface_types::ecc::EccCurve::NistP256,
                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
                32usize,
            ),
            PublicKeyType::SECP384R1 => (
                tss_esapi::interface_types::ecc::EccCurve::NistP384,
                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha384,
                48usize,
            ),
            _ => bail!("Unsupported key type for spec TPM: {:?}", keytype),
        };

        // Step 3: Generate random unique strings
        let dk_us_size = coord_size * 2; // X + Y
        let mut device_key_us = vec![0u8; dk_us_size];
        openssl::rand::rand_bytes(&mut device_key_us)
            .context("Error generating device key unique string")?;
        let mut hmac_us = [0u8; 32];
        openssl::rand::rand_bytes(&mut hmac_us).context("Error generating HMAC unique string")?;

        // Step 4: Define + write DeviceKey_US NV (Profile B)
        let dk_us_handle = nv::define_nv_space(
            &mut ctx,
            tpm::DEVICE_KEY_US_INDEX,
            dk_us_size,
            tpm::NvProfile::B,
            use_platform,
        )
        .context("Error defining DeviceKey_US NV")?;
        nv::write_nv(&mut ctx, dk_us_handle, &device_key_us, tpm::NvProfile::B)
            .context("Error writing DeviceKey_US NV")?;
        log::debug!("Wrote DeviceKey_US NV ({} bytes)", dk_us_size);

        // Compute DAK auth policy AFTER writing (NV Name now includes WRITTEN flag).
        // Both the trial session and runtime sessions see the same NV state.
        let dk_policy = policy::compute_fdo_auth_policy(&mut ctx, dk_us_handle)
            .context("Error computing DAK auth policy")?;
        log::debug!("Computed DAK auth policy digest (after NV write)");

        // Step 5: Define + write HMAC_US NV (Profile B)
        let hmac_us_handle = nv::define_nv_space(
            &mut ctx,
            tpm::HMAC_US_INDEX,
            32,
            tpm::NvProfile::B,
            use_platform,
        )
        .context("Error defining HMAC_US NV")?;
        nv::write_nv(&mut ctx, hmac_us_handle, &hmac_us, tpm::NvProfile::B)
            .context("Error writing HMAC_US NV")?;
        log::debug!("Wrote HMAC_US NV (32 bytes)");

        // Compute HMAC key auth policy AFTER writing
        let hmac_policy = policy::compute_fdo_auth_policy(&mut ctx, hmac_us_handle)
            .context("Error computing HMAC key auth policy")?;
        log::debug!("Computed HMAC key auth policy digest (after NV write)");

        // Step 7: Create ECC signing key (DAK) with auth policy + persist
        let (dak_transient, public_bytes) =
            key::generate_spec_ec_key(&mut ctx, curve, hash_alg, &device_key_us, Some(&dk_policy))
                .context("Error creating spec ECC key")?;
        key::persist_key(&mut ctx, dak_transient, tpm::DAK_HANDLE)
            .context("Error persisting DAK")?;
        log::info!(
            "DAK persisted to 0x{:08X} (userWithAuth=false)",
            tpm::DAK_HANDLE
        );

        // Step 8: Create HMAC key with auth policy + persist
        let hmac_transient = key::generate_spec_hmac_key(&mut ctx, &hmac_us, Some(&hmac_policy))
            .context("Error creating spec HMAC key")?;
        key::persist_key(&mut ctx, hmac_transient, tpm::HMAC_KEY_HANDLE)
            .context("Error persisting HMAC key")?;
        log::info!(
            "HMAC key persisted to 0x{:08X} (userWithAuth=false)",
            tpm::HMAC_KEY_HANDLE
        );

        // Step 8: Define DCActive NV (Profile A), write 0x00 (DI in progress)
        let dc_active_handle = nv::define_nv_space(
            &mut ctx,
            tpm::DC_ACTIVE_INDEX,
            1,
            tpm::NvProfile::A,
            use_platform,
        )
        .context("Error defining DCActive NV")?;
        nv::write_nv(&mut ctx, dc_active_handle, &[0x00], tpm::NvProfile::A)
            .context("Error writing DCActive NV")?;
        log::debug!("DCActive set to 0x00 (DI in progress)");

        // Step 9: Load persistent handles for use during DI protocol
        let dak_handle = key::load_persistent_signing_key(&mut ctx, tpm::DAK_HANDLE)
            .context("Error loading persistent DAK")?;
        let hmac_handle = key::load_persistent_signing_key(&mut ctx, tpm::HMAC_KEY_HANDLE)
            .context("Error loading persistent HMAC key")?;

        Ok(KeyReference::SpecTpm {
            tss_context: Box::new(ctx),
            dak_handle,
            hmac_handle,
            public_bytes,
            use_platform,
            dk_us_nv_handle: dk_us_handle,
            hmac_us_nv_handle: hmac_us_handle,
        })
    }

    async fn get_new_key(
        keytype: PublicKeyType,
        allowed_storage_types: Option<&[KeyStorageType]>,
    ) -> Result<Self> {
        let allowed_storage_types = match allowed_storage_types {
            Some([]) => {
                bail!("No key storage types allowed")
            }
            Some(storage_types) => storage_types,
            None => &[KeyStorageType::FileSystem],
        };
        for key_storage_type in allowed_storage_types {
            #[allow(clippy::single_match)]
            match *key_storage_type {
                #[cfg(feature = "tpm_support")]
                KeyStorageType::Tpm => match KeyReference::get_new_key_tpm(keytype).await {
                    Ok(keyref) => return Ok(keyref),
                    Err(e) => {
                        log::debug!("Error getting new key from TPM: {:?}", e);
                        continue;
                    }
                },
                #[cfg(not(feature = "tpm_support"))]
                KeyStorageType::Tpm => {
                    log::warn!("TPM key storage requested but tpm_support feature is not enabled");
                    continue;
                }
                KeyStorageType::FileSystem => {
                    match KeyReference::get_new_key_filesystem(keytype).await {
                        Ok(keyref) => return Ok(keyref),
                        Err(e) => {
                            log::debug!("Error creating new filesystem key: {}", e);
                            continue;
                        }
                    }
                }
                _ => {}
            }
        }
        bail!(
            "No usable key storage types found, allowed: {:?}",
            allowed_storage_types
        );
    }

    async fn env_key_filesystem() -> Result<Self> {
        let sign_key_path = env::var("DI_SIGN_KEY_PATH").context("No DI sign key path set")?;
        let hmac_key_path = env::var("DI_HMAC_KEY_PATH").context("No DI HMAC key path set")?;

        let sign_key = fs::read(&sign_key_path)
            .with_context(|| format!("Error reading sign key from {}", &sign_key_path))?;
        let hmac_key = fs::read(&hmac_key_path)
            .with_context(|| format!("Error reading HMAC key from {}", &hmac_key_path))?;

        let sign_key = PKey::private_key_from_der(&sign_key).context("Error loading sign key")?;

        Ok(KeyReference::FileSystem { sign_key, hmac_key })
    }

    async fn env_key() -> Result<Self> {
        let key_storage_type =
            env::var("DI_KEY_STORAGE_TYPE").context("No DI key storage type selected")?;
        let key_storage_type =
            KeyStorageType::from_str(&key_storage_type).context("Invalid storage type")?;

        match key_storage_type {
            KeyStorageType::FileSystem => KeyReference::env_key_filesystem().await,
            #[cfg(feature = "tpm_support")]
            KeyStorageType::Tpm => {
                // Try P-256 first (most broadly supported), fall back to P-384
                match KeyReference::get_new_key_tpm_spec(PublicKeyType::SECP256R1).await {
                    Ok(keyref) => Ok(keyref),
                    Err(e) => {
                        log::info!("P-256 TPM key creation failed ({e:#}), trying P-384");
                        KeyReference::get_new_key_tpm_spec(PublicKeyType::SECP384R1).await
                    }
                }
            }
            #[cfg(not(feature = "tpm_support"))]
            KeyStorageType::Tpm => {
                bail!("TPM support not compiled in (enable tpm_support feature)")
            }
            _ => bail!(format!("Unsupported key storage type {key_storage_type:?}")),
        }
    }

    async fn str_key(key: String) -> Result<Self> {
        let key_storage_type = KeyStorageType::from_str(&key).context("Invalid sroage type")?;
        match key_storage_type {
            KeyStorageType::FileSystem => KeyReference::env_key_filesystem().await,
            #[cfg(feature = "tpm_support")]
            KeyStorageType::Tpm => {
                // Use spec-compliant NV-based TPM storage
                match KeyReference::get_new_key_tpm_spec(PublicKeyType::SECP256R1).await {
                    Ok(keyref) => Ok(keyref),
                    Err(e) => {
                        log::info!("P-256 TPM key creation failed ({e:#}), trying P-384");
                        KeyReference::get_new_key_tpm_spec(PublicKeyType::SECP384R1).await
                    }
                }
            }
            #[cfg(not(feature = "tpm_support"))]
            KeyStorageType::Tpm => {
                bail!("TPM support not compiled in (enable tpm_support feature)")
            }
            _ => bail!(format!("Unsupported key storage type {key_storage_type:?}")),
        }
    }

    fn get_public_key_as_der(&self) -> Result<Vec<u8>> {
        match self {
            KeyReference::FileSystem { sign_key, .. } => sign_key
                .public_key_to_der()
                .context("Error serializing public key"),
            #[cfg(feature = "tpm_support")]
            KeyReference::SemiTpm { signing_public, .. } => {
                let signing_public = tss_esapi::structures::Public::unmarshall(signing_public)
                    .context("Error unmarshalling Public")?;
                match signing_public {
                    tss_esapi::structures::Public::Rsa {
                        parameters, unique, ..
                    } => {
                        let exponent = BigNum::from_u32(parameters.exponent().value())
                            .context("Error converting exponent to BigNum")?;
                        let modulus = BigNum::from_slice(unique.value())
                            .context("Error converting modulus to BigNum")?;
                        Rsa::from_public_components(modulus, exponent)
                            .context("Error creating RSA key")?
                            .public_key_to_der()
                            .context("Error serializing public key")
                    }
                    tss_esapi::structures::Public::Ecc {
                        parameters, unique, ..
                    } => {
                        let curve = match parameters.ecc_curve() {
                            tss_esapi::interface_types::ecc::EccCurve::NistP192 => {
                                Nid::X9_62_PRIME192V1
                            }
                            tss_esapi::interface_types::ecc::EccCurve::NistP224 => Nid::SECP224R1,
                            tss_esapi::interface_types::ecc::EccCurve::NistP256 => {
                                Nid::X9_62_PRIME256V1
                            }
                            tss_esapi::interface_types::ecc::EccCurve::NistP384 => Nid::SECP384R1,
                            tss_esapi::interface_types::ecc::EccCurve::NistP521 => Nid::SECP521R1,
                            _ => bail!("Unsupported ECC curve"),
                        };
                        let curve =
                            EcGroup::from_curve_name(curve).context("Error creating EC group")?;
                        let x = BigNum::from_slice(unique.x())
                            .context("Error converting X coordinate to BigNum")?;
                        let y = BigNum::from_slice(unique.y())
                            .context("Error converting Y coordinate to BigNum")?;

                        EcKey::from_public_key_affine_coordinates(&curve, &x, &y)
                            .context("Error creating EC key")?
                            .public_key_to_der()
                            .context("Error serializing public key")
                    }
                    _ => bail!("Unsupported signing key type"),
                }
            }
            #[cfg(feature = "tpm_support")]
            KeyReference::SpecTpm { public_bytes, .. } => {
                fdo_data_formats::tpm::key::public_key_to_der(public_bytes)
                    .context("Error extracting public key from TPM")
            }
        }
    }

    fn get_public_key_storage_type(&self) -> KeyStorageType {
        match self {
            KeyReference::FileSystem { .. } => KeyStorageType::FileSystem,
            #[cfg(feature = "tpm_support")]
            KeyReference::SemiTpm { .. } => KeyStorageType::Tpm,
            #[cfg(feature = "tpm_support")]
            KeyReference::SpecTpm { .. } => KeyStorageType::Tpm,
        }
    }

    /// Determine the FDO PublicKeyType from the signing key.
    fn get_public_key_type(&self) -> Result<PublicKeyType> {
        match self {
            KeyReference::FileSystem { sign_key, .. } => match sign_key.id() {
                openssl::pkey::Id::EC => {
                    let ec = sign_key.ec_key().context("Error getting EC key")?;
                    match ec.group().curve_name() {
                        Some(Nid::X9_62_PRIME256V1) => Ok(PublicKeyType::SECP256R1),
                        Some(Nid::SECP384R1) => Ok(PublicKeyType::SECP384R1),
                        _ => bail!("Unsupported EC curve"),
                    }
                }
                openssl::pkey::Id::RSA => match sign_key.bits() {
                    2048 => Ok(PublicKeyType::Rsa2048RESTR),
                    _ => Ok(PublicKeyType::RsaPkcs),
                },
                _ => bail!("Unsupported key type"),
            },
            #[cfg(feature = "tpm_support")]
            KeyReference::SemiTpm { signing_public, .. } => {
                let signing_public = tss_esapi::structures::Public::unmarshall(signing_public)
                    .context("Error unmarshalling signing public key")?;
                match signing_public {
                    tss_esapi::structures::Public::Ecc { parameters, .. } => {
                        match parameters.ecc_curve() {
                            tss_esapi::interface_types::ecc::EccCurve::NistP256 => {
                                Ok(PublicKeyType::SECP256R1)
                            }
                            tss_esapi::interface_types::ecc::EccCurve::NistP384 => {
                                Ok(PublicKeyType::SECP384R1)
                            }
                            _ => bail!("Unsupported TPM ECC curve"),
                        }
                    }
                    _ => bail!("Unsupported TPM key type"),
                }
            }
            #[cfg(feature = "tpm_support")]
            KeyReference::SpecTpm { public_bytes, .. } => {
                let signing_public = tss_esapi::structures::Public::unmarshall(public_bytes)
                    .context("Error unmarshalling spec TPM public key")?;
                match signing_public {
                    tss_esapi::structures::Public::Ecc { parameters, .. } => {
                        match parameters.ecc_curve() {
                            tss_esapi::interface_types::ecc::EccCurve::NistP256 => {
                                Ok(PublicKeyType::SECP256R1)
                            }
                            tss_esapi::interface_types::ecc::EccCurve::NistP384 => {
                                Ok(PublicKeyType::SECP384R1)
                            }
                            _ => bail!("Unsupported TPM ECC curve"),
                        }
                    }
                    _ => bail!("Unsupported TPM key type"),
                }
            }
        }
    }

    /// Generate an X.509 Certificate Signing Request (CSR) with CN=device.fdo-rs.
    /// Returns DER-encoded CSR bytes.
    /// The Go server validates the CSR signature, so it must be self-signed
    /// with the device's signing key.
    fn generate_csr(&mut self) -> Result<Vec<u8>> {
        match self {
            KeyReference::FileSystem { sign_key, .. } => {
                let mut name_builder =
                    X509NameBuilder::new().context("Error creating X509 name builder")?;
                name_builder
                    .append_entry_by_text("CN", "device.fdo-rs")
                    .context("Error setting CSR subject CN")?;
                let name = name_builder.build();

                let mut req_builder =
                    X509ReqBuilder::new().context("Error creating X509 request builder")?;
                req_builder
                    .set_subject_name(&name)
                    .context("Error setting CSR subject name")?;
                req_builder
                    .set_pubkey(sign_key)
                    .context("Error setting CSR public key")?;

                // Choose digest based on key type
                let digest = match sign_key.id() {
                    openssl::pkey::Id::EC => {
                        let bits = sign_key.bits();
                        if bits <= 256 {
                            MessageDigest::sha256()
                        } else {
                            MessageDigest::sha384()
                        }
                    }
                    openssl::pkey::Id::RSA => MessageDigest::sha384(),
                    _ => MessageDigest::sha256(),
                };

                req_builder
                    .sign(sign_key, digest)
                    .context("Error signing CSR")?;
                let req = req_builder.build();
                req.to_der().context("Error converting CSR to DER")
            }
            #[cfg(feature = "tpm_support")]
            KeyReference::SemiTpm {
                ref mut tss_context,
                primary_handle,
                signing_public,
                signing_private,
                ..
            } => {
                // For TPM keys, we need to:
                // 1. Build the CSR with the public key
                // 2. Sign the TBS (to-be-signed) portion with the TPM
                //
                // Extract the public key as an OpenSSL PKey for CSR construction
                let signing_pub = tss_esapi::structures::Public::unmarshall(signing_public)
                    .context("Error unmarshalling signing public key")?;

                let (pkey, digest, _hash_algo) = match &signing_pub {
                    tss_esapi::structures::Public::Ecc {
                        parameters, unique, ..
                    } => {
                        let (curve_nid, digest, hash_algo) = match parameters.ecc_curve() {
                            tss_esapi::interface_types::ecc::EccCurve::NistP256 => (
                                Nid::X9_62_PRIME256V1,
                                MessageDigest::sha256(),
                                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
                            ),
                            tss_esapi::interface_types::ecc::EccCurve::NistP384 => (
                                Nid::SECP384R1,
                                MessageDigest::sha384(),
                                tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha384,
                            ),
                            _ => bail!("Unsupported TPM ECC curve for CSR generation"),
                        };
                        let group = EcGroup::from_curve_name(curve_nid)
                            .context("Error creating EC group")?;
                        let x = BigNum::from_slice(unique.x())
                            .context("Error converting X coordinate")?;
                        let y = BigNum::from_slice(unique.y())
                            .context("Error converting Y coordinate")?;
                        let ec_key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)
                            .context("Error creating EC public key")?;
                        let pkey = PKey::from_ec_key(ec_key).context("Error converting to PKey")?;
                        (pkey, digest, hash_algo)
                    }
                    _ => bail!("Unsupported TPM key type for CSR generation"),
                };

                // Build CSR structure with public key (unsigned)
                let mut name_builder =
                    X509NameBuilder::new().context("Error creating X509 name builder")?;
                name_builder
                    .append_entry_by_text("CN", "device.fdo-rs")
                    .context("Error setting CSR subject CN")?;
                let name = name_builder.build();

                let mut req_builder =
                    X509ReqBuilder::new().context("Error creating X509 request builder")?;
                req_builder
                    .set_subject_name(&name)
                    .context("Error setting CSR subject name")?;
                req_builder
                    .set_pubkey(&pkey)
                    .context("Error setting CSR public key")?;

                // Get the TBS (to-be-signed) data by signing with a dummy,
                // then we'll extract the TBS bytes and re-sign with TPM.
                // Unfortunately OpenSSL doesn't expose the TBS directly,
                // so we use a different approach: build the DER manually.

                // Use openssl to get the CSR info (to-be-signed) portion:
                // We sign with a temporary key just to get the DER structure,
                // then we'll replace the signature with the TPM signature.
                //
                // Alternative: use the openssl CSR but with a custom signer.
                // OpenSSL 3.x doesn't make this easy, so we'll build it manually.

                // Get the raw TBS data from an unsigned CSR
                // Method: serialize the CertificationRequestInfo, hash it, sign with TPM
                use openssl::hash::hash;

                // Build CertificationRequestInfo DER bytes using openssl's internal
                // We can get this by building a self-signed CSR and extracting the TBS
                // Actually, the simplest approach: sign with a temp key, extract TBS, re-sign
                let temp_key = {
                    let ec_key = pkey.ec_key().context("Not EC key")?;
                    let group = ec_key.group();
                    let temp_ec = EcKey::generate(group).context("Error generating temp key")?;
                    PKey::from_ec_key(temp_ec).context("Error creating temp PKey")?
                };
                req_builder
                    .sign(&temp_key, digest)
                    .context("Error temp-signing CSR")?;
                let temp_csr_der = req_builder
                    .build()
                    .to_der()
                    .context("Error encoding temp CSR")?;

                // Parse the DER to find the TBS portion (CertificationRequestInfo)
                // CSR DER = SEQUENCE { CertificationRequestInfo, SignatureAlgorithm, Signature }
                // The TBS is the first element of the outer SEQUENCE
                let tbs_bytes = extract_tbs_from_csr_der(&temp_csr_der)
                    .context("Error extracting TBS from CSR DER")?;

                // Hash the TBS
                let tbs_hash = hash(digest, &tbs_bytes).context("Error hashing TBS")?;

                // Load the signing key into TPM and sign
                let signing_handle = tss_context
                    .execute_with_nullauth_session(|ctx| {
                        ctx.load(
                            *primary_handle,
                            signing_private.as_slice().try_into()?,
                            signing_pub.clone(),
                        )
                    })
                    .context("Error loading TPM signing key")?;

                let tpm_digest = tss_esapi::structures::Digest::try_from(tbs_hash.as_ref())
                    .context("Error creating TPM digest")?;
                let validation: tss_esapi::structures::HashcheckTicket =
                    tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
                        tag: tss_esapi::constants::tss::TPM2_ST_HASHCHECK,
                        hierarchy: tss_esapi::constants::tss::TPM2_RH_NULL,
                        digest: Default::default(),
                    }
                    .try_into()
                    .context("Error creating validation ticket")?;

                let signature = tss_context
                    .execute_with_nullauth_session(|ctx| {
                        ctx.sign(
                            signing_handle,
                            tpm_digest,
                            tss_esapi::structures::SignatureScheme::Null,
                            validation,
                        )
                    })
                    .context("Error signing CSR with TPM")?;

                // Flush the signing key
                tss_context
                    .execute_with_nullauth_session(|ctx| ctx.flush_context(signing_handle.into()))
                    .context("Error flushing signing key")?;

                // Convert TPM ECDSA signature to DER
                let sig_der = match signature {
                    tss_esapi::structures::Signature::EcDsa(sig) => {
                        ecdsa_sig_to_der(sig.signature_r().value(), sig.signature_s().value())
                            .context("Error converting ECDSA signature to DER")?
                    }
                    _ => bail!("Unexpected TPM signature type"),
                };

                // Reassemble the CSR DER with the TPM signature
                let csr_der = assemble_csr_der(&tbs_bytes, &sig_der, &signing_pub)
                    .context("Error assembling CSR with TPM signature")?;

                Ok(csr_der)
            }
            #[cfg(feature = "tpm_support")]
            KeyReference::SpecTpm {
                ref mut tss_context,
                dak_handle,
                public_bytes,
                dk_us_nv_handle,
                ..
            } => {
                let signing_pub = tss_esapi::structures::Public::unmarshall(public_bytes)
                    .context("Error unmarshalling spec TPM public key")?;

                let (pkey, digest) = match &signing_pub {
                    tss_esapi::structures::Public::Ecc {
                        parameters, unique, ..
                    } => {
                        let (curve_nid, digest) = match parameters.ecc_curve() {
                            tss_esapi::interface_types::ecc::EccCurve::NistP256 => {
                                (Nid::X9_62_PRIME256V1, MessageDigest::sha256())
                            }
                            tss_esapi::interface_types::ecc::EccCurve::NistP384 => {
                                (Nid::SECP384R1, MessageDigest::sha384())
                            }
                            _ => bail!("Unsupported curve for CSR"),
                        };
                        let group = EcGroup::from_curve_name(curve_nid)?;
                        let x = BigNum::from_slice(unique.x())?;
                        let y = BigNum::from_slice(unique.y())?;
                        let ec_key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)?;
                        let pkey = PKey::from_ec_key(ec_key)?;
                        (pkey, digest)
                    }
                    _ => bail!("Unsupported key type for CSR"),
                };

                let mut name_builder = X509NameBuilder::new()?;
                name_builder.append_entry_by_text("CN", "device.fdo-rs")?;
                let name = name_builder.build();

                let mut req_builder = X509ReqBuilder::new()?;
                req_builder.set_subject_name(&name)?;
                req_builder.set_pubkey(&pkey)?;

                // Sign with a temp key to get TBS structure
                let temp_key = {
                    let ec_key = pkey.ec_key()?;
                    let temp_ec = EcKey::generate(ec_key.group())?;
                    PKey::from_ec_key(temp_ec)?
                };
                req_builder.sign(&temp_key, digest)?;
                let temp_csr_der = req_builder.build().to_der()?;

                let tbs_bytes =
                    extract_tbs_from_csr_der(&temp_csr_der).context("Error extracting TBS")?;

                use openssl::hash::hash;
                let tbs_hash = hash(digest, &tbs_bytes)?;

                // Sign with persistent DAK using policy session via second ESYS connection
                let (r, s) = fdo_data_formats::tpm::policy::sign_with_policy(
                    fdo_data_formats::tpm::DEVICE_KEY_US_INDEX,
                    fdo_data_formats::tpm::DAK_HANDLE,
                    tbs_hash.as_ref(),
                )
                .context("Error signing CSR with TPM DAK")?;

                let sig_der = ecdsa_sig_to_der(&r, &s)?;

                assemble_csr_der(&tbs_bytes, &sig_der, &signing_pub).context("Error assembling CSR")
            }
        }
    }

    fn save_to_credential(
        self,
        device_info: String,
        guid: Guid,
        rvinfo: RendezvousInfo,
        manufacturer_public_key_hash: Hash,
        protocol_version: ProtocolVersion,
    ) -> Result<()> {
        match self {
            KeyReference::FileSystem { sign_key, hmac_key } => {
                let private_key = sign_key
                    .private_key_to_der()
                    .context("Error serializing private sign key")?;

                let cred = FileDeviceCredential {
                    active: true,
                    protver: protocol_version,
                    device_info,
                    guid,
                    rvinfo,
                    pubkey_hash: manufacturer_public_key_hash,

                    key_storage: KeyStorage::Plain {
                        hmac_secret: hmac_key,
                        private_key,
                    },
                };

                let cred = cred
                    .serialize_data()
                    .context("Error serializing device credential")?;

                let filename = match env::var_os("DEVICE_CREDENTIAL_FILENAME") {
                    Some(filename) => filename.into_string().unwrap(),
                    None => DEVICE_CREDENTIAL_FILESYSTEM_PATH.to_string(),
                };

                fs::write(filename, cred).context("Error writing device credential")
            }
            #[cfg(feature = "tpm_support")]
            KeyReference::SemiTpm {
                signing_public,
                signing_private,
                hmac_public,
                hmac_private,
                ..
            } => {
                let cred = FileDeviceCredential {
                    active: true,
                    protver: protocol_version,
                    device_info,
                    guid,
                    rvinfo,
                    pubkey_hash: manufacturer_public_key_hash,

                    key_storage: KeyStorage::Tpm {
                        signing_public,
                        signing_private,
                        hmac_public,
                        hmac_private,
                    },
                };

                let cred = cred
                    .serialize_data()
                    .context("Error serializing device credential")?;

                let filename = match env::var_os("DEVICE_CREDENTIAL_FILENAME") {
                    Some(filename) => filename.into_string().unwrap(),
                    None => DEVICE_CREDENTIAL_FILESYSTEM_PATH.to_string(),
                };

                fs::write(filename, cred).context("Error writing device credential")
            }
            #[cfg(feature = "tpm_support")]
            KeyReference::SpecTpm {
                mut tss_context,
                use_platform,
                public_bytes,
                ..
            } => {
                use fdo_data_formats::tpm::{self, nv};

                // Write DCTPM NV: GUID (16 bytes) + DeviceInfo string
                // Guid serialization: extract raw bytes via CBOR roundtrip
                let guid_bytes = guid.serialize_data().context("Error serializing GUID")?;
                // The CBOR-encoded GUID is a bstr; for NV we need raw 16 bytes.
                // Use the serialized form directly (Go uses raw GUID bytes).
                // Actually the Guid inner data is a Vec<u8> of 16 bytes.
                // We can serialize to CBOR and extract, or just use the serialized GUID.
                // For interop with Go: DCTPM = raw GUID (16 bytes) + DeviceInfo string.
                // Let's extract the inner bytes by serializing to CBOR bstr and unwrapping.
                let guid_raw: Vec<u8> = {
                    let mut buf = Vec::new();
                    ciborium::ser::into_writer(&guid, &mut buf)
                        .context("Error CBOR-encoding GUID")?;
                    // CBOR bstr: major type 2 + 16 bytes = [0x50, ...16 bytes...]
                    if buf.len() >= 17 && buf[0] == 0x50 {
                        buf[1..17].to_vec()
                    } else {
                        // Fallback: use the serialized data directly
                        guid_bytes
                    }
                };
                let mut dctpm_data = Vec::with_capacity(16 + device_info.len());
                dctpm_data.extend_from_slice(&guid_raw[..std::cmp::min(guid_raw.len(), 16)]);
                // Pad to 16 if shorter
                while dctpm_data.len() < 16 {
                    dctpm_data.push(0);
                }
                dctpm_data.extend_from_slice(device_info.as_bytes());

                let dctpm_handle = nv::define_nv_space(
                    &mut tss_context,
                    tpm::DCTPM_INDEX,
                    dctpm_data.len(),
                    tpm::NvProfile::B,
                    use_platform,
                )
                .context("Error defining DCTPM NV")?;
                nv::write_nv(
                    &mut tss_context,
                    dctpm_handle,
                    &dctpm_data,
                    tpm::NvProfile::B,
                )
                .context("Error writing DCTPM NV")?;
                log::info!(
                    "Wrote DCTPM NV ({} bytes): GUID + DeviceInfo",
                    dctpm_data.len()
                );

                // Write DCOV NV: CBOR array matching Go's dcovNVData encoding.
                // Go encodes dcovNVData as CBOR array (not map): [version, rvinfo, pubkeyhash, keytype]
                // Each element uses the FDO protocol's native CBOR encoding.
                let key_type_value: u8 = {
                    // Derive key type from public bytes
                    let pub_struct = tss_esapi::structures::Public::unmarshall(&public_bytes)
                        .context("Error unmarshalling public for key type")?;
                    match pub_struct {
                        tss_esapi::structures::Public::Ecc { parameters, .. } => {
                            match parameters.ecc_curve() {
                                tss_esapi::interface_types::ecc::EccCurve::NistP256 => 10, // SECP256R1
                                tss_esapi::interface_types::ecc::EccCurve::NistP384 => 11, // SECP384R1
                                _ => 0,
                            }
                        }
                        _ => 0,
                    }
                };

                // Serialize DCOV as CBOR array matching Go's dcovNVData encoding:
                // [version, rvinfo, pubkeyhash, keytype, hmac_handle]
                // Go's custom CBOR library encodes structs as arrays (not maps),
                // with field ordering determined by `keyasint` struct tags.
                let dcov_payload = {
                    let version_val = serde_cbor::Value::Integer(protocol_version as i128);
                    let rvinfo_val = serde_cbor::value::to_value(&rvinfo)
                        .unwrap_or(serde_cbor::Value::Array(vec![]));
                    let hash_val =
                        serde_cbor::value::to_value(&manufacturer_public_key_hash)
                            .unwrap_or(serde_cbor::Value::Null);
                    let keytype_val = serde_cbor::Value::Integer(key_type_value as i128);
                    let hmac_handle_val =
                        serde_cbor::Value::Integer(tpm::HMAC_KEY_HANDLE as i128);

                    let dcov_array = serde_cbor::Value::Array(vec![
                        version_val,
                        rvinfo_val,
                        hash_val,
                        keytype_val,
                        hmac_handle_val,
                    ]);
                    serde_cbor::to_vec(&dcov_array)
                        .context("Error encoding DCOV CBOR array")?
                };

                let dcov_handle = nv::define_nv_space(
                    &mut tss_context,
                    tpm::DCOV_INDEX,
                    dcov_payload.len(),
                    tpm::NvProfile::C,
                    use_platform,
                )
                .context("Error defining DCOV NV")?;
                nv::write_nv(
                    &mut tss_context,
                    dcov_handle,
                    &dcov_payload,
                    tpm::NvProfile::C,
                )
                .context("Error writing DCOV NV")?;
                log::info!("Wrote DCOV NV ({} bytes)", dcov_payload.len());

                // Update DCActive to 0x01 (device initialized)
                if let Ok((_, _, dc_active_handle)) =
                    nv::read_nv_public(&mut tss_context, tpm::DC_ACTIVE_INDEX)
                {
                    nv::write_nv(
                        &mut tss_context,
                        dc_active_handle,
                        &[0x01],
                        tpm::NvProfile::A,
                    )
                    .context("Error updating DCActive to 0x01")?;
                }
                log::info!("DCActive set to 0x01 (device initialized)");
                log::info!("Credentials stored in TPM NV indices (no file written)");

                Ok(())
            }
        }
    }

    fn perform_hmac(&mut self, data: &[u8]) -> Result<HMac> {
        match self {
            KeyReference::FileSystem { hmac_key, .. } => {
                let hmac_key =
                    PKey::hmac(hmac_key.as_slice()).context("Error creating HMAC key")?;
                let mut hmac_signer = Signer::new(MessageDigest::sha384(), &hmac_key)
                    .context("Error creating hmac signer")?;
                hmac_signer
                    .update(data)
                    .context("Error feeding data to hmac computation")?;
                let hmac = hmac_signer
                    .sign_to_vec()
                    .context("Error finalizing hmac computation")?;
                HMac::from_digest(HashType::HmacSha384, hmac)
                    .context("Error converting result to hmac")
            }
            #[cfg(feature = "tpm_support")]
            KeyReference::SemiTpm {
                ref mut tss_context,
                primary_handle,
                hmac_public,
                hmac_private,
                ..
            } => {
                let hmac_public = tss_esapi::structures::Public::unmarshall(hmac_public)
                    .context("Error unmarshalling public key")?;
                let hash_algo = match hmac_public {
                    tss_esapi::structures::Public::KeyedHash { parameters, .. } => {
                        let parameters: tss_esapi::tss2_esys::TPMS_KEYEDHASH_PARMS =
                            parameters.into();
                        let scheme = parameters.scheme;
                        match tss_esapi::constants::AlgorithmIdentifier::try_from(scheme.scheme)
                            .context("Error converting scheme to scheme type")?
                        {
                            tss_esapi::constants::AlgorithmIdentifier::Hmac => {}
                            scheme => bail!("Unsupported scheme in key: {:?}", scheme),
                        }
                        let details = unsafe { scheme.details.hmac }.hashAlg;
                        let details = tss_esapi::constants::AlgorithmIdentifier::try_from(details)
                            .context("Error converting scheme to hash algorithm")?;

                        match details {
                            tss_esapi::constants::AlgorithmIdentifier::Sha256 => {
                                HashingAlgorithm::Sha256
                            }
                            tss_esapi::constants::AlgorithmIdentifier::Sha384 => {
                                HashingAlgorithm::Sha384
                            }
                            details => bail!("Unsupported ECC details: {:?}", details),
                        }
                    }
                    algo => bail!("Unsupported signing key type: {:?}", algo),
                };
                let hash_type = match hash_algo {
                    HashingAlgorithm::Sha256 => HashType::Sha256,
                    HashingAlgorithm::Sha384 => HashType::Sha384,
                    algo => bail!("Unsupported hash algorithm: {:?}", algo),
                };
                let hmac_key = tss_context
                    .execute_with_nullauth_session(|ctx| {
                        ctx.load(
                            *primary_handle,
                            hmac_private
                                .as_slice()
                                .try_into()
                                .context("Error converting hmac private key")?,
                            hmac_public,
                        )
                        .context("Error loading TPM hmac key")
                    })
                    .context("Error loading HMAC key")?;
                let data = data.try_into().context("Error creating data buffer")?;
                let hmac = tss_context
                    .execute_with_nullauth_session(|ctx| {
                        ctx.execute_with_temporary_object(hmac_key.into(), |ctx, hmac_key| {
                            ctx.hmac(hmac_key, data, hash_algo)
                        })
                    })
                    .context("Error computing hmac")?;
                HMac::from_digest(hash_type, hmac.to_vec())
                    .context("Error converting result to hmac")
            }
            #[cfg(feature = "tpm_support")]
            KeyReference::SpecTpm { .. } => {
                // Use persistent HMAC key with policy session via second ESYS connection
                let hmac_bytes = fdo_data_formats::tpm::policy::hmac_with_policy(
                    fdo_data_formats::tpm::HMAC_US_INDEX,
                    fdo_data_formats::tpm::HMAC_KEY_HANDLE,
                    data,
                )
                .context("Error computing HMAC with TPM policy session")?;
                HMac::from_digest(HashType::HmacSha256, hmac_bytes)
                    .context("Error creating HMac from TPM HMAC")
            }
        }
    }
}

const IPV4_DEFAULT: &str = "00000000";

fn get_default_network_iface() -> Result<Option<String>, std::io::Error> {
    // Check IPv4 addresses from /proc/net/route
    let file = std::fs::File::open("/proc/net/route")?;
    let reader = BufReader::new(file);

    for line in reader.lines().skip(1) {
        let line = line?;
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        if fields[1] == IPV4_DEFAULT && fields[0] != "lo" {
            let iface = fields[0].to_string();
            log::info!("Default network interface is ipv4 based {iface}");
            return Ok(Some(iface));
        }
    }
    Ok(None)
}
