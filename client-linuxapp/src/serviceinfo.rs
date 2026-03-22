// Copyright (c) 2021, Red Hat, Inc.
// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause

use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::{env, fs};

use anyhow::{anyhow, bail, Context, Result};

use fdo_data_formats::{
    constants::{FdoServiceInfoModule, HashType, ServiceInfoModule, StandardServiceInfoModule},
    messages::v20::to2::{DeviceSvcInfo20, OwnerSvcInfo20},
    types::{CborSimpleTypeExt, Hash, ServiceInfo},
};
use fdo_http_wrapper::client::{RequestResult, ServiceClient};

const MAX_SERVICE_INFO_LOOPS: u32 = 1000;

fn find_available_modules() -> Result<Vec<ServiceInfoModule>> {
    let module_list = vec![
        StandardServiceInfoModule::DevMod.into(),
        FdoServiceInfoModule::Bmo.into(),
    ];
    Ok(module_list)
}

// BMO (Bare Metal Onboarding) FSIM state
//
// Handles chunked image transfer from owner to device:
//   image-begin (CBOR map) -> image-ack -> image-data-N... -> image-end -> image-result
// Also handles BIOS parameter setting:
//   set (CBOR array of [name, value]) -> response
//
// Delivery modes:
//   0 (inline) - image data sent as chunks via FDO channel
//   1 (url)    - server provides URL; device writes it for external consumer to fetch
//   2 (meta-url) - server provides meta-payload URL; device fetches and parses CBOR to resolve image URL

const BMO_DELIVERY_MODE_INLINE: u64 = 0;
const BMO_DELIVERY_MODE_URL: u64 = 1;
const BMO_DELIVERY_MODE_META_URL: u64 = 2;

#[allow(dead_code)]
#[derive(Debug)]
struct BmoImageBegin {
    image_type: String,
    total_size: Option<u64>,
    hash_alg: Option<String>,
    require_ack: bool,
    delivery_mode: u64,
    name: Option<String>,
    version: Option<String>,
    description: Option<String>,
    boot_args: Option<String>,
    url: Option<String>,
    tls_ca: Option<Vec<u8>>,
    expected_hash: Option<Vec<u8>>,
    meta_signer: Option<Vec<u8>>,
}

#[derive(Debug)]
struct BmoInProgress {
    begin: Option<BmoImageBegin>,
    data: Vec<u8>,
    output_dir: PathBuf,
}

impl BmoInProgress {
    fn new() -> Self {
        let output_dir = env::var("BMO_OUTPUT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp/fdo-bmo"));
        BmoInProgress {
            begin: None,
            data: Vec::new(),
            output_dir,
        }
    }

    fn parse_image_begin(value: &serde_cbor::Value) -> Result<BmoImageBegin> {
        let map = match value {
            serde_cbor::Value::Map(m) => m,
            _ => bail!("BMO image-begin: expected CBOR map, got {:?}", value),
        };

        let get_int =
            |key: i128| -> Option<&serde_cbor::Value> { map.get(&serde_cbor::Value::Integer(key)) };
        let get_text = |key: i128| -> Option<String> {
            get_int(key).and_then(|v| match v {
                serde_cbor::Value::Text(s) => Some(s.clone()),
                _ => None,
            })
        };
        let get_u64 = |key: i128| -> Option<u64> {
            get_int(key).and_then(|v| match v {
                serde_cbor::Value::Integer(n) => Some(*n as u64),
                _ => None,
            })
        };
        let get_bool = |key: i128| -> Option<bool> {
            get_int(key).and_then(|v| match v {
                serde_cbor::Value::Bool(b) => Some(*b),
                _ => None,
            })
        };
        let get_bytes = |key: i128| -> Option<Vec<u8>> {
            get_int(key).and_then(|v| match v {
                serde_cbor::Value::Bytes(b) => Some(b.clone()),
                _ => None,
            })
        };

        let image_type = get_text(-1)
            .ok_or_else(|| anyhow!("BMO image-begin: missing required field -1 (image_type)"))?;

        Ok(BmoImageBegin {
            image_type,
            total_size: get_u64(0),
            hash_alg: get_text(1),
            require_ack: get_bool(3).unwrap_or(false),
            delivery_mode: get_u64(-6).unwrap_or(BMO_DELIVERY_MODE_INLINE),
            name: get_text(-3),
            version: get_text(-4),
            description: get_text(-5),
            boot_args: get_text(-2),
            url: get_text(-7),
            tls_ca: get_bytes(-8),
            expected_hash: get_bytes(-9),
            meta_signer: get_bytes(-10),
        })
    }

    fn send_ack(
        si_out: &mut ServiceInfo,
        accepted: bool,
        code: Option<u64>,
        msg: Option<&str>,
    ) -> Result<()> {
        let mut ack: Vec<serde_cbor::Value> = vec![serde_cbor::Value::Bool(accepted)];
        if let Some(c) = code {
            ack.push(serde_cbor::Value::Integer(c as i128));
        }
        if let Some(m) = msg {
            ack.push(serde_cbor::Value::Text(m.to_string()));
        }
        si_out.add(FdoServiceInfoModule::Bmo, "image-ack", &ack)?;
        Ok(())
    }

    fn send_result(si_out: &mut ServiceInfo, status: u64, msg: &str) -> Result<()> {
        let result: Vec<serde_cbor::Value> = vec![
            serde_cbor::Value::Integer(status as i128),
            serde_cbor::Value::Text(msg.to_string()),
        ];
        si_out.add(FdoServiceInfoModule::Bmo, "image-result", &result)?;
        Ok(())
    }

    fn finalize(
        &mut self,
        hash_bytes: Option<&[u8]>,
        hash_alg: &Option<String>,
        si_out: &mut ServiceInfo,
    ) -> Result<()> {
        let begin = self
            .begin
            .take()
            .ok_or_else(|| anyhow!("BMO image-end without image-begin"))?;

        fs::create_dir_all(&self.output_dir).context("BMO: failed to create output directory")?;

        match begin.delivery_mode {
            BMO_DELIVERY_MODE_INLINE => {
                // Verify hash if provided
                if let Some(expected_hash) = hash_bytes {
                    let alg = hash_alg.as_deref().unwrap_or("sha256");
                    let hash_type = match alg {
                        "sha256" => HashType::Sha256,
                        "sha384" => HashType::Sha384,
                        _ => {
                            Self::send_result(
                                si_out,
                                2,
                                &format!("Unsupported hash algorithm: {}", alg),
                            )?;
                            return Ok(());
                        }
                    };
                    let hash = Hash::from_digest(hash_type, expected_hash.to_vec())?;
                    if let Err(e) = hash.compare_data(&self.data) {
                        log::error!("BMO image hash mismatch: {:?}", e);
                        Self::send_result(si_out, 2, "Hash verification failed")?;
                        return Ok(());
                    }
                    log::info!("BMO image hash verified ({})", alg);
                }

                let filename = begin.name.as_deref().unwrap_or("bmo-image.bin");
                let output_path = self.output_dir.join(filename);
                fs::write(&output_path, &self.data)
                    .with_context(|| format!("BMO: failed to write image to {:?}", output_path))?;
                log::info!(
                    "BMO image written: {:?} ({} bytes, type: {})",
                    output_path,
                    self.data.len(),
                    begin.image_type
                );
                Self::send_result(
                    si_out,
                    0,
                    &format!("Image received: {} bytes", self.data.len()),
                )?;
            }

            BMO_DELIVERY_MODE_URL => {
                let url = begin.url.as_deref().unwrap_or("(none)");
                log::info!("BMO url delivery: url={}, type={}", url, begin.image_type);

                let info_path = self.output_dir.join("bmo-url.txt");
                let mut info = format!(
                    "delivery_mode=1\nurl={}\nimage_type={}\n",
                    url, begin.image_type
                );
                if let Some(name) = &begin.name {
                    info.push_str(&format!("name={}\n", name));
                }
                if let Some(alg) = &begin.hash_alg {
                    info.push_str(&format!("hash_alg={}\n", alg));
                }
                fs::write(&info_path, &info)
                    .with_context(|| format!("BMO: failed to write url info to {:?}", info_path))?;

                if let Some(hash) = &begin.expected_hash {
                    let hash_path = self.output_dir.join("expected_hash.bin");
                    fs::write(&hash_path, hash)?;
                    log::info!("BMO expected hash written ({} bytes)", hash.len());
                }
                if let Some(ca) = &begin.tls_ca {
                    let ca_path = self.output_dir.join("tls_ca.der");
                    fs::write(&ca_path, ca)?;
                    log::info!("BMO TLS CA written ({} bytes)", ca.len());
                }

                Self::send_result(si_out, 0, &format!("URL received: {}", url))?;
            }

            BMO_DELIVERY_MODE_META_URL => {
                let meta_url = begin
                    .url
                    .as_deref()
                    .ok_or_else(|| anyhow!("BMO meta-url: no URL in image-begin"))?;
                log::info!("BMO meta-url delivery: fetching {}", meta_url);

                let meta_bytes = reqwest::blocking::get(meta_url)
                    .with_context(|| format!("BMO meta-url: failed to fetch {}", meta_url))?
                    .bytes()
                    .context("BMO meta-url: failed to read response body")?;

                log::info!(
                    "BMO meta-url: fetched {} bytes from {}",
                    meta_bytes.len(),
                    meta_url
                );

                let meta_cbor: serde_cbor::Value = serde_cbor::from_slice(&meta_bytes)
                    .context("BMO meta-url: failed to parse CBOR")?;

                let meta_map = match &meta_cbor {
                    serde_cbor::Value::Map(m) => m,
                    _ => bail!("BMO meta-url: expected CBOR map, got {:?}", meta_cbor),
                };

                let get_meta_text = |key: i128| -> Option<String> {
                    meta_map
                        .get(&serde_cbor::Value::Integer(key))
                        .and_then(|v| match v {
                            serde_cbor::Value::Text(s) => Some(s.clone()),
                            _ => None,
                        })
                };

                let image_type = get_meta_text(0).unwrap_or_default();
                let image_url = get_meta_text(1).unwrap_or_default();
                let hash_alg = get_meta_text(3);
                let boot_args = get_meta_text(5);
                let name = get_meta_text(6);
                let version = get_meta_text(7);
                let description = get_meta_text(8);

                log::info!("BMO meta-url resolved:");
                log::info!("  image_type: {}", image_type);
                log::info!("  image_url:  {}", image_url);
                if let Some(alg) = &hash_alg {
                    log::info!("  hash_alg:   {}", alg);
                }
                if let Some(n) = &name {
                    log::info!("  name:       {}", n);
                }
                if let Some(v) = &version {
                    log::info!("  version:    {}", v);
                }
                if let Some(d) = &description {
                    log::info!("  description:{}", d);
                }
                if let Some(a) = &boot_args {
                    log::info!("  boot_args:  {}", a);
                }

                let info_path = self.output_dir.join("bmo-meta-url.txt");
                let mut info = format!(
                    "delivery_mode=2\nmeta_url={}\nimage_type={}\nimage_url={}\n",
                    meta_url, image_type, image_url
                );
                if let Some(alg) = &hash_alg {
                    info.push_str(&format!("hash_alg={}\n", alg));
                }
                if let Some(n) = &name {
                    info.push_str(&format!("name={}\n", n));
                }
                if let Some(v) = &version {
                    info.push_str(&format!("version={}\n", v));
                }
                if let Some(d) = &description {
                    info.push_str(&format!("description={}\n", d));
                }
                if let Some(a) = &boot_args {
                    info.push_str(&format!("boot_args={}\n", a));
                }
                fs::write(&info_path, &info).with_context(|| {
                    format!("BMO: failed to write meta-url info to {:?}", info_path)
                })?;

                let raw_path = self.output_dir.join("meta_payload.cbor");
                fs::write(&raw_path, &meta_bytes)?;

                if let Some(signer) = &begin.meta_signer {
                    let signer_path = self.output_dir.join("meta_signer.cbor");
                    fs::write(&signer_path, signer)?;
                    log::info!("BMO meta signer key received ({} bytes)", signer.len());
                }

                Self::send_result(
                    si_out,
                    0,
                    &format!("Meta-URL resolved: image_url={}", image_url),
                )?;
            }

            other => {
                Self::send_result(si_out, 2, &format!("Unsupported delivery mode: {}", other))?;
            }
        }

        // Write boot_args if present (common to all modes)
        if let Some(args) = &begin.boot_args {
            let args_path = self.output_dir.join("boot_args");
            fs::write(&args_path, args)
                .with_context(|| format!("BMO: failed to write boot_args to {:?}", args_path))?;
            log::info!("BMO boot args written: {:?}", args_path);
        }

        self.data.clear();
        Ok(())
    }
}

fn bmo_handle_set(value: &serde_cbor::Value, si_out: &mut ServiceInfo) -> Result<()> {
    let params = match value {
        serde_cbor::Value::Array(a) => a,
        _ => bail!("BMO set: expected CBOR array, got {:?}", value),
    };

    let output_dir = env::var("BMO_OUTPUT_DIR").unwrap_or_else(|_| "/tmp/fdo-bmo".to_string());
    let params_path = PathBuf::from(&output_dir).join("bios_params");
    fs::create_dir_all(&output_dir).context("BMO: failed to create output directory")?;

    let mut param_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&params_path)
        .with_context(|| format!("BMO: failed to open {:?}", params_path))?;

    for param in params {
        let pair = match param {
            serde_cbor::Value::Array(p) if p.len() >= 2 => p,
            _ => {
                log::warn!("BMO set: skipping malformed parameter: {:?}", param);
                continue;
            }
        };
        let name = match &pair[0] {
            serde_cbor::Value::Text(s) => s.clone(),
            _ => {
                log::warn!("BMO set: non-string parameter name: {:?}", pair[0]);
                continue;
            }
        };
        let value_str = match &pair[1] {
            serde_cbor::Value::Text(s) => s.clone(),
            serde_cbor::Value::Bool(b) => b.to_string(),
            serde_cbor::Value::Integer(i) => i.to_string(),
            serde_cbor::Value::Null => "null".to_string(),
            other => format!("{:?}", other),
        };

        writeln!(param_file, "{}={}", name, value_str)
            .with_context(|| format!("BMO: failed to write parameter {}={}", name, value_str))?;
        log::info!("BMO BIOS parameter: {}={}", name, value_str);

        let response: Vec<serde_cbor::Value> = vec![
            serde_cbor::Value::Integer(0),
            serde_cbor::Value::Text(format!("Set {}={}", name, value_str)),
        ];
        si_out.add(FdoServiceInfoModule::Bmo, "response", &response)?;
    }

    Ok(())
}

async fn process_serviceinfo_in(
    si_in: &ServiceInfo,
    si_out: &mut ServiceInfo,
    bmo_in_progress: &mut BmoInProgress,
    active_modules: &mut HashSet<ServiceInfoModule>,
) -> Result<bool> {
    for (module, key, value) in si_in.iter() {
        log::trace!("Got module {}, command {}, value {:?}", module, key, value);
        if key == "active" {
            let value = value.as_bool().context("Error parsing active value")?;
            if value {
                log::trace!("Activating module {}", module);
                active_modules.insert(module);
            } else {
                log::trace!("Deactivating module {}", module);
                active_modules.remove(&module);
            }
            continue;
        }
        if !active_modules.contains(&module) {
            log::trace!("Skipping non-activated module {}", module);
            bail!("Non-activated module {} got request", module);
        }

        if module == FdoServiceInfoModule::Bmo.into() {
            if key == "image-begin" {
                let begin = BmoInProgress::parse_image_begin(&value)
                    .context("Error parsing BMO image-begin")?;
                log::info!(
                    "BMO image-begin: type={}, size={:?}, mode={}, name={:?}, url={:?}",
                    begin.image_type,
                    begin.total_size,
                    begin.delivery_mode,
                    begin.name,
                    begin.url
                );
                if begin.require_ack {
                    BmoInProgress::send_ack(si_out, true, None, None)?;
                }
                if let Some(size) = begin.total_size {
                    bmo_in_progress.data.reserve(size as usize);
                }
                bmo_in_progress.begin = Some(begin);
            } else if key.starts_with("image-data") {
                let chunk = value
                    .as_bytes()
                    .context("Error parsing BMO image-data chunk")?;
                bmo_in_progress.data.extend_from_slice(chunk);
                log::trace!(
                    "BMO image-data: +{} bytes (total {})",
                    chunk.len(),
                    bmo_in_progress.data.len()
                );
            } else if key == "image-end" {
                let hash_bytes = match &value {
                    serde_cbor::Value::Map(m) => {
                        m.get(&serde_cbor::Value::Integer(1)).and_then(|v| match v {
                            serde_cbor::Value::Bytes(b) => Some(b.as_slice()),
                            _ => None,
                        })
                    }
                    _ => None,
                };
                let hash_alg = bmo_in_progress
                    .begin
                    .as_ref()
                    .and_then(|b| b.hash_alg.clone());
                bmo_in_progress
                    .finalize(hash_bytes, &hash_alg, si_out)
                    .context("Error finalizing BMO image")?;
                *bmo_in_progress = BmoInProgress::new();
            } else if key == "set" {
                bmo_handle_set(&value, si_out).context("Error handling BMO set")?;
            }
        } else {
            log::debug!("Ignoring unknown module {} key {}", module, key);
        }
    }

    Ok(false)
}

pub(crate) async fn perform_to2_serviceinfos(client: &mut ServiceClient) -> Result<bool> {
    let mut loop_num = 0;
    let mut out_si = ServiceInfo::new();
    let mut reboot_required = false;
    let mut bmo_state = BmoInProgress::new();
    let mut active_modules: HashSet<ServiceInfoModule> = HashSet::new();

    while loop_num < MAX_SERVICE_INFO_LOOPS {
        if loop_num == 0 {
            let modules = find_available_modules().context("Error getting list of modules")?;
            let sysinfo = sys_info::linux_os_release()
                .context("Error getting operating system information")?;

            out_si.add(StandardServiceInfoModule::DevMod, "active", &true)?;
            out_si.add(
                StandardServiceInfoModule::DevMod,
                "os",
                &std::env::consts::OS,
            )?;
            out_si.add(
                StandardServiceInfoModule::DevMod,
                "arch",
                &std::env::consts::ARCH,
            )?;
            out_si.add(
                StandardServiceInfoModule::DevMod,
                "version",
                &sysinfo.pretty_name.unwrap(),
            )?;
            out_si.add(StandardServiceInfoModule::DevMod, "device", &"unused")?;
            out_si.add(StandardServiceInfoModule::DevMod, "sep", &":")?;
            out_si.add(
                StandardServiceInfoModule::DevMod,
                "bin",
                &std::env::consts::ARCH,
            )?;
            out_si.add_modules(&modules)?;
        }

        let send_si = DeviceSvcInfo20::new(false, out_si);
        out_si = ServiceInfo::new();
        log::trace!("Sending ServiceInfo loop {}: {:?}", loop_num, send_si);

        let return_si: RequestResult<OwnerSvcInfo20> = client.send_request(send_si, None).await;
        let return_si =
            return_si.with_context(|| format!("Error during ServiceInfo loop {loop_num}"))?;
        log::trace!("Got ServiceInfo loop {}: {:?}", loop_num, return_si);

        if return_si.is_done() {
            log::trace!("ServiceInfo loops done, number taken: {}", loop_num);
            return Ok(reboot_required);
        }

        let reboot_si = process_serviceinfo_in(
            return_si.service_info(),
            &mut out_si,
            &mut bmo_state,
            &mut active_modules,
        )
        .await
        .context("Error processing returned serviceinfo")?;

        if return_si.is_more_service_info() {
            log::trace!("Owner has more ServiceInfo, continuing loop {}", loop_num);
        }
        if !reboot_required {
            reboot_required = reboot_si;
        }

        loop_num += 1;
    }
    Err(anyhow!(
        "Maximum number of ServiceInfo loops ({}) exceeded",
        MAX_SERVICE_INFO_LOOPS
    ))
}
