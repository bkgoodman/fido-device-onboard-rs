// Copyright (c) 2021, Red Hat, Inc.
// Copyright (c) 2026, Dell Technologies, Inc.
// SPDX-License-Identifier: BSD-3-Clause

use std::process::{Command, Stdio};
use std::{
    collections::HashSet,
    fs::{File, Permissions},
    io::Write,
    path::Path,
    str,
};
use std::{env, fs};
use std::{os::unix::fs::PermissionsExt, path::PathBuf};

use anyhow::{anyhow, bail, Context, Result};

use fdo_data_formats::{
    constants::{
        FdoServiceInfoModule, FedoraIotServiceInfoModule, HashType, RedHatComServiceInfoModule,
        ServiceInfoModule, StandardServiceInfoModule,
    },
    messages::v20::to2::{DeviceSvcInfo20, OwnerSvcInfo20},
    types::{CborSimpleTypeExt, Hash, ServiceInfo},
};
use fdo_http_wrapper::client::{RequestResult, ServiceClient};
use fdo_util::passwd_shadow;

const MAX_SERVICE_INFO_LOOPS: u32 = 1000;

fn find_available_modules() -> Result<Vec<ServiceInfoModule>> {
    let mut module_list = vec![
        // These modules are always here
        StandardServiceInfoModule::DevMod.into(),
        FedoraIotServiceInfoModule::SSHKey.into(),
        FedoraIotServiceInfoModule::BinaryFile.into(),
        FedoraIotServiceInfoModule::Command.into(),
        FedoraIotServiceInfoModule::Reboot.into(),
        FdoServiceInfoModule::Bmo.into(),
    ];

    // See if we add RHSM
    if Path::new("/usr/sbin/subscription-manager").exists() {
        module_list.push(RedHatComServiceInfoModule::SubscriptionManager.into());
    }

    if Path::new("/usr/bin/clevis").exists() {
        module_list.push(FedoraIotServiceInfoModule::DiskEncryptionClevis.into());
    }

    Ok(module_list)
}

fn set_perm_mode(path: &Path, mode: u32) -> Result<()> {
    let mut perms = fs::metadata(path)
        .context("Error getting directory metadata")?
        .permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms).context("Error setting permissions")?;
    Ok(())
}

fn create_user(user: &str) -> Result<()> {
    // Checks if user already present
    if passwd_shadow::is_user_in_passwd(user)? {
        log::info!("User: {user} already present");
        return Ok(());
    }
    // Creates new user if user not present
    log::info!("Creating user: {user}");
    let status = Command::new("useradd")
        .arg("-m")
        .arg(user)
        .spawn()
        .context("Error spawning new user command")?
        .wait()
        .context("Error creating new user")?;

    if status.success() {
        log::info!("User {user} created successfully");
        Ok(())
    } else {
        bail!(format!(
            "User creation failed. Exit Status: {:#?}",
            status.code()
        ));
    }
}

// Returns true if password is encrypted
// is_password_encrypted functionality is taken from osbuild-composer's crypt.go:
// https://github.com/osbuild/osbuild-composer/blob/main/internal/crypt/crypt.go
fn is_password_encrypted(s: &str) -> bool {
    let prefixes = ["$2b$", "$6$", "$5$"];

    for prefix in prefixes {
        if s.starts_with(prefix) {
            return true;
        }
    }

    false
}

fn create_user_with_password(user: &str, password: &str) -> Result<()> {
    // Checks if user already present
    if passwd_shadow::is_user_in_passwd(user)? {
        log::info!("User {user} is already present");
        return Ok(());
    }

    let mut str_encrypted_pw = password.to_string();
    log::info!("Checking for password encryption");
    if !is_password_encrypted(password) {
        log::info!("Encrypting password");
        let mut openssl = Command::new("openssl")
            .arg("passwd")
            .arg("-6")
            .arg("-stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        let openssl_stdin = openssl.stdin.as_mut().unwrap();
        openssl_stdin.write_all(password.as_bytes())?;
        let output = openssl.wait_with_output()?;

        str_encrypted_pw = str::from_utf8(&output.stdout)
            .expect("Error converting [u8] to string")
            .trim_end()
            .to_string();
    }
    // Creates new user if user not present
    log::info!("Creating user {user} with password");
    let status = Command::new("useradd")
        .arg("-p")
        .arg(str_encrypted_pw)
        .arg(user)
        .spawn()
        .context("Error spawning new user command")?
        .wait()
        .context("Error creating new user")?;

    if status.success() {
        log::info!("User {user} created successfully with password");
        Ok(())
    } else {
        bail!(format!(
            "User creation failed. Exit Status: {:#?}",
            status.code()
        ));
    }
}

fn install_ssh_key(user: &str, key: &str) -> Result<()> {
    let (uid, gid, home) = match passwd_shadow::get_user_uid_gid_home(user) {
        Ok((uid, gid, home)) => (uid, gid, home),
        Err(e) => bail!(e),
    };

    let uid = nix::unistd::Uid::from(uid);
    let gid = nix::unistd::Gid::from(gid);
    let key_path = if let Ok(val) = env::var("SSH_KEY_PATH") {
        PathBuf::from(&val)
    } else {
        let ssh_dir = Path::new(&home).join(".ssh");
        if !ssh_dir.exists() {
            log::debug!("Creating SSH directory at {}", ssh_dir.display());
            fs::create_dir(&ssh_dir).context("Error creating SSH key directory")?;
            set_perm_mode(&ssh_dir, 0o700).with_context(|| {
                format!(
                    "Error setting permissions on SSH key directory {}",
                    ssh_dir.display()
                )
            })?;
            nix::unistd::chown(&ssh_dir, Some(uid), Some(gid))?;
        }
        ssh_dir.join("authorized_keys")
    };
    log::debug!("Writing SSH keys to {:?}", key_path);
    let contents = if key_path.exists() {
        log::debug!(
            "SSH authorized keys {} file exists, appending",
            key_path.display()
        );
        fs::read_to_string(&key_path).context("Error reading current file")?
    } else {
        log::debug!("Creating SSH authorized keys {}", key_path.display());
        "".to_string()
    };
    let contents = format!(
        "{contents}\n# These keys are installed by FIDO Device Onboarding\n{key}\n# End of FIDO Device Onboarding keys\n"
    );
    fs::write(&key_path, contents.as_bytes()).context("Error writing SSH keys")?;
    set_perm_mode(&key_path, 0o600).with_context(|| {
        format!(
            "Error setting permissions on authorized keys file {}",
            key_path.display()
        )
    })?;
    nix::unistd::chown(&key_path, Some(uid), Some(gid))?;

    Ok(())
}

fn perform_rhsm(organization_id: &str, activation_key: &str, perform_insights: bool) -> Result<()> {
    log::info!("Executing subscription-manager registration");
    Command::new("subscription-manager")
        .arg("register")
        .arg(format!("--org={organization_id}"))
        .arg(format!("--activationkey={activation_key}"))
        .spawn()
        .context("Error spawning subscription-manager")?
        .wait()
        .context("Error running subscription-manager")?;

    if perform_insights {
        log::info!("Executing insights-client registration");
        Command::new("insights-client")
            .arg("--register")
            .spawn()
            .context("Error spawning insights-client")?
            .wait()
            .context("Error running insights-client")?;
    }

    Ok(())
}

#[derive(Debug)]
struct BinaryFileInProgress<'a> {
    path: Option<String>,
    prefix: Option<&'a str>,
    length: Option<u64>,
    contents: Option<Vec<u8>>,
    mode: Option<u32>,
    digest: Option<Hash>,
}

impl<'a> BinaryFileInProgress<'a> {
    fn new(prefix: Option<&'a str>) -> Self {
        BinaryFileInProgress {
            path: None,
            prefix,
            length: None,
            contents: None,
            mode: None,
            digest: None,
        }
    }

    #[cfg(not(unix))]
    compile_error!("This root splitting would need to get fixed for non-unix systems");
    fn destination_path(path_str: &str, prefix: Option<&str>) -> Result<PathBuf> {
        let path = PathBuf::from(path_str);

        if !path.is_absolute() {
            bail!("Binary file path must be absolute");
        }

        if let Some(val) = prefix {
            // make sure we drop the first slash or PathBuf returns the join'ed absolute path
            Ok(PathBuf::from(val).join(&path_str[1..path_str.len()]))
        } else {
            Ok(path)
        }
    }

    fn deploy(self) -> Result<()> {
        let path =
            BinaryFileInProgress::destination_path(self.path.as_ref().unwrap(), self.prefix)?;

        let contents = self.contents.as_ref().unwrap();
        let mode = self.mode.unwrap_or(0o600);

        log::info!(
            "Creating file {:?} with {} bytes (mode {:?})",
            path,
            self.length.unwrap(),
            mode
        );

        fs::create_dir_all(path.parent().unwrap()).context("Error creating file's directory")?;

        let mut file = File::create(path).context("Error creating file")?;
        file.write_all(contents).context("Error writing file")?;
        file.set_permissions(Permissions::from_mode(mode))
            .context("Error setting file permissions")?;
        file.sync_all().context("Error syncing file")?;

        Ok(())
    }
}

#[derive(Debug)]
struct DiskEncryptionInProgress {
    disk_label: Option<String>,
    pin: Option<String>,
    config: Option<String>,
    reencrypt: bool,
}

impl DiskEncryptionInProgress {
    fn new() -> Self {
        Self {
            disk_label: None,
            pin: None,
            config: None,
            reencrypt: false,
        }
    }

    fn execute_with_values(
        si_out: &mut ServiceInfo,
        disk_label: &str,
        pin: &str,
        config: &str,
        reencrypt: bool,
    ) -> Result<()> {
        log::info!(
            "Initiating disk re-encryption, disk-label: {}, pin: {}, config: {}, reencrypt: {}",
            disk_label,
            pin,
            config,
            reencrypt
        );

        let mut dev = if disk_label.starts_with('/') {
            libcryptsetup_rs::CryptInit::init(&std::path::PathBuf::from(disk_label))
        } else {
            libcryptsetup_rs::CryptInit::init_by_name_and_header(disk_label, None)
        }
        .with_context(|| format!("Error opening device {disk_label}"))?;

        log::debug!("Device initiated");

        dev.context_handle()
            .load::<libcryptsetup_rs::CryptParamsLuks2Ref>(None, None)
            .context("Error loading device context")?;

        log::debug!("Device information loaded");

        si_out.add(
            FedoraIotServiceInfoModule::DiskEncryptionClevis,
            "disk-label",
            &disk_label,
        )?;

        log::debug!("Rebinding clevis");
        crate::reencrypt::rebind::rebind_clevis(&mut dev, pin, config)
            .context("Error rebinding clevis")?;
        si_out.add(
            FedoraIotServiceInfoModule::DiskEncryptionClevis,
            "bound",
            &true,
        )?;
        if reencrypt {
            log::debug!("Initiating re-encryption");
            crate::reencrypt::initiate_reencrypt(dev).context("Error initiating reencryption")?;
        }
        log::debug!("Re-encryption initiated");
        si_out.add(
            FedoraIotServiceInfoModule::DiskEncryptionClevis,
            "reencrypt-initiated",
            &reencrypt,
        )?;

        Ok(())
    }

    fn execute(self, si_out: &mut ServiceInfo) -> Result<()> {
        let disk_label = self
            .disk_label
            .ok_or_else(|| anyhow!("Disk label not set"))?;
        let pin = self
            .pin
            .ok_or_else(|| anyhow!("Disk encryption PIN not set"))?;
        let config = self
            .config
            .ok_or_else(|| anyhow!("Disk encryption config not set"))?;
        let reencrypt = self.reencrypt;

        Self::execute_with_values(si_out, &disk_label, &pin, &config, reencrypt)
            .with_context(|| format!("Error executing disk encryption for disk label {disk_label}"))
    }
}

#[derive(Debug)]
struct CommandInProgress {
    command: Option<String>,
    args: Vec<String>,
    may_fail: bool,
    return_stdout: bool,
    return_stderr: bool,
}

impl CommandInProgress {
    fn new() -> Self {
        CommandInProgress {
            command: None,
            args: Vec::new(),
            may_fail: false,
            return_stdout: false,
            return_stderr: false,
        }
    }

    fn execute(self, si_out: &mut ServiceInfo) -> Result<()> {
        si_out.add(
            FedoraIotServiceInfoModule::Command,
            "command",
            self.command.as_ref().unwrap(),
        )?;
        si_out.add(FedoraIotServiceInfoModule::Command, "args", &self.args)?;

        let mut cmd = Command::new(self.command.as_ref().unwrap());
        cmd.args(&self.args);

        let output = cmd.output().context("Error running command")?;

        if self.return_stdout {
            si_out.add(
                FedoraIotServiceInfoModule::Command,
                "stdout",
                &serde_bytes::Bytes::new(&output.stdout),
            )?;
        }
        if self.return_stderr {
            si_out.add(
                FedoraIotServiceInfoModule::Command,
                "stderr",
                &serde_bytes::Bytes::new(&output.stderr),
            )?;
        }
        si_out.add(
            FedoraIotServiceInfoModule::Command,
            "exit_code",
            &output.status.code(),
        )?;

        if self.may_fail || output.status.success() {
            Ok(())
        } else {
            bail!(
                "Command failed {} {:?} stderr: {}",
                self.command.as_ref().unwrap(),
                self.args,
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

// BMO (Bare Metal Onboarding) FSIM state
//
// Handles chunked image transfer from owner to device:
//   image-begin (CBOR map) -> image-ack -> image-data-N... -> image-end -> image-result
// Also handles BIOS parameter setting:
//   set (CBOR array of [name, value]) -> response

const BMO_DELIVERY_MODE_INLINE: u64 = 0;

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

        let get_int = |key: i128| -> Option<&serde_cbor::Value> {
            map.get(&serde_cbor::Value::Integer(key))
        };
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
        })
    }

    fn send_ack(si_out: &mut ServiceInfo, accepted: bool, code: Option<u64>, msg: Option<&str>) -> Result<()> {
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

    fn finalize(&mut self, hash_bytes: Option<&[u8]>, hash_alg: &Option<String>, si_out: &mut ServiceInfo) -> Result<()> {
        let begin = self.begin.take()
            .ok_or_else(|| anyhow!("BMO image-end without image-begin"))?;

        // Verify hash if provided
        if let Some(expected_hash) = hash_bytes {
            let alg = hash_alg.as_deref().unwrap_or("sha256");
            let hash_type = match alg {
                "sha256" => HashType::Sha256,
                "sha384" => HashType::Sha384,
                _ => {
                    Self::send_result(si_out, 2, &format!("Unsupported hash algorithm: {}", alg))?;
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

        // Write image to output directory
        fs::create_dir_all(&self.output_dir)
            .context("BMO: failed to create output directory")?;

        let filename = begin.name.as_deref().unwrap_or("bmo-image.bin");
        let output_path = self.output_dir.join(filename);
        fs::write(&output_path, &self.data)
            .with_context(|| format!("BMO: failed to write image to {:?}", output_path))?;

        log::info!(
            "BMO image written: {:?} ({} bytes, type: {})",
            output_path, self.data.len(), begin.image_type
        );

        if let Some(args) = &begin.boot_args {
            let args_path = self.output_dir.join("boot_args");
            fs::write(&args_path, args)
                .with_context(|| format!("BMO: failed to write boot_args to {:?}", args_path))?;
            log::info!("BMO boot args written: {:?}", args_path);
        }

        Self::send_result(si_out, 0, &format!("Image received: {} bytes", self.data.len()))?;
        self.data.clear();
        Ok(())
    }
}

fn bmo_handle_set(value: &serde_cbor::Value, si_out: &mut ServiceInfo) -> Result<()> {
    // value is a CBOR array of [name, value] pairs
    let params = match value {
        serde_cbor::Value::Array(a) => a,
        _ => bail!("BMO set: expected CBOR array, got {:?}", value),
    };

    let output_dir = env::var("BMO_OUTPUT_DIR")
        .unwrap_or_else(|_| "/tmp/fdo-bmo".to_string());
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
    let mut sshkey_user: Option<String> = None;
    let mut sshkey_password: Option<String> = None;
    let mut sshkey_keys: Option<String> = None;

    let mut rhsm_organization_id: Option<String> = None;
    let mut rhsm_activation_key: Option<String> = None;
    let mut rhsm_perform_insights: Option<bool> = None;

    let binary_file_prefix_owned = env::var("BINARYFILE_PATH_PREFIX").ok();
    let mut binary_file_in_progress =
        BinaryFileInProgress::new(binary_file_prefix_owned.as_deref());
    let mut command_in_progress = CommandInProgress::new();
    let mut disk_encryption_in_progress = DiskEncryptionInProgress::new();

    let mut reboot_requested = false;

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
        if module == FedoraIotServiceInfoModule::SSHKey.into() {
            if key == "username" {
                let value = value.as_str().context("Error parsing username value")?;
                sshkey_user = Some(value.to_string());
                log::info!("Username is: {value}");
            } else if key == "password" {
                let value = value.as_str().context("Error parsing password value")?;
                sshkey_password = Some(value.to_string());
                log::info!("Password is present");
            } else if key == "sshkeys" {
                let value = value.as_str().context("Error parsing sshkey value")?;
                sshkey_keys = Some(value.to_string());
                log::info!("Keys are present");
            }
        } else if module == FedoraIotServiceInfoModule::Reboot.into() {
            if key == "reboot" {
                let value = value.as_bool().context("Error parsing reboot value")?;
                reboot_requested = value;
                log::trace!("Got reboot value: {value}");
            }
        } else if module == RedHatComServiceInfoModule::SubscriptionManager.into() {
            if key == "organization_id" {
                let value = value
                    .as_str()
                    .with_context(|| format!("Error parsing rhsm {key} value"))?;
                rhsm_organization_id = Some(value.to_string());
            } else if key == "activation_key" {
                let value = value
                    .as_str()
                    .with_context(|| format!("Error parsing rhsm {key} value"))?;
                rhsm_activation_key = Some(value.to_string());
            } else if key == "perform_insights" {
                let value = value
                    .as_bool()
                    .with_context(|| format!("Error parsing rhsm {key} value"))?;
                rhsm_perform_insights = Some(value);
            }
        } else if module == FedoraIotServiceInfoModule::BinaryFile.into() {
            if key == "name" {
                if binary_file_in_progress.path.is_some() {
                    bail!(
                        "Got binary file path {:?} after path {:?}",
                        value,
                        binary_file_in_progress.path
                    );
                }
                binary_file_in_progress.path = Some(
                    value
                        .as_str()
                        .context("Error parsing binary file name")?
                        .to_string(),
                );
            } else if key == "length" {
                if binary_file_in_progress.length.is_some() {
                    bail!(
                        "Got binary file length {:?} after length {:?}",
                        value,
                        binary_file_in_progress.length
                    );
                }
                binary_file_in_progress.length =
                    Some(value.as_u64().context("Error parsing binary file length")?);
                binary_file_in_progress.contents = Some(Vec::with_capacity(
                    binary_file_in_progress.length.unwrap() as usize,
                ));
            } else if key.starts_with("data") {
                if binary_file_in_progress.contents.is_none() {
                    bail!("Got binary file data before length {:?}", value);
                }
                binary_file_in_progress
                    .contents
                    .as_mut()
                    .unwrap()
                    .extend_from_slice(value.as_bytes().context("Error parsing binary file data")?);
            } else if key == "mode" {
                if binary_file_in_progress.mode.is_some() {
                    bail!(
                        "Got binary file mode {:?} after mode {:?}",
                        value,
                        binary_file_in_progress.mode
                    );
                }
                binary_file_in_progress.mode =
                    Some(value.as_u32().context("Error parsing binary file mode")?);
            } else if key.starts_with("sha-") {
                let sha_type = key.split('-').nth(1).unwrap();
                let sha_value = value
                    .as_bytes()
                    .with_context(|| format!("Error parsing binary file sha-{sha_type} value"))?;
                let hasher = match sha_type {
                    "256" => HashType::Sha256,
                    "384" => HashType::Sha384,
                    _ => {
                        bail!("Unknown sha-{}", sha_type);
                    }
                };
                binary_file_in_progress.digest =
                    Some(Hash::from_digest(hasher, sha_value.to_vec())?);

                // We got the full file, check it and add it to the files to get deployed
                if binary_file_in_progress.path.is_none() {
                    bail!("Got binary file sha-{} before name", sha_type);
                }
                if binary_file_in_progress.length.is_none() {
                    bail!("Got binary file sha-{} before length", sha_type);
                }
                let read_bytes = binary_file_in_progress.contents.as_ref().unwrap().len();
                if read_bytes != binary_file_in_progress.length.unwrap() as usize {
                    bail!(
                        "Got binary file (path {}) with length {} but only {} bytes of data",
                        binary_file_in_progress.path.as_ref().unwrap(),
                        binary_file_in_progress.length.unwrap(),
                        read_bytes
                    );
                }
                if let Err(e) = binary_file_in_progress
                    .digest
                    .as_ref()
                    .unwrap()
                    .compare_data(binary_file_in_progress.contents.as_ref().unwrap())
                {
                    bail!(
                        "Got binary file (path {}) with invalid digest: {:?}",
                        binary_file_in_progress.path.as_ref().unwrap(),
                        e
                    );
                }

                binary_file_in_progress
                    .deploy()
                    .context("Error deploying binary file")?;
                binary_file_in_progress =
                    BinaryFileInProgress::new(binary_file_prefix_owned.as_deref());
            }
        } else if module == FedoraIotServiceInfoModule::Command.into() {
            if key == "command" {
                if command_in_progress.command.is_some() {
                    bail!(
                        "Got command {:?} after command {:?}",
                        value,
                        command_in_progress.command
                    );
                }
                command_in_progress.command =
                    Some(value.as_str().context("Error parsing command")?.to_string());
            } else if key == "args" {
                command_in_progress.args =
                    value.as_str_array().context("Error parsing command args")?;
            } else if key == "may_fail" {
                command_in_progress.may_fail =
                    value.as_bool().context("Error parsing command may_fail")?;
            } else if key == "return_stdout" {
                command_in_progress.return_stdout = value
                    .as_bool()
                    .context("Error parsing command return_stdout")?;
            } else if key == "return_stderr" {
                command_in_progress.return_stderr = value
                    .as_bool()
                    .context("Error parsing command return_stderr")?;
            } else if key == "execute" {
                command_in_progress
                    .execute(si_out)
                    .context("Error executing command")?;
                command_in_progress = CommandInProgress::new();
            }
        } else if module == FedoraIotServiceInfoModule::DiskEncryptionClevis.into() {
            if key == "disk-label" {
                if disk_encryption_in_progress.disk_label.is_some() {
                    bail!(
                        "Got clevis disk-label {:?} after disk-label {:?}",
                        value,
                        disk_encryption_in_progress.disk_label
                    );
                }
                disk_encryption_in_progress.disk_label = Some(
                    value
                        .as_str()
                        .context("Error parsing clevis disk-label")?
                        .to_string(),
                );
            } else if key == "pin" {
                if disk_encryption_in_progress.pin.is_some() {
                    bail!(
                        "Got clevis pin {:?} after pin {:?}",
                        value,
                        disk_encryption_in_progress.pin
                    );
                }
                disk_encryption_in_progress.pin = Some(
                    value
                        .as_str()
                        .context("Error parsing clevis pin")?
                        .to_string(),
                );
            } else if key == "config" {
                if disk_encryption_in_progress.config.is_some() {
                    bail!(
                        "Got clevis config {:?} after config {:?}",
                        value,
                        disk_encryption_in_progress.config
                    );
                }
                disk_encryption_in_progress.config = Some(
                    value
                        .as_str()
                        .context("Error parsing clevis pin config")?
                        .to_string(),
                );
            } else if key == "reencrypt" {
                disk_encryption_in_progress.reencrypt =
                    value.as_bool().context("Error parsing clevis reencrypt")?;
            } else if key == "execute" {
                disk_encryption_in_progress
                    .execute(si_out)
                    .context("Error executing clevis")?;
                disk_encryption_in_progress = DiskEncryptionInProgress::new();
            }
        } else if module == FdoServiceInfoModule::Bmo.into() {
            if key == "image-begin" {
                let begin = BmoInProgress::parse_image_begin(&value)
                    .context("Error parsing BMO image-begin")?;
                log::info!(
                    "BMO image-begin: type={}, size={:?}, mode={}, name={:?}",
                    begin.image_type, begin.total_size, begin.delivery_mode,
                    begin.name
                );
                if begin.delivery_mode != BMO_DELIVERY_MODE_INLINE {
                    BmoInProgress::send_ack(si_out, false, Some(14), Some("Only inline delivery supported"))?;
                    log::warn!("BMO: rejecting non-inline delivery mode {}", begin.delivery_mode);
                } else {
                    if begin.require_ack {
                        BmoInProgress::send_ack(si_out, true, None, None)?;
                    }
                    if let Some(size) = begin.total_size {
                        bmo_in_progress.data.reserve(size as usize);
                    }
                    bmo_in_progress.begin = Some(begin);
                }
            } else if key.starts_with("image-data") {
                let chunk = value.as_bytes()
                    .context("Error parsing BMO image-data chunk")?;
                bmo_in_progress.data.extend_from_slice(chunk);
                log::trace!("BMO image-data: +{} bytes (total {})", chunk.len(), bmo_in_progress.data.len());
            } else if key == "image-end" {
                // Parse end map for hash
                let hash_bytes = match &value {
                    serde_cbor::Value::Map(m) => {
                        m.get(&serde_cbor::Value::Integer(1)).and_then(|v| match v {
                            serde_cbor::Value::Bytes(b) => Some(b.as_slice()),
                            _ => None,
                        })
                    }
                    _ => None,
                };
                let hash_alg = bmo_in_progress.begin.as_ref().and_then(|b| b.hash_alg.clone());
                bmo_in_progress.finalize(hash_bytes, &hash_alg, si_out)
                    .context("Error finalizing BMO image")?;
                *bmo_in_progress = BmoInProgress::new();
            } else if key == "set" {
                bmo_handle_set(&value, si_out)
                    .context("Error handling BMO set")?;
            }
        }
    }

    // Perform SSH or password setup
    if active_modules.contains(&FedoraIotServiceInfoModule::SSHKey.into()) {
        if sshkey_user.is_none() {
            bail!("SSHkey module missing username");
        } else if sshkey_keys.is_none() && sshkey_password.is_none() {
            bail!("SSHkey module missing password and key");
        }
        if sshkey_password.is_some() {
            log::info!("SSHkey module was active, creating user with password");
            create_user_with_password(
                sshkey_user.as_ref().unwrap(),
                sshkey_password.as_ref().unwrap(),
            )
            .context(format!(
                "Error creating new user with password: {}",
                sshkey_user.as_ref().unwrap()
            ))?;
        }
        if let Some(sshkey_keys) = sshkey_keys {
            log::info!("SSHkey module was active, installing SSH keys");
            create_user(sshkey_user.as_ref().unwrap()).context(format!(
                "Error creating new user: {}",
                sshkey_user.as_ref().unwrap()
            ))?;
            let sshkey_keys_v: Vec<String> =
                sshkey_keys.split(';').map(|s| s.to_string()).collect();
            for key in sshkey_keys_v {
                let key_s: String = key;
                install_ssh_key(sshkey_user.as_ref().unwrap(), key_s.as_str())
                    .context("Error installing SSH key")?;
                log::info!("Installed sshkey: {key_s}");
            }
        }
    }

    // Perform RHSM
    if active_modules.contains(&RedHatComServiceInfoModule::SubscriptionManager.into()) {
        log::debug!("RHSM module was active, running RHSM");
        if rhsm_organization_id.is_none()
            || rhsm_activation_key.is_none()
            || rhsm_perform_insights.is_none()
        {
            bail!("Missing one of the RHSM module configurations");
        }
        perform_rhsm(
            rhsm_organization_id.as_ref().unwrap(),
            rhsm_activation_key.as_ref().unwrap(),
            rhsm_perform_insights.unwrap(),
        )
        .context("Error performing RHSM enrollment")?;
    }

    Ok(reboot_requested)
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

            // We just blindly send the devmod module
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

        // Process current batch of serviceinfo
        let reboot_si = process_serviceinfo_in(
            return_si.service_info(), &mut out_si, &mut bmo_state, &mut active_modules,
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

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use super::BinaryFileInProgress;

    use crate::serviceinfo::*;
    use fdo_util::system_info::get_current_user_name;

    #[test]
    fn test_binaryfileinprogress_destination_path() {
        assert_eq!(
            BinaryFileInProgress::destination_path(
                &String::from("/etc/something"),
                Some("/usr/prefix")
            )
            .unwrap(),
            PathBuf::from("/usr/prefix/etc/something")
        );
        assert_eq!(
            BinaryFileInProgress::destination_path(&String::from("/etc/something"), None).unwrap(),
            PathBuf::from("/etc/something")
        );
    }

    #[test]
    fn test_pw_encryption() {
        let type_5_encryption = "$5$ML4hMHtER3/SY9D2$2eWHscoFbfVebDC32qA2dPo3pD6FFM6CRTrvAOMpwQ";
        assert!(is_password_encrypted(type_5_encryption));
        let type_2b_encryption = "$2b$ML4hMHtER3/SY9D2$2eWHscoFbfVebDC32qA2dPo3pD6FFM6CRTrvAOMpwQ";
        assert!(is_password_encrypted(type_2b_encryption));
        let type_6_encryption = "$6$ML4hMHtER3/SY9D2$2eWHscoFbfVebDC32qA2dPo3pD6FFM6CRTrvAOMpwQ";
        assert!(is_password_encrypted(type_6_encryption));
        let plaintext_encryption = "testpassword";
        assert!(!is_password_encrypted(plaintext_encryption));
        let empty_pw = "";
        assert!(!is_password_encrypted(empty_pw));
    }

    #[test]
    #[ignore = "to run this test you must be root and run `cargo test -- --ignored`"]
    fn test_user_creation_no_pw() {
        let current_user_name = get_current_user_name();
        assert_eq!(current_user_name, "root");
        let test_user = "test";
        assert!(create_user(test_user).is_ok());
        let empty_user = "";
        assert!(create_user(empty_user).is_err());
        let at_user = "test@test";
        assert!(create_user(at_user).is_err());
        let dash_user = "-test";
        assert!(create_user(dash_user).is_err());
        let digits_user = "12345";
        assert!(create_user(digits_user).is_err());
    }

    #[test]
    #[ignore = "to run this test you must be root and run `cargo test -- --ignored`"]
    fn test_user_creation_with_pw() {
        let current_user_name = get_current_user_name();
        assert_eq!(current_user_name, "root");
        let test_user = "testb";
        let test_password = "password";
        assert!(create_user_with_password(test_user, test_password).is_ok());
        let empty_user = "";
        assert!(create_user_with_password(empty_user, test_password).is_err());
        let at_user = "testb@testb";
        assert!(create_user_with_password(at_user, test_password).is_err());
        let dash_user = "-testb";
        assert!(create_user_with_password(dash_user, test_password).is_err());
        let digits_user = "123456";
        assert!(create_user_with_password(digits_user, test_password).is_err());
        let empty_password = "";
        assert!(create_user_with_password(test_user, empty_password).is_ok());
    }
}
