// no_std support for UEFI
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "std")]
mod errors;
#[cfg(feature = "std")]
pub use errors::Error;

// Simple error type for no_std
#[cfg(not(feature = "std"))]
#[derive(Debug, Clone)]
pub struct Error(pub alloc::string::String);

#[cfg(not(feature = "std"))]
impl Error {
    pub fn new(msg: &str) -> Self {
        Error(alloc::string::String::from(msg))
    }
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "std")]
pub mod constants;
#[cfg(feature = "std")]
pub use constants::ProtocolVersion;

#[cfg(not(feature = "std"))]
pub mod constants_uefi;
#[cfg(not(feature = "std"))]
pub use constants_uefi as constants;
#[cfg(not(feature = "std"))]
pub use constants_uefi::ProtocolVersion;

#[cfg(feature = "std")]
pub mod devicecredential;
#[cfg(feature = "std")]
pub use crate::devicecredential::DeviceCredential;

// Types module - std version uses full types, no_std uses simplified UEFI types
#[cfg(feature = "std")]
pub mod types;

#[cfg(not(feature = "std"))]
pub mod types_uefi;
#[cfg(not(feature = "std"))]
pub use types_uefi as types;

#[cfg(feature = "std")]
pub mod enhanced_types;

#[cfg(feature = "std")]
pub mod ownershipvoucher;

#[cfg(feature = "std")]
pub mod publickey;

// Messages module - std version uses full messages, no_std uses simplified UEFI messages
#[cfg(feature = "std")]
pub mod messages;

#[cfg(not(feature = "std"))]
pub mod messages_uefi;
#[cfg(not(feature = "std"))]
pub use messages_uefi as messages;

#[cfg(feature = "std")]
pub mod cborparser;

#[cfg(feature = "std")]
pub mod cose_aad;

#[cfg(feature = "tpm_support")]
pub mod tpm;

#[cfg(feature = "std")]
mod serializable;
#[cfg(feature = "std")]
pub use serializable::DeserializableMany;
#[cfg(feature = "std")]
pub use serializable::Serializable;
#[cfg(feature = "std")]
pub use serializable::StoredItem;

// Simplified serializable for no_std using ciborium
#[cfg(not(feature = "std"))]
mod serializable_nostd;
#[cfg(not(feature = "std"))]
pub use serializable_nostd::Serializable;

#[cfg(feature = "std")]
pub fn interoperable_kdf_available() -> bool {
    #[cfg(feature = "use_noninteroperable_kdf")]
    {
        false
    }
    #[cfg(not(feature = "use_noninteroperable_kdf"))]
    {
        if std::env::var("FORCE_NONINTEROPERABLE_KDF").is_ok() {
            log::warn!("Forcing the use of non-interoperable KDF via environment variable");
            false
        } else {
            true
        }
    }
}

#[cfg(not(feature = "std"))]
pub fn interoperable_kdf_available() -> bool {
    true
}
