// no_std Serializable trait using minicbor-serde
use alloc::vec::Vec;
use crate::Error;

pub trait Serializable {
    fn deserialize_data(data: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;

    fn serialize_data(&self) -> Result<Vec<u8>, Error>;
}

// Blanket implementation for serde types using minicbor-serde
impl<T> Serializable for T
where
    T: serde::Serialize,
    T: serde::de::DeserializeOwned,
{
    fn deserialize_data(data: &[u8]) -> Result<Self, Error> {
        minicbor_serde::from_slice(data)
            .map_err(|e| Error(alloc::format!("CBOR decode error: {:?}", e)))
    }

    fn serialize_data(&self) -> Result<Vec<u8>, Error> {
        minicbor_serde::to_vec(self)
            .map_err(|e| Error(alloc::format!("CBOR encode error: {:?}", e)))
    }
}
