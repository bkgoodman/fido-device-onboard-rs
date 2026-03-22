use std::{fmt::Display, str::FromStr};

impl<'de> serde::Deserialize<'de> for ServiceInfoModule {
    fn deserialize<D>(deserializer: D) -> Result<ServiceInfoModule, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        struct SIMVisitor;
        impl serde::de::Visitor<'_> for SIMVisitor {
            type Value = ServiceInfoModule;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a module string")
            }

            fn visit_str<E>(self, value: &str) -> Result<ServiceInfoModule, E>
            where
                E: serde::de::Error,
            {
                ServiceInfoModule::from_str(value).map_err(|e| E::custom(format!("{e}")))
            }
        }
        deserializer.deserialize_string(SIMVisitor)
    }
}

impl serde::Serialize for ServiceInfoModule {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServiceInfoModule {
    Standard(StandardServiceInfoModule),
    Fdo(FdoServiceInfoModule),
    Unsupported(String),
}

impl FromStr for ServiceInfoModule {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "devmod" => StandardServiceInfoModule::DevMod.into(),
            "fdo.bmo" => FdoServiceInfoModule::Bmo.into(),
            other => ServiceInfoModule::Unsupported(other.to_string()),
        })
    }
}

impl From<StandardServiceInfoModule> for ServiceInfoModule {
    fn from(module: StandardServiceInfoModule) -> Self {
        ServiceInfoModule::Standard(module)
    }
}

impl From<FdoServiceInfoModule> for ServiceInfoModule {
    fn from(module: FdoServiceInfoModule) -> Self {
        ServiceInfoModule::Fdo(module)
    }
}

impl Display for ServiceInfoModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceInfoModule::Standard(module) => module.fmt(f),
            ServiceInfoModule::Fdo(module) => {
                write!(f, "fdo.")?;
                Display::fmt(module, f)
            }
            ServiceInfoModule::Unsupported(other) => write!(f, "{other}"),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum StandardServiceInfoModule {
    DevMod,
}

impl Display for StandardServiceInfoModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                StandardServiceInfoModule::DevMod => "devmod",
            }
        )
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum FdoServiceInfoModule {
    Bmo,
}

impl Display for FdoServiceInfoModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                FdoServiceInfoModule::Bmo => "bmo",
            }
        )
    }
}
