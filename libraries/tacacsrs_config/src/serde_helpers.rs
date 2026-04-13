#![allow(clippy::ref_option)]

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

pub(crate) mod base64_binary {
    use super::BASE64;

    pub(crate) mod bytes {
        use base64::Engine;
        use serde::Deserialize;

        use super::BASE64;

        pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(&BASE64.encode(value))
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let encoded = String::deserialize(deserializer)?;
            BASE64.decode(encoded).map_err(serde::de::Error::custom)
        }
    }

    pub(crate) mod option_bytes {
        use base64::Engine;
        use serde::Deserialize;

        use super::BASE64;

        pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            match value {
                Some(bytes) => serializer.serialize_some(&BASE64.encode(bytes)),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            Option::<String>::deserialize(deserializer)?
                .map(|encoded| BASE64.decode(encoded).map_err(serde::de::Error::custom))
                .transpose()
        }
    }

    #[allow(dead_code)]
    pub(crate) mod vec_bytes {
        use base64::Engine;
        use serde::Deserialize;
        use serde::Serialize;

        use super::BASE64;

        pub fn serialize<S>(value: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let encoded = value
                .iter()
                .map(|bytes| BASE64.encode(bytes))
                .collect::<Vec<_>>();
            encoded.serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            Vec::<String>::deserialize(deserializer)?
                .into_iter()
                .map(|encoded| BASE64.decode(encoded).map_err(serde::de::Error::custom))
                .collect()
        }
    }
}
