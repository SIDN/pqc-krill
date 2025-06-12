//! Support for signing things using software keys (through liboqs) and
//! storing them unencrypted on disk.
use std::{
    str::FromStr,
    sync::{Arc, RwLock},
};

use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::engine::Engine as _;
use kvx::{namespace, Namespace};
use rpki::{crypto::{
    signer::KeyError,
    KeyIdentifier, PublicKey, PublicKeyFormat, RpkiSignature,
    RpkiSignatureAlgorithm, Signature, SigningError,
}, dep::bcder::{decode::{self, DecodeError, Source}, encode::{self, Values}, Mode, OctetString, Tag}};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

use crate::commons::{
    crypto::{
        dispatch::signerinfo::SignerMapper, signers::error::SignerError,
        SignerHandle,
    },
    eventsourcing::{Key, KeyValueStore, Segment, SegmentExt},
};

//------------ OQSSigner -------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Hash, PartialEq, Eq)]
pub struct OQSSignerConfig {
    #[serde(default)]
    pub keys_storage_uri: Option<Url>,
}

impl OQSSignerConfig {
    pub fn new(storage_uri: Url) -> Self {
        Self {
            keys_storage_uri: Some(storage_uri),
        }
    }
}

#[derive(Debug)]
pub struct OQSSigner {
    keys_store: KeyValueStore,

    name: String,

    handle: RwLock<Option<SignerHandle>>,

    info: Option<String>,

    mapper: Option<Arc<SignerMapper>>,
}

impl OQSSigner {
    pub fn build(
        storage_uri: &Url,
        name: &str,
        mapper: Option<Arc<SignerMapper>>,
    ) -> Result<Self, SignerError> {
        let keys_store = Self::init_keys_store(storage_uri)?;

        let s = OQSSigner {
            name: name.to_string(),
            info: Some(format!(
                "OQS Soft Signer [keys store: {}]",
                storage_uri,
            )),
            handle: RwLock::new(None), // will be set later
            mapper,
            keys_store,
        };

        Ok(s)
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn set_handle(&self, handle: SignerHandle) {
        let mut writable_handle = self.handle.write().unwrap();
        if writable_handle.is_some() {
            panic!("Cannot set signer handle as handle is already set");
        }
        *writable_handle = Some(handle);
    }

    pub fn get_info(&self) -> Option<String> {
        self.info.clone()
    }

    pub fn create_registration_key(
        &self,
    ) -> Result<(PublicKey, String), SignerError> {
        let key_id = self.build_key()?;
        let internal_key_id = key_id.to_string();
        let key_pair = self.load_key(&key_id)?;
        let public_key = key_pair.get_key_info().map_err(SignerError::other)?;
        Ok((public_key, internal_key_id))
    }

    pub fn sign_registration_challenge<D: AsRef<[u8]> + ?Sized>(
        &self,
        signer_private_key_id: &str,
        challenge: &D,
    ) -> Result<RpkiSignature, SignerError> {
        let key_id = KeyIdentifier::from_str(signer_private_key_id)
            .map_err(|_| SignerError::KeyNotFound)?;
        let key_pair = self.load_key(&key_id)?;
        let signature = key_pair.sign(challenge.as_ref()).map_err(SignerError::other)?; 
        Ok(signature)
    }
}

pub const OQS_KEYS_NS: &Namespace = namespace!("oqs_keys");

impl OQSSigner {
    fn init_keys_store(
        storage_uri: &Url,
    ) -> Result<KeyValueStore, SignerError> {
        let store = KeyValueStore::create(storage_uri, OQS_KEYS_NS)
            .map_err(|_| SignerError::InvalidStorage(storage_uri.clone()))?;
        Ok(store)
    }

    fn build_key(&self) -> Result<KeyIdentifier, SignerError> {
        let kp = OQSKeyPair::new(PublicKeyFormat::MlDsa65).map_err(SignerError::other)?;
        self.store_key(kp)
    }

    fn store_key(
        &self,
        kp: OQSKeyPair,
    ) -> Result<KeyIdentifier, SignerError> {
        let pk = &kp.get_key_info().map_err(SignerError::other)?;
        let key_id = pk.key_identifier();

        let json = serde_json::to_value(&kp)?;
        match self
            .keys_store
            .store(&Key::new_global(Segment::parse_lossy(&key_id.to_string())), &json) // key_id should always be a valid Segment
        {
            Ok(_) => Ok(key_id),
            Err(err) => Err(SignerError::Other(format!("Failed to store key: {}:", err))),
        }
    }

    fn load_key(
        &self,
        key_id: &KeyIdentifier,
    ) -> Result<OQSKeyPair, SignerError> {
        match self
            .keys_store
            .get(&Key::new_global(Segment::parse_lossy(&key_id.to_string()))) // key_id should always be a valid Segment
        {
            Ok(Some(kp)) => Ok(kp),
            Ok(None) => Err(SignerError::KeyNotFound),
            Err(err) => Err(SignerError::Other(format!("Failed to get key: {}", err))),
        }
    }

    fn remember_key_id(
        &self,
        key_id: &KeyIdentifier,
    ) -> Result<(), SignerError> {
        if let Some(mapper) = &self.mapper {
            let readable_handle = self.handle.read().unwrap();
            let signer_handle = readable_handle.as_ref().ok_or_else(|| {
                SignerError::other("Failed to record signer key: Signer handle not set")
            })?;
            mapper
                .add_key(signer_handle, key_id, &format!("{}", key_id))
                .map_err(|err| {
                    SignerError::Other(format!(
                        "Failed to record signer key: {}",
                        err
                    ))
                })
        } else {
            Ok(())
        }
    }
}

// Implement the functions defined by the `Signer` trait because
// `SignerProvider` expects to invoke them, but as the dispatching is not
// trait based we don't actually have to implement the `Signer` trait.
impl OQSSigner {
    pub fn create_key(
        &self
    ) -> Result<KeyIdentifier, SignerError> {

        let key_id = self.build_key()?;
        self.remember_key_id(&key_id)?;

        Ok(key_id)
    }

    pub fn get_key_info(
        &self,
        key_id: &KeyIdentifier,
    ) -> Result<PublicKey, KeyError<SignerError>> {
        let key_pair = self.load_key(key_id)?;
        Ok(key_pair.get_key_info().map_err(SignerError::other)?)
    }

    pub fn destroy_key(
        &self,
        key_id: &KeyIdentifier,
    ) -> Result<(), KeyError<SignerError>> {
        self.keys_store
            .drop_key(&Key::new_global(Segment::parse_lossy(
                &key_id.to_string(),
            ))) // key_id should always be a valid Segment
            .map_err(|_| KeyError::Signer(SignerError::KeyNotFound))
    }

    pub fn sign<D: AsRef<[u8]> + ?Sized>(
        &self,
        key_id: &KeyIdentifier,
        data: &D,
    ) -> Result<RpkiSignature, SigningError<SignerError>> {
        let key_pair = self.load_key(key_id)?;
        key_pair.sign(data.as_ref())
            .map_err(|e: oqs::Error| SigningError::Signer(SignerError::other(e)))
    }

    pub fn sign_one_off<D: AsRef<[u8]> + ?Sized>(
        &self,
        data: &D,
    ) -> Result<(RpkiSignature, PublicKey), SignerError> {
        let kp = OQSKeyPair::new(PublicKeyFormat::MlDsa65)
            .map_err(SignerError::other)?;
        let signature = kp.sign(data.as_ref())
            .map_err(|e| SignerError::other(e))?;
        let key = kp.get_key_info()
            .map_err(SignerError::other)?;

        Ok((signature, key))
    }
}

//------------ OQSKeyPair ------------------------------------------------

pub struct OQSKeyPair {
    alg: oqs::sig::Algorithm,
    pkey: oqs::sig::PublicKey,
    skey: oqs::sig::SecretKey,
}

impl OQSKeyPair {
    fn new(algorithm: PublicKeyFormat) -> Result<Self, oqs::Error> {
        match algorithm {
            PublicKeyFormat::MlDsa65 => {
                let sigalg = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65)?;
                let (pkey, skey) = sigalg.keypair()?;
                Ok(OQSKeyPair { pkey, skey, alg: oqs::sig::Algorithm::MlDsa65 })
            }
            _ => Err(oqs::Error::AlgorithmDisabled)
        }
        
    }

    fn sign(
        &self,
        data: &[u8]
    ) -> Result<RpkiSignature, oqs::Error> {
        let sigalg = oqs::sig::Sig::new(self.alg)?;
        let sig = sigalg.sign(data, &self.skey)?;
        Ok(Signature::new(RpkiSignatureAlgorithm::MlDsa65, sig.into_vec().into()))
    }

    fn get_key_info(&self) -> Result<PublicKey, oqs::Error> {
        match self.alg {
            oqs::sig::Algorithm::MlDsa65 => {
                Ok(PublicKey::mldsa65_from_bytes(self.pkey.clone().into_vec().into()))
            }
            _ => Err(oqs::Error::AlgorithmDisabled)
        }
    }

    pub fn decode<S: decode::IntoSource>(
        source: S
    ) -> Result<Self, DecodeError<<S::Source as Source>::Error>> {
        Mode::Der.decode(source, Self::take_from)
    }

    pub fn take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let alg = PublicKeyFormat::take_from(cons)?;
            match alg {
                PublicKeyFormat::MlDsa65 => {
                    let sigalg = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65)
                        .map_err(|_| cons.content_err("unsupported algorithm"))?;

                    let skey = sigalg.secret_key_from_bytes(
                        &OctetString::take_from(cons)?.into_bytes()
                    ).ok_or(cons.content_err("invalid secret key"))?.to_owned();

                    let pkey = sigalg.public_key_from_bytes(
                        &OctetString::take_from(cons)?.into_bytes()
                    ).ok_or(cons.content_err("invalid public key"))?.to_owned();

                    // We do not check whether the public key  
                    // corresponds to the private key.
                    Ok(OQSKeyPair { pkey, skey, alg: oqs::sig::Algorithm::MlDsa65 })
                }
                _ => Err(cons.content_err("unsupported algorithm"))
            }
        })
    }

    fn from_base64(base64: &str) -> Result<OQSKeyPair, SignerError> {
        let bytes = BASE64_ENGINE.decode(base64).map_err(|_| {
            SignerError::other("Cannot parse private key base64")
        })?;
        Self::decode(bytes.as_slice()).map_err(|e| {
            SignerError::Other(format!("Invalid private key: {}", e))
        })
    }
}

impl Serialize for OQSKeyPair {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // We encode the keypair into a custom format because the OQS library does not
        // support generating an expanded keypair from the seed or generating the public
        // key from the secret key or seed.
        // The custom format is:
        //
        // OQSKeyPair ::= SEQUENCE {
        //     alg AlgorithmIdentifier,
        //     skey OCTET STRING,
        //     pkey OCTET STRING,
        // }
        let der = encode::Constructed::new(
            Tag::SEQUENCE, 
            (
                {
                    match self.alg {
                        oqs::sig::Algorithm::MlDsa65 => PublicKeyFormat::MlDsa65.encode(),
                        _ => unreachable!()
                    }
                },
                OctetString::new(self.skey.clone().into_vec().into()).encode(),
                OctetString::new(self.pkey.clone().into_vec().into()).encode()
            ),
        ).to_captured(Mode::Der);
        let bytes = der.into_bytes();

        BASE64_ENGINE.encode(bytes).serialize(s)
    }
}

impl<'de> Deserialize<'de> for OQSKeyPair {
    fn deserialize<D>(d: D) -> Result<OQSKeyPair, D::Error>
    where
        D: Deserializer<'de>,
    {
        match String::deserialize(d) {
            Ok(base64) => {
                Self::from_base64(&base64).map_err(de::Error::custom)
            }
            Err(err) => Err(err),
        }
    }
}
