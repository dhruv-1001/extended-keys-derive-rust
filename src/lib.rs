use std::ops::Deref;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::util::bip32::DerivationPath as BdkDerivationPath;
use bdk::bitcoin::Network;
use bdk::descriptor::DescriptorXKey;
use bdk::keys::bip39::{Language, Mnemonic};
use bdk::keys::{
    DerivableKey, DescriptorPublicKey as BdkDescriptorPublicKey,
    DescriptorSecretKey as BdkDescriptorSecretKey, ExtendedKey,
};
use bdk::Error as BdkError;

#[allow(dead_code)]
struct DescriptorSecretKey {
    descriptor_secret_key_mutex: Mutex<BdkDescriptorSecretKey>,
}

#[allow(dead_code)]
impl DescriptorSecretKey {
    fn new(network: Network, mnemonic: String, password: Option<String>) -> Result<Self, BdkError> {
        let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)
            .map_err(|e| BdkError::Generic(e.to_string()))?;
        let xkey: ExtendedKey = (mnemonic, password).into_extended_key()?;
        let descriptor_secret_key = BdkDescriptorSecretKey::XPrv(DescriptorXKey {
            origin: None,
            xkey: xkey.into_xprv(network).unwrap(),
            derivation_path: BdkDerivationPath::master(),
            wildcard: bdk::descriptor::Wildcard::None,
        });
        Ok(Self {
            descriptor_secret_key_mutex: Mutex::new(descriptor_secret_key),
        })
    }
    // let key_source: KeySource = match descriptor_xprv.origin.clone() {
    //     None => (descriptor_xprv.xkey.fingerprint(&secp), path.clone()),
    //     Some((fingerprint, origin_path)) => {
    //         (fingerprint, origin_path.extend(path.clone()))
    //     }
    // };

    fn derive(&self, path: Arc<DerivationPath>) -> Result<Arc<Self>, BdkError> {
        let secp = Secp256k1::new();
        let descriptor_secret_key = self.descriptor_secret_key_mutex.lock().unwrap();
        let path = path.derivation_path_mutex.lock().unwrap().deref().clone();
        let descriptor_x_key = match descriptor_secret_key.deref() {
            BdkDescriptorSecretKey::XPrv(descriptor_x_key) => Some(descriptor_x_key),
            _ => None,
        }
        .unwrap();
        let derived_xprv = descriptor_x_key.xkey.derive_priv(&secp, &path).unwrap();
        let key_source = match descriptor_x_key.origin.clone() {
            Some((fingerprint, origin_path)) => (fingerprint, origin_path.extend(path.clone())),
            None => (descriptor_x_key.xkey.fingerprint(&secp), path.clone()),
        };
        let derived_descriptor_secret_key = BdkDescriptorSecretKey::XPrv(DescriptorXKey {
            origin: Some(key_source),
            xkey: derived_xprv,
            derivation_path: BdkDerivationPath::default(),
            wildcard: bdk::descriptor::Wildcard::None,
        });
        Ok(Arc::new(Self {
            descriptor_secret_key_mutex: Mutex::new(derived_descriptor_secret_key),
        }))
    }

    fn extend(&self, path: Arc<DerivationPath>) -> Result<Arc<Self>, BdkError> {
        let secp = Secp256k1::new();
        let descriptor_secret_key = self.descriptor_secret_key_mutex.lock().unwrap();
        let path = path.derivation_path_mutex.lock().unwrap().deref().clone();
        let descriptor_x_key = match descriptor_secret_key.deref() {
            BdkDescriptorSecretKey::XPrv(descriptor_x_key) => Some(descriptor_x_key),
            _ => None,
        }
        .unwrap();
        let key_source = match descriptor_x_key.origin.clone() {
            Some((fingerprint, origin_path)) => (fingerprint, origin_path.extend(path.clone())),
            None => (descriptor_x_key.xkey.fingerprint(&secp), path.clone()),
        };
        let extended_path = descriptor_x_key.derivation_path.extend(path);
        let extended_descriptor_secret_key = BdkDescriptorSecretKey::XPrv(DescriptorXKey {
            origin: Some(key_source),
            xkey: descriptor_x_key.xkey,
            derivation_path: extended_path,
            wildcard: bdk::descriptor::Wildcard::None,
        });
        Ok(Arc::new(Self {
            descriptor_secret_key_mutex: Mutex::new(extended_descriptor_secret_key),
        }))
    }

    // fn as_public(&self) -> Arc<DescriptorPublicKey> {

    // }

    fn as_string(&self) -> String {
        self.descriptor_secret_key_mutex.lock().unwrap().to_string()
    }
}

#[allow(dead_code)]
struct DescriptorPublicKey {
    descriptor_public_key_mutex: Mutex<BdkDescriptorPublicKey>,
}

#[allow(dead_code)]
impl DescriptorPublicKey {
    // fn derive(&self, path: Arc<DerivationPath>) -> Result<Arc<Self>, BdkError> {

    // }

    // fn extend(&self, path: Arc<DerivationPath>) -> Result<Arc<Self>, BdkError> {

    // }

    fn as_string(&self) -> String {
        self.descriptor_public_key_mutex.lock().unwrap().to_string()
    }
}

#[derive(Debug)]
struct DerivationPath {
    derivation_path_mutex: Mutex<BdkDerivationPath>,
}

#[allow(dead_code)]
impl DerivationPath {
    fn new(path: String) -> Result<Self, BdkError> {
        BdkDerivationPath::from_str(&path)
            .map(|x| DerivationPath {
                derivation_path_mutex: Mutex::new(x),
            })
            .map_err(|e| BdkError::Generic(e.to_string()))
    }
}

#[cfg(test)]
mod test {
    use crate::*;

    fn get_descriptor_secret_key() -> DescriptorSecretKey {
        let mnemonic =
        "chaos fabric time speed sponsor all flat solution wisdom trophy crack object robot pave observe combine where aware bench orient secret primary cable detect".to_string();
        DescriptorSecretKey::new(Network::Testnet, mnemonic, None).unwrap()
    }

    fn derive_descriptor_secret_key(
        descriptor_secret_key: DescriptorSecretKey,
        path: String,
    ) -> Arc<DescriptorSecretKey> {
        let path = DerivationPath::new(path).unwrap();
        descriptor_secret_key.derive(Arc::new(path)).unwrap()
    }

    fn extend_descriptor_secret_key(
        descriptor_secret_key: DescriptorSecretKey,
        path: String,
    ) -> Arc<DescriptorSecretKey> {
        let path = DerivationPath::new(path).unwrap();
        descriptor_secret_key.derive(Arc::new(path)).unwrap()
    }

    #[test]
    fn test_generate_descriptor_secret_key() {
        let descriptor_secret_key = get_descriptor_secret_key();
        assert_eq!(descriptor_secret_key.as_string(), "tprv8ZgxMBicQKsPdWuqM1t1CDRvQtQuBPyfL6GbhQwtxDKgUAVPbxmj71pRA8raTqLrec5LyTs5TqCxdABcZr77bt2KyWA5bizJHnC4g4ysm4h")
    }

    #[test]
    fn test_derive_descriptor_secret_key() {
        let descriptor_secret_key = get_descriptor_secret_key();
        let derived_descriptor_secret_key =
            derive_descriptor_secret_key(descriptor_secret_key, "m/0".to_string());
        assert_eq!(derived_descriptor_secret_key.as_string(), "[d1d04177/0]tprv8d7Y4JLmD25jkKbyDZXcdoPHu1YtMHuH21qeN7mFpjfumtSU7eZimFYUCSa3MYzkEYfSNRBV34GEr2QXwZCMYRZ7M1g6PUtiLhbJhBZEGYJ")
    }

    #[test]
    fn test_extend_descriptor_secret_key() {
        let descriptor_secret_key = get_descriptor_secret_key();
        let extended_descriptor_secret_key: &DescriptorSecretKey =
            &extend_descriptor_secret_key(descriptor_secret_key, "m/0".to_string());
        let extended_descriptor_secret_key = extended_descriptor_secret_key
            .descriptor_secret_key_mutex
            .lock()
            .unwrap();
        let descriptor_x_key = match extended_descriptor_secret_key.deref() {
            BdkDescriptorSecretKey::XPrv(descriptor_x_key) => Some(descriptor_x_key),
            _ => None,
        }
        .unwrap();
        assert_eq!(
            descriptor_x_key.origin.as_ref().unwrap().1,
            BdkDerivationPath::from_str("m/0").unwrap()
        )
    }
}
