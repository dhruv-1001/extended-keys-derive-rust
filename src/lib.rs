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

pub fn lib_main() {
    println!("\nDescriptorSecretKey\n\n");
    // master
    let mnemonic =
        "chaos fabric time speed sponsor all flat solution wisdom trophy crack object robot pave observe combine where aware bench orient secret primary cable detect".to_string();
    let master_des = DescriptorSecretKey::new(Network::Testnet, mnemonic, None).unwrap();
    show_descriptor_x_key(&master_des, "master");

    // derive m/0 from master
    let derived_des: &DescriptorSecretKey = &derive_key(&master_des, "m/0");
    show_descriptor_x_key(&derived_des, "derive m/0 from master");

    // extend m/0 from master
    let extended_des: &DescriptorSecretKey = &extend_key(&master_des, "m/0");
    show_descriptor_x_key(&extended_des, "extend m/0 from master");

    // derive m/0 and extend m/0 from master
    let extend_derived_des: &DescriptorSecretKey = &extend_key(&derived_des, "m/0");
    show_descriptor_x_key(&extend_derived_des, "derive m/0 and extend m/0");

    // extend m/0 and extend m/0 from master
    let extend_extended_des: &DescriptorSecretKey = &extend_key(&extended_des, "m/0");
    show_descriptor_x_key(&extend_extended_des, "extend m/0 and extend m/0");

    // extend m/0 and derive m/0 from master
    let derive_extended_des = &derive_key(&extended_des, "m/0");
    show_descriptor_x_key(&derive_extended_des, "extend m/0 and derive m/0");
}

fn derive_key(key: &DescriptorSecretKey, path: &str) -> Arc<DescriptorSecretKey> {
    let path = Arc::new(DerivationPath::new(path.to_string()).unwrap());
    key.derive(path).unwrap()
}

fn extend_key(key: &DescriptorSecretKey, path: &str) -> Arc<DescriptorSecretKey> {
    let path = Arc::new(DerivationPath::new(path.to_string()).unwrap());
    key.extend(path).unwrap()
}

fn show_descriptor_x_key(key: &DescriptorSecretKey, message: &str) {
    println!("{}", message);
    println!(
        "{}",
        key.descriptor_secret_key_mutex.lock().unwrap().to_string()
    );
    let descriptor_secret_key = key.descriptor_secret_key_mutex.lock().unwrap();
    let key = match descriptor_secret_key.deref() {
        BdkDescriptorSecretKey::XPrv(key) => Some(key),
        _ => None,
    }
    .unwrap();

    println!("xkey            -> {}", key.xkey.to_string());
    println!("origin          -> {:?}", key.origin);
    println!("derivation_path -> {:?}", key.derivation_path);
    println!("wildcard        -> {:?}", key.wildcard);
    println!("================================")
}

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
            wildcard: bdk::descriptor::Wildcard::Unhardened,
        });
        Ok(Self {
            descriptor_secret_key_mutex: Mutex::new(descriptor_secret_key),
        })
    }

    fn derive(&self, path: Arc<DerivationPath>) -> Result<Arc<Self>, BdkError> {
        let secp = Secp256k1::new();
        let descriptor_secret_key = self.descriptor_secret_key_mutex.lock().unwrap();
        let path = path.derivation_path_mutex.lock().unwrap().deref().clone();
        let descriptor_x_key = match descriptor_secret_key.deref() {
            BdkDescriptorSecretKey::XPrv(descriptor_x_key) => Some(descriptor_x_key),
            _ => None,
        }
        .unwrap();
        let derived_xprv = descriptor_x_key.xkey.derive_priv(&secp, &path)?;
        let key_source = match descriptor_x_key.origin.clone() {
            Some((fingerprint, origin_path)) => (fingerprint, origin_path.extend(path.clone())),
            None => (descriptor_x_key.xkey.fingerprint(&secp), path.clone()),
        };
        let derived_descriptor_secret_key = BdkDescriptorSecretKey::XPrv(DescriptorXKey {
            origin: Some(key_source),
            xkey: derived_xprv,
            derivation_path: BdkDerivationPath::default(),
            wildcard: descriptor_x_key.wildcard,
        });
        Ok(Arc::new(Self {
            descriptor_secret_key_mutex: Mutex::new(derived_descriptor_secret_key),
        }))
    }

    fn extend(&self, path: Arc<DerivationPath>) -> Result<Arc<Self>, BdkError> {
        let descriptor_secret_key = self.descriptor_secret_key_mutex.lock().unwrap();
        let path = path.derivation_path_mutex.lock().unwrap().deref().clone();
        let descriptor_x_key = match descriptor_secret_key.deref() {
            BdkDescriptorSecretKey::XPrv(descriptor_x_key) => Some(descriptor_x_key),
            _ => None,
        }
        .unwrap();
        let extended_path = descriptor_x_key.derivation_path.extend(path);
        let extended_descriptor_secret_key = BdkDescriptorSecretKey::XPrv(DescriptorXKey {
            origin: descriptor_x_key.origin.clone(),
            xkey: descriptor_x_key.xkey,
            derivation_path: extended_path,
            wildcard: descriptor_x_key.wildcard,
        });
        Ok(Arc::new(Self {
            descriptor_secret_key_mutex: Mutex::new(extended_descriptor_secret_key),
        }))
    }

    fn as_public(&self) -> Arc<DescriptorPublicKey> {
        let secp = Secp256k1::new();
        let descriptor_public_key = self
            .descriptor_secret_key_mutex
            .lock()
            .unwrap()
            .as_public(&secp)
            .unwrap();
        Arc::new(DescriptorPublicKey {
            descriptor_public_key_mutex: Mutex::new(descriptor_public_key),
        })
    }

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
    fn derive(&self, path: Arc<DerivationPath>) -> Result<Arc<Self>, BdkError> {
        let secp = Secp256k1::new();
        let descriptor_public_key = self.descriptor_public_key_mutex.lock().unwrap();
        let path = path.derivation_path_mutex.lock().unwrap().deref().clone();
        let descriptor_x_key = match descriptor_public_key.deref() {
            BdkDescriptorPublicKey::XPub(descriptor_x_key) => Some(descriptor_x_key),
            _ => None,
        }
        .unwrap();
        let derived_xpub = descriptor_x_key.xkey.derive_pub(&secp, &path)?;
        let key_source = match descriptor_x_key.origin.clone() {
            Some((fingerprint, origin_path)) => (fingerprint, origin_path.extend(path.clone())),
            None => (descriptor_x_key.xkey.fingerprint(), path.clone()),
        };
        let derived_descriptor_public_key = BdkDescriptorPublicKey::XPub(DescriptorXKey {
            origin: Some(key_source),
            xkey: derived_xpub,
            derivation_path: BdkDerivationPath::default(),
            wildcard: descriptor_x_key.wildcard,
        });
        Ok(Arc::new(Self {
            descriptor_public_key_mutex: Mutex::new(derived_descriptor_public_key),
        }))
    }

    fn extend(&self, path: Arc<DerivationPath>) -> Result<Arc<Self>, BdkError> {
        let descriptor_secret_key = self.descriptor_public_key_mutex.lock().unwrap();
        let path = path.derivation_path_mutex.lock().unwrap().deref().clone();
        let descriptor_x_key = match descriptor_secret_key.deref() {
            BdkDescriptorPublicKey::XPub(descriptor_x_key) => Some(descriptor_x_key),
            _ => None,
        }
        .unwrap();
        let extended_path = descriptor_x_key.derivation_path.extend(path);
        let extended_descriptor_public_key = BdkDescriptorPublicKey::XPub(DescriptorXKey {
            origin: descriptor_x_key.origin.clone(),
            xkey: descriptor_x_key.xkey,
            derivation_path: extended_path,
            wildcard: descriptor_x_key.wildcard,
        });
        Ok(Arc::new(Self {
            descriptor_public_key_mutex: Mutex::new(extended_descriptor_public_key),
        }))
    }

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

    fn derive_dsk(
        key: &DescriptorSecretKey,
        path: &str,
    ) -> Result<Arc<DescriptorSecretKey>, BdkError> {
        let path = Arc::new(DerivationPath::new(path.to_string()).unwrap());
        key.derive(path)
    }

    fn extend_dsk(
        key: &DescriptorSecretKey,
        path: &str,
    ) -> Result<Arc<DescriptorSecretKey>, BdkError> {
        let path = Arc::new(DerivationPath::new(path.to_string()).unwrap());
        key.extend(path)
    }

    fn derive_dpk(
        key: &DescriptorPublicKey,
        path: &str,
    ) -> Result<Arc<DescriptorPublicKey>, BdkError> {
        let path = Arc::new(DerivationPath::new(path.to_string()).unwrap());
        key.derive(path)
    }

    fn extend_dpk(
        key: &DescriptorPublicKey,
        path: &str,
    ) -> Result<Arc<DescriptorPublicKey>, BdkError> {
        let path = Arc::new(DerivationPath::new(path.to_string()).unwrap());
        key.extend(path)
    }

    #[test]
    fn test_generate_descriptor_secret_key() {
        let master_dsk = get_descriptor_secret_key();
        assert_eq!(master_dsk.as_string(), "tprv8ZgxMBicQKsPdWuqM1t1CDRvQtQuBPyfL6GbhQwtxDKgUAVPbxmj71pRA8raTqLrec5LyTs5TqCxdABcZr77bt2KyWA5bizJHnC4g4ysm4h/*");
        assert_eq!(master_dsk.as_public().as_string(), "tpubD6NzVbkrYhZ4WywdEfYbbd62yuvqLjAZuPsNyvzCNV85JekAEMbKHWSHLF9h3j45SxewXDcLv328B1SEZrxg4iwGfmdt1pDFjZiTkGiFqGa/*");
    }

    #[test]
    fn test_derive_self() {
        let master_dsk = get_descriptor_secret_key();
        let derived_dsk: &DescriptorSecretKey = &derive_dsk(&master_dsk, "m").unwrap();
        assert_eq!(derived_dsk.as_string(), "[d1d04177]tprv8ZgxMBicQKsPdWuqM1t1CDRvQtQuBPyfL6GbhQwtxDKgUAVPbxmj71pRA8raTqLrec5LyTs5TqCxdABcZr77bt2KyWA5bizJHnC4g4ysm4h/*");

        let master_dpk: &DescriptorPublicKey = &master_dsk.as_public();
        let derived_dpk: &DescriptorPublicKey = &derive_dpk(master_dpk, "m").unwrap();
        assert_eq!(derived_dpk.as_string(), "[d1d04177]tpubD6NzVbkrYhZ4WywdEfYbbd62yuvqLjAZuPsNyvzCNV85JekAEMbKHWSHLF9h3j45SxewXDcLv328B1SEZrxg4iwGfmdt1pDFjZiTkGiFqGa/*");
    }

    #[test]
    fn test_derive_descriptors_keys() {
        let master_dsk = get_descriptor_secret_key();
        let derived_dsk: &DescriptorSecretKey = &derive_dsk(&master_dsk, "m/0").unwrap();
        assert_eq!(derived_dsk.as_string(), "[d1d04177/0]tprv8d7Y4JLmD25jkKbyDZXcdoPHu1YtMHuH21qeN7mFpjfumtSU7eZimFYUCSa3MYzkEYfSNRBV34GEr2QXwZCMYRZ7M1g6PUtiLhbJhBZEGYJ/*");

        let master_dpk: &DescriptorPublicKey = &master_dsk.as_public();
        let derived_dpk: &DescriptorPublicKey = &derive_dpk(master_dpk, "m/0").unwrap();
        assert_eq!(derived_dpk.as_string(), "[d1d04177/0]tpubD9oaCiP1MPmQdndm7DCD3D3QU34pWd6BbKSRedoZF1UJcNhEk3PJwkALNYkhxeTKL29oGNR7psqvT1KZydCGqUDEKXN6dVQJY2R8ooLPy8m/*");
    }

    #[test]
    fn test_extend_descriptor_keys() {
        let master_dsk = get_descriptor_secret_key();
        let extended_dsk: &DescriptorSecretKey = &extend_dsk(&master_dsk, "m/0").unwrap();
        assert_eq!(extended_dsk.as_string(), "tprv8ZgxMBicQKsPdWuqM1t1CDRvQtQuBPyfL6GbhQwtxDKgUAVPbxmj71pRA8raTqLrec5LyTs5TqCxdABcZr77bt2KyWA5bizJHnC4g4ysm4h/0/*");

        let master_dpk: &DescriptorPublicKey = &master_dsk.as_public();
        let extended_dpk: &DescriptorPublicKey = &extend_dpk(master_dpk, "m/0").unwrap();
        assert_eq!(extended_dpk.as_string(), "tpubD6NzVbkrYhZ4WywdEfYbbd62yuvqLjAZuPsNyvzCNV85JekAEMbKHWSHLF9h3j45SxewXDcLv328B1SEZrxg4iwGfmdt1pDFjZiTkGiFqGa/0/*");
    }

    #[test]
    fn test_derive_and_extend_descriptor_secret_key() {
        let master_dsk = get_descriptor_secret_key();

        // derive DescriptorSecretKey with path "m/0" from master
        let derived_dsk: &DescriptorSecretKey = &derive_dsk(&master_dsk, "m/0").unwrap();
        assert_eq!(derived_dsk.as_string(), "[d1d04177/0]tprv8d7Y4JLmD25jkKbyDZXcdoPHu1YtMHuH21qeN7mFpjfumtSU7eZimFYUCSa3MYzkEYfSNRBV34GEr2QXwZCMYRZ7M1g6PUtiLhbJhBZEGYJ/*");

        // extend derived_dsk with path "m/0"
        let extended_dsk: &DescriptorSecretKey = &extend_dsk(derived_dsk, "m/0").unwrap();
        assert_eq!(extended_dsk.as_string(), "[d1d04177/0]tprv8d7Y4JLmD25jkKbyDZXcdoPHu1YtMHuH21qeN7mFpjfumtSU7eZimFYUCSa3MYzkEYfSNRBV34GEr2QXwZCMYRZ7M1g6PUtiLhbJhBZEGYJ/0/*");
        let extended_dsk_mutex = extended_dsk.descriptor_secret_key_mutex.lock().unwrap();

        // checking extended derivation_path
        assert_eq!(
            match extended_dsk_mutex.deref() {
                BdkDescriptorSecretKey::XPrv(xkey) => {
                    Some(xkey.derivation_path.clone())
                }
                _ => {
                    None
                }
            }
            .unwrap()
            .to_string(),
            BdkDerivationPath::from_str("m/0").unwrap().to_string()
        );
    }

    #[test]
    fn test_derive_hardened_path_using_public() {
        let master_dpk = get_descriptor_secret_key().as_public();
        let derived_dpk = &derive_dpk(&master_dpk, "m/84h/1h/0h");
        assert!(derived_dpk.is_err());
    }
}
