use std::ops::Deref;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::util::bip32::{DerivationPath as BdkDerivationPath, KeySource};
use bdk::bitcoin::Network;
use bdk::descriptor::Legacy;
use bdk::keys::bip39::{Language, Mnemonic, WordCount};
use bdk::keys::{
    DerivableKey, DescriptorKey as BdkDescriptorKey, DescriptorPublicKey, DescriptorSecretKey,
    ExtendedKey, GeneratableKey, GeneratedKey,
};
use bdk::miniscript::BareCtx;
use bdk::Error as BdkError;

#[allow(unused_imports)]
use extended_keys_derive_rust::lib_main;

/*

    Test cases
    generate master
    derive m/0 from master
    extend m/0 from master
    extend m/0 from derived m/0 from master
    derive m/0 from extended m/0 from master

*/

/*
different changes
*/

fn main() {
    this_main();
    // lib_main();
}

#[allow(dead_code)]
fn this_main() {
    println!("\nDescriptorKey\n\n");
    // master
    let mnemonic =
        "chaos fabric time speed sponsor all flat solution wisdom trophy crack object robot pave observe combine where aware bench orient secret primary cable detect".to_string();
    let master_des = DescriptorKey::new(Network::Testnet, mnemonic, None).unwrap();
    show_descriptor_key_data(&master_des, "master");

    // derive m/0 from master
    let derived_des: &DescriptorKey = &derive_key(&master_des, "m/0");
    show_descriptor_key_data(derived_des, "derive m/0 from master");

    // extend m/0 from master
    let extended_des = &extend_key(&master_des, "m/0");
    show_descriptor_key_data(extended_des, "extend m/0 from master");

    // derive m/0 and extend m/0 from master
    let extend_derived_des: &DescriptorKey = &extend_key(derived_des, "m/0");
    show_descriptor_key_data(extend_derived_des, "derive m/0 and extend m/0");

    // extend m/0 and extend m/0 from master
    let extend_extended_des: &DescriptorKey = &extend_key(extended_des, "m/0");
    show_descriptor_key_data(extend_extended_des, "extend m/0 and extend m/0");

    // extend m/0 and derive m/0 from master
    let derive_extended_des = &derive_key(extended_des, "m/0");
    show_descriptor_key_data(derive_extended_des, "extend m/0 and derive m/0");

    let derive_hardened_des = &derive_key(&master_des, "m/84h/1h/0h");
    show_descriptor_key_data(derive_hardened_des, "derive m/84h/1h/0h from master")
}

#[allow(dead_code)]
fn derive_key(key: &DescriptorKey, path: &str) -> Arc<DescriptorKey> {
    let path = Arc::new(DerivationPath::new(path.to_string()).unwrap());
    key.derive(Some(path), None).unwrap()
}

#[allow(dead_code)]
fn extend_key(key: &DescriptorKey, path: &str) -> Arc<DescriptorKey> {
    let path = Arc::new(DerivationPath::new(path.to_string()).unwrap());
    key.derive(None, Some(path)).unwrap()
}

#[allow(dead_code)]
fn show_descriptor_key_data(descriptor_key: &DescriptorKey, message: &str) {
    println!("{}", message);
    let key = descriptor_key.descriptor_key_mutex.lock().unwrap();
    match key.deref() {
        BdkDescriptorKey::Secret(key, _, _) => {
            println!("{}", key)
        }
        BdkDescriptorKey::Public(key, _, _) => {
            println!("{}", key)
        }
    }
    match key.deref() {
        BdkDescriptorKey::Secret(DescriptorSecretKey::XPrv(xprv), _, _) => {
            println!("xkey            -> {}", xprv.xkey);
            println!("origin          -> {:?}", xprv.origin);
            println!("derivation_path -> {:?}", xprv.derivation_path);
            println!("wildcard        -> {:?}", xprv.wildcard);
        }
        BdkDescriptorKey::Public(DescriptorPublicKey::XPub(xpub), _, _) => {
            println!("xkey            -> {}", xpub.xkey);
            println!("origin          -> {:?}", xpub.origin);
            println!("derivation_path -> {:?}", xpub.derivation_path);
            println!("wildcard        -> {:?}", xpub.wildcard);
        }
        _ => todo!(),
    }
    println!("================================")
}

#[allow(dead_code)]
fn generate_mnemonic(word_count: WordCount) -> Result<String, BdkError> {
    let mnemonic: GeneratedKey<_, BareCtx> =
        Mnemonic::generate((word_count, Language::English)).unwrap();
    Ok(mnemonic.to_string())
}

#[allow(dead_code)]
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

#[allow(dead_code)]
#[derive(Debug)]
struct DescriptorKey {
    descriptor_key_mutex: Mutex<BdkDescriptorKey<Legacy>>,
}

#[allow(dead_code)]
impl DescriptorKey {
    fn new(network: Network, mnemonic: String, password: Option<String>) -> Result<Self, BdkError> {
        let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)
            .map_err(|e| BdkError::Generic(e.to_string()))?;
        let xkey: ExtendedKey = (mnemonic, password).into_extended_key()?;
        let descriptor_key = xkey
            .into_xprv(network)
            .unwrap()
            .into_descriptor_key(None, BdkDerivationPath::master())?;
        Ok(Self {
            descriptor_key_mutex: Mutex::new(descriptor_key),
        })
    }

    fn derive(
        &self,
        origin_path: Option<Arc<DerivationPath>>,
        descriptor_path: Option<Arc<DerivationPath>>,
    ) -> Result<Arc<DescriptorKey>, BdkError> {
        let secp = Secp256k1::new();
        let root_key = self.descriptor_key_mutex.lock().unwrap();
        let root_path =
            origin_path.map(|op| op.derivation_path_mutex.lock().unwrap().deref().clone());
        let descriptor_path = descriptor_path
            .map(|dp| dp.derivation_path_mutex.lock().unwrap().deref().clone())
            .unwrap_or_default();
        match root_key.deref() {
            BdkDescriptorKey::Public(DescriptorPublicKey::XPub(xpub), _, _) => {
                let derived_descriptor_key = if let Some(path) = root_path {
                    let key_source: KeySource = (xpub.xkey.fingerprint(), path.clone());
                    let derived_xpub = xpub.xkey.derive_pub(&secp, &path)?;
                    derived_xpub.into_descriptor_key(Some(key_source), descriptor_path)?
                } else {
                    xpub.xkey
                        .into_descriptor_key(xpub.origin.clone(), descriptor_path)?
                };
                Ok(Arc::new(DescriptorKey {
                    descriptor_key_mutex: Mutex::new(derived_descriptor_key),
                }))
            }
            BdkDescriptorKey::Secret(DescriptorSecretKey::XPrv(xprv), _, _) => {
                let derived_descriptor_key = if let Some(path) = root_path {
                    let key_source: KeySource = (xprv.xkey.fingerprint(&secp), path.clone());
                    let derived_xpub = xprv.xkey.derive_priv(&secp, &path)?;
                    derived_xpub.into_descriptor_key(Some(key_source), descriptor_path)?
                } else {
                    xprv.xkey
                        .into_descriptor_key(xprv.origin.clone(), descriptor_path)?
                };
                Ok(Arc::new(DescriptorKey {
                    descriptor_key_mutex: Mutex::new(derived_descriptor_key),
                }))
            }
            _ => Err(BdkError::Generic("Unsupported Key Type".to_string())),
        }
    }

    fn as_public(&self) -> Arc<DescriptorKey> {
        let secp = Secp256k1::new();
        let root_key = self.descriptor_key_mutex.lock().unwrap();

        match root_key.deref() {
            BdkDescriptorKey::Public(descriptor_public_key, network, _) => {
                Arc::new(DescriptorKey {
                    descriptor_key_mutex: Mutex::new(BdkDescriptorKey::from_public(
                        descriptor_public_key.clone(),
                        network.clone(),
                    )),
                })
            }
            BdkDescriptorKey::Secret(descriptor_secret_key, network, _) => {
                let descriptor_public_key = descriptor_secret_key.as_public(&secp).unwrap();
                Arc::new(DescriptorKey {
                    descriptor_key_mutex: Mutex::new(BdkDescriptorKey::from_public(
                        descriptor_public_key,
                        network.clone(),
                    )),
                })
            }
        }
    }

    fn as_string(&self) -> String {
        let descriptor_key = self.descriptor_key_mutex.lock().unwrap();
        match descriptor_key.deref() {
            BdkDescriptorKey::Public(descriptor_public_key, _, _) => {
                descriptor_public_key.to_string()
            }
            BdkDescriptorKey::Secret(descriptor_secret_key, _, _) => {
                descriptor_secret_key.to_string()
            }
        }
    }
}
