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

fn main() {
    // deriving master extended key
    let mnemonic =
        "chaos fabric time speed sponsor all flat solution wisdom trophy crack object robot pave observe combine where aware bench orient secret primary cable detect".to_string();
    let master_key = DescriptorKey::new(Network::Testnet, mnemonic.clone(), None).unwrap();
    println!("master");
    println!("xprv    ->    {:?}", master_key.into_string());
    println!("xpub    ->    {:?}", master_key.as_public().into_string());
    derive_descriptor_key(&master_key, "m".to_string(), "m".to_string());
    let key_m_0 = derive_descriptor_key(&master_key, "m/0".to_string(), "m".to_string());
    derive_descriptor_key(&key_m_0, "m/84h/1h/0h".to_string(), "m/0".to_string());
    derive_descriptor_key(&master_key, "m/84h/1h/0h".to_string(), "m".to_string());
}

fn derive_descriptor_key(
    descriptor_key: &DescriptorKey,
    from_path: String,
    to_path: String,
) -> Arc<DescriptorKey> {
    let origin_path = Arc::new(DerivationPath::new(from_path.clone()).unwrap());
    let derivation_path = Some(Arc::new(DerivationPath::new(to_path.clone()).unwrap()));
    let derived_descriptor_key = descriptor_key.derive(origin_path, derivation_path);
    println!("{} -> {}", from_path.to_string(), to_path.to_string());
    println!("xprv    ->    {:?}", derived_descriptor_key.into_string());
    println!(
        "xpub    ->    {:?}",
        derived_descriptor_key.as_public().into_string()
    );
    derived_descriptor_key
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
        let xkey: ExtendedKey = (mnemonic.clone(), password).into_extended_key()?;
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
        origin_path: Arc<DerivationPath>,
        derivation_path: Option<Arc<DerivationPath>>,
    ) -> Arc<DescriptorKey> {
        let secp = Secp256k1::new();
        let root_key = self.descriptor_key_mutex.lock().unwrap();
        let root_path = origin_path
            .derivation_path_mutex
            .lock()
            .unwrap()
            .deref()
            .clone();
        let derivation_path = derivation_path
            .map(|dp| dp.derivation_path_mutex.lock().unwrap().deref().clone())
            .unwrap_or_default();
        match root_key.deref() {
            BdkDescriptorKey::Public(DescriptorPublicKey::XPub(xpub), _, _) => {
                let key_source: KeySource = (xpub.xkey.fingerprint(), root_path.clone());
                let derived_xpub = xpub.xkey.derive_pub(&secp, &root_path).unwrap().clone();
                let derived_descriptor_key = derived_xpub
                    .into_descriptor_key(Some(key_source), derivation_path)
                    .unwrap();
                Arc::new(DescriptorKey {
                    descriptor_key_mutex: Mutex::new(derived_descriptor_key),
                })
            }
            BdkDescriptorKey::Secret(DescriptorSecretKey::XPrv(xprv), _, _) => {
                let key_source: KeySource = (xprv.xkey.fingerprint(&secp), root_path.clone());
                let derived_xprv = xprv.xkey.derive_priv(&secp, &root_path).unwrap();
                let derived_descriptor_key = derived_xprv
                    .into_descriptor_key(Some(key_source), derivation_path)
                    .unwrap();
                Arc::new(DescriptorKey {
                    descriptor_key_mutex: Mutex::new(derived_descriptor_key),
                })
            }
            // This case should never happen since we only create xkeys in the new() function
            // in the future if we decide to also support SinglePriv and SinglePub keys then
            // those types will need to be handled here.
            _ => panic!(),
        }
    }

    fn as_public(&self) -> Arc<DescriptorKey> {
        let secp = Secp256k1::new();
        let root_key = self.descriptor_key_mutex.lock().unwrap();

        match root_key.deref() {
            BdkDescriptorKey::Public(descriptor_public_key, valid_networks, _) => {
                Arc::new(DescriptorKey {
                    descriptor_key_mutex: Mutex::new(BdkDescriptorKey::from_public(
                        descriptor_public_key.clone(),
                        valid_networks.clone(),
                    )),
                })
            }
            BdkDescriptorKey::Secret(descriptor_secret_key, valid_networks, _) => {
                let descriptor_public_key = descriptor_secret_key.as_public(&secp).unwrap();
                Arc::new(DescriptorKey {
                    descriptor_key_mutex: Mutex::new(BdkDescriptorKey::from_public(
                        descriptor_public_key.clone(),
                        valid_networks.clone(),
                    )),
                })
            }
        }
    }

    fn into_string(&self) -> String {
        let descriptor_key = self.descriptor_key_mutex.lock().unwrap();
        match descriptor_key.deref() {
            BdkDescriptorKey::Public(descriptor_public_key, _valid_networks, _) => {
                descriptor_public_key.to_string()
            }
            BdkDescriptorKey::Secret(descriptor_secret_key, _valid_networks, _) => {
                descriptor_secret_key.to_string()
            }
        }
    }
}
