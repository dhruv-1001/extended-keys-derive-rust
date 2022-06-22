use std::str::FromStr;
use std::sync::{Arc, Mutex};

use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::{Network};
use bdk::bitcoin::util::bip32::{
    ExtendedPrivKey as BdkExtendedPrivKey, 
    ExtendedPubKey as BdkExtendedPubKey,
    DerivationPath as BdkDerivationPath
};
use bdk::keys::{GeneratedKey, GeneratableKey, ExtendedKey, DerivableKey};
use bdk::keys::bip39::{Language, Mnemonic, WordCount};
use bdk::{Error as BdkError};
use bdk::miniscript::BareCtx;

fn main() {
    let mnemonic = generate_mnemonic(WordCount::Words12).unwrap();
    println!("{:?}", &mnemonic);
    let extended_priv_key = ExtendedPrivKey::new(
        Network::Bitcoin, 
        mnemonic, None
    ).unwrap();
    println!("{:?}", extended_priv_key.to_string());
    let derivation_path_one = DerivationPath::new("m/84'/1'/0'/0".to_string()).unwrap();
    let derivation_path_two = DerivationPath::new("m/84'/1'/0'/0".to_string()).unwrap();
    let derived_priv_key = extended_priv_key.derive_xprv(&Some(derivation_path_one));
    println!("{:?}", derived_priv_key.to_string());
    let derived_priv_key_no_path = extended_priv_key.derive_xprv(&None);
    println!("{:?}", derived_priv_key_no_path.to_string());
    let derived_pub_key = extended_priv_key.derive_xpub(&Some(derivation_path_two));
    println!("{:?}", derived_pub_key.to_string());
    let derived_pub_key_no_path = extended_priv_key.derive_xpub(&None);
    println!("{:?}", derived_pub_key_no_path.to_string())
}

struct DerivationPath {
    derivation_path: Mutex<BdkDerivationPath>,
}

impl DerivationPath {
    fn new(path: String) -> Result<Self, BdkError> {
        let path = BdkDerivationPath::from_str(&path).unwrap();
        Ok(DerivationPath { 
            derivation_path: Mutex::new(path) 
        })
    }
}

struct ExtendedPrivKey {
    xprv: Mutex<BdkExtendedPrivKey>,
}

impl ExtendedPrivKey {
    fn new(
        network: Network,
        mnemonic: String,
        password: Option<String>,
    ) -> Result<Self, BdkError> {
        let mnemonic = Mnemonic::parse_in(Language::English, mnemonic).unwrap();
        let xkey: ExtendedKey = (mnemonic.clone(), password).into_extended_key()?;
        let xprv = xkey.into_xprv(network).unwrap();
        Ok(ExtendedPrivKey { 
            xprv: Mutex::new(xprv)
        })
    }

    fn derive_xprv(
        &self,
        derivation_path: &Option<DerivationPath>,
    ) -> Arc<ExtendedPrivKey> {
        let secp = Secp256k1::new();
        if let Some(derivation_path) = derivation_path {
            let path = derivation_path.derivation_path.lock().unwrap().clone();
            let derived_xprv = self.xprv.lock().unwrap().derive_priv(&secp, &path).unwrap();
            Arc::new(ExtendedPrivKey { 
                xprv: Mutex::new(derived_xprv),
            })
        } else {
            Arc::new (ExtendedPrivKey { 
                xprv: Mutex::new(self.xprv.lock().unwrap().to_owned())
            })
        }
    }

    fn derive_xpub(
        &self,
        derivation_path: &Option<DerivationPath>,
    ) -> Arc<ExtendedPubKey> {
        let secp = Secp256k1::new();
        if let Some(derivation_path) = derivation_path {
            let path = derivation_path.derivation_path.lock().unwrap().clone();
            let derived_xprv = self.xprv.lock().unwrap().derive_priv(&secp, &path).unwrap();
            let derived_xpub = BdkExtendedPubKey::from_private(&secp, &derived_xprv);
            Arc::new(ExtendedPubKey { 
                xpub: Mutex::new(derived_xpub)
            })
        } else {
            let derived_xpub = BdkExtendedPubKey::from_private(&secp, &self.xprv.lock().unwrap().clone());
            Arc::new(ExtendedPubKey { 
                xpub: Mutex::new(derived_xpub) 
            })
        }
    }

    fn to_string(&self) -> String {
        self.xprv.lock().unwrap().to_string()
    }
}


struct ExtendedPubKey {
    xpub: Mutex<BdkExtendedPubKey>,
}

impl ExtendedPubKey{
    fn to_string(&self) -> String {
        self.xpub.lock().unwrap().to_string()
    }
}

fn generate_mnemonic(
    word_count: WordCount,
) -> Result<String, BdkError> {
    let mnemonic: GeneratedKey<_, BareCtx> = Mnemonic::generate((word_count, Language::English)).unwrap();
    Ok(mnemonic.to_string())
}