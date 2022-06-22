use std::str::FromStr;
use std::sync::Mutex;

use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::{Network};
use bdk::bitcoin::util::bip32::{
    ExtendedPrivKey as BdkExtendedPrivKey, 
    ExtendedPubKey as BdkExtendedPubKey,
    DerivationPath as BdkDerivationPath
};
use bdk::keys::{GeneratedKey, GeneratableKey, ExtendedKey, DerivableKey};
use bdk::keys::bip39::{Language, Mnemonic, WordCount};
use bdk::Error;
use bdk::miniscript::BareCtx;

fn main() {
    let mnemonic = generate_mnemonic(WordCount::Words12).unwrap();
    println!("{:?}", &mnemonic);
    let extended_priv_key = ExtendedPrivKey::new(
        Network::Testnet, 
        mnemonic, None
    ).unwrap();
    println!("{:?}", extended_priv_key.to_string());
    let derivation_path = DerivationPath::new("m/84'/1'/0'/0".to_string()).unwrap();
    let derived_priv_key = extended_priv_key.derive_xprv(&derivation_path);
    println!("{:?}", derived_priv_key.to_string());
    let derived_pub_key = extended_priv_key.derive_xpub(derivation_path);
    println!("{:?}", derived_pub_key.to_string())
}

fn generate_mnemonic(
    word_count: WordCount,
) -> Result<Mnemonic, Error> {
    let mnemonic: GeneratedKey<_, BareCtx> = Mnemonic::generate((word_count, Language::English)).unwrap();
    Ok(mnemonic.into_key())
}

#[allow(dead_code)]
struct DerivationPath{
    derivation_path: Mutex<BdkDerivationPath>,
}

#[allow(dead_code)]
impl DerivationPath {
    fn new(
        path: String,
    ) -> Result<Self, Error> {
        let derivation_path = Mutex::new(
            BdkDerivationPath::from_str(&path).unwrap()
        );
        Ok(DerivationPath { derivation_path })
    }
}

#[warn(dead_code)]
#[derive(Debug)]
struct ExtendedPrivKey {
    xprv: Mutex<BdkExtendedPrivKey>,
}

#[allow(dead_code)]
impl ExtendedPrivKey {
    fn new(
        network: Network,
        mnemonic: Mnemonic,
        password: Option<String>,
    ) -> Result<Self, Error> {
        let xkey: ExtendedKey = (mnemonic.clone(), password).into_extended_key()?;
        let xprv = Mutex::new(
            xkey.into_xprv(network).unwrap()
        );
        Ok(ExtendedPrivKey { xprv })
    }

    fn derive_xprv(
        &self,
        path: &DerivationPath,
    ) -> ExtendedPrivKey {
        let secp = Secp256k1::new();
        let path = path.derivation_path.lock().unwrap().clone();
        let derived_xprv = Mutex::new(
            self.xprv.lock().unwrap().derive_priv(&secp, &path).unwrap()
        );
        ExtendedPrivKey { xprv: derived_xprv }
    }

    fn derive_xpub(
        &self,
        path: DerivationPath,
    ) -> ExtendedPubKey {
        let secp = Secp256k1::new();
        let path = path.derivation_path.lock().unwrap().clone();
        let derived_xprv = Mutex::new(
            self.xprv.lock().unwrap().derive_priv(&secp, &path).unwrap()
        );
        let derived_xpub = Mutex::new(
            BdkExtendedPubKey::from_private(&secp, &derived_xprv.lock().unwrap())
        );
        ExtendedPubKey { xpub: derived_xpub }
    }

    fn to_string(
        &self,
    ) -> String {
        self.xprv.lock().unwrap().to_string()
    }
}

#[allow(dead_code)]
struct ExtendedPubKey {
    xpub: Mutex<BdkExtendedPubKey>,
}

impl ExtendedPubKey{
    fn to_string(
        &self
    ) -> String {
        self.xpub.lock().unwrap().to_string()
    }
}