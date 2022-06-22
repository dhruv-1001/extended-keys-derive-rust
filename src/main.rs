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
    );
    println!("{:?}", extended_priv_key.unwrap().xprv);
}

fn generate_mnemonic(
    word_count: WordCount,
) -> Result<Mnemonic, Error> {
    let mnemonic: GeneratedKey<_, BareCtx> = Mnemonic::generate((word_count, Language::English)).unwrap();
    Ok(mnemonic.into_key())
}

struct DerivationPath{
    derivation_path: Mutex<BdkDerivationPath>,
}

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
        path: DerivationPath,
    ) -> ExtendedPrivKey {
        let secp = Secp256k1::new();
        let path = path.derivation_path.lock().unwrap().clone();
        let derived_xprv = Mutex::new(
            self.xprv.lock().unwrap().derive_priv(&secp, &path).unwrap()
        );
        ExtendedPrivKey { xprv: derived_xprv }
    }

    // fn derive_xpub(
    //     &self,
    //     derivation_path: DerivationPath,
    // ) -> ExtendedPubKey {

    // }

    // fn to_string(
    //     &self,
    // ) -> String {

    // }
}

struct ExtendedPubKey {
    xpub: Mutex<BdkExtendedPubKey>,
}

impl ExtendedPubKey{
    fn to_string(
        &self
    ) -> String {
        "".to_string()
    }
}