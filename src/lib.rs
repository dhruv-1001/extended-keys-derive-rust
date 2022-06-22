// pub struct DescriptorKeyInfo {
//     xprv: Option<String>,
//     xpub: String,
// }

// impl ExtendedKeyInfo {
//     fn new(
//         network: Network,
//         word_count: WordCount,
//         password: Option<String>,
//     ) -> Result<Self, Error> {
//         let mnemonic: GeneratedKey<_, BareCtx> =
//         Mnemonic::generate((word_count, Language::English)).unwrap();
//         let mnemonic = mnemonic.into_key();
//         let xkey: ExtendedKey = (mnemonic.clone(), password).into_extended_key()?;
//         let xprv = xkey.into_xprv(network).unwrap();
//         let fingerprint = xprv.fingerprint(&Secp256k1::new());
//         Ok(ExtendedKeyInfo {
//             mnemonic: mnemonic.to_string(),
//             xprv: xprv.to_string(),
//             fingerprint: fingerprint.to_string(),
//         })
//     }

//     fn restore(
//         network: Network,
//         mnemonic: String,
//         password: Option<String>,
//     ) -> Result<Self, Error> {
//         let mnemonic = Mnemonic::parse_in(Language::English, mnemonic).unwrap();
//         let xkey: ExtendedKey = (mnemonic.clone(), password).into_extended_key()?;
//         let xprv = xkey.into_xprv(network).unwrap();
//         let fingerprint = xprv.fingerprint(&Secp256k1::new());
//         Ok(ExtendedKeyInfo {
//             mnemonic: mnemonic.to_string(),
//             xprv: xprv.to_string(),
//             fingerprint: fingerprint.to_string(),
//         })
//     }

//     fn derive(
//         xprv: String,
//         path: String,    
//     ) -> Result<DescriptorKeyInfo, BdkError> {
//         let secp = Secp256k1::new();
//         let xprv = ExtendedPrivKey::from_str(&xprv)?;
//         let path = DerivationPath::from_str(&path)?;
//         let derived_xprv = &xprv.derive_priv(&secp, &path)?;
//         let origin: KeySource = (xprv.fingerprint(&secp), path);
//         let derived_xprv_desc_key: DescriptorKey<Segwitv0> = 
//             derived_xprv.into_descriptor_key(Some(origin), DerivationPath::default())?;
//         if let Secret(desc_seckey, _, _) = derived_xprv_desc_key {
//             let desc_pubkey = desc_seckey
//                 .as_public(&secp)
//                 .map_err(|e| Error::Generic(e.to_string()))?;
//             Ok(
//                 DescriptorKeyInfo{
//                     xprv: Some(desc_seckey.to_string()),
//                     xpub: desc_pubkey.to_string(),
//                 }
//             )
//         } else {
//             Err(Error::Key(Message("Invalid key variant".to_string())))
//         }
//     }
// }
