use super::setup_security_module;
use crate::{
    common::{
        crypto::{
            algorithms::{
                encryption::{AsymmetricEncryption, BlockCiphers, SymmetricMode},
                hashes::{Hash, Sha2Bits},
                KeyBits,
            },
            KeyUsage,
        },
        factory::SecurityModule,
    },
    hsm::core::instance::HsmType,
    tpm::{core::instance::TpmType, TpmConfig},
};
use test_case::test_matrix;

#[test_matrix(
    [SecurityModule::Tpm(TpmType::Linux),
     SecurityModule::Tpm(TpmType::Windows),
     SecurityModule::Hsm(HsmType::NitroKey)]
)]
fn test_create_rsa_key(module: SecurityModule) {
    let provider = setup_security_module(module);

    let config = TpmConfig::new(
        AsymmetricEncryption::Rsa(KeyBits::Bits4096),
        BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![
            KeyUsage::SignEncrypt,
            KeyUsage::ClientAuth,
            KeyUsage::SignEncrypt,
            KeyUsage::CreateX509,
        ],
    );

    providerw
        .lock()
        .unwrap()
        .initialize_module()
        .expect("Failed to initialize module");

    provider
        .lock()
        .unwrap()
        .create_key("test_rsa_key", config)
        .expect("Failed to create RSA key");
}

#[test_matrix(
    [SecurityModule::Tpm(TpmType::Linux),
     SecurityModule::Tpm(TpmType::Windows),
     SecurityModule::Hsm(HsmType::NitroKey)]
)]
fn test_load_rsa_key(module: SecurityModule) {
    let provider = setup_security_module(module);

    let config = TpmConfig::new(
        AsymmetricEncryption::Rsa(KeyBits::Bits4096),
        BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![
            KeyUsage::SignEncrypt,
            KeyUsage::ClientAuth,
            KeyUsage::SignEncrypt,
            KeyUsage::CreateX509,
        ],
    );

    provider
        .lock()
        .unwrap()
        .initialize_module()
        .expect("Failed to initialize module");

    provider
        .lock()
        .unwrap()
        .load_key("test_rsa_key", config)
        .expect("Failed to load RSA key");
}
