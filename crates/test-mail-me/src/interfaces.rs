// use dotenv::dotenv;
// use thiserror::Error;
// use std::result::Result as StdResult;

use rand::prelude::Rng;
use std::path::PathBuf;
use std::env;

use fuels::{
    prelude::*,
    types::Bits256,
};

pub mod mail_me_fuel_interface {
    use super::*;

    abigen!(
        Contract(
            name = "MailMe",
            abi = "./contracts/src16-typed-data/fuel_example/out/debug/src16_fuel_typed_data-abi.json"
        ),
    );

    fn get_project_root() -> PathBuf {
        let current_dir = env::current_dir().expect("Failed to get current directory");
        current_dir.ancestors()
            .find(|path| path.join("contracts").exists())
            .unwrap_or(&current_dir)
            .to_path_buf()
    }

    fn get_contract_paths() -> (PathBuf, PathBuf, PathBuf) {
        let project_root = get_project_root();
        let contract_dir = project_root.join("contracts")
            .join("src16-typed-data")
            .join("fuel_example")
            .join("out")
            .join("debug");

        (
            contract_dir.join("src16_fuel_typed_data.bin"),
            contract_dir.join("src16_fuel_typed_data-storage_slots.json"),
            contract_dir.join("src16_fuel_typed_data-abi.json")
        )
    }

    pub fn get_contract_binary_path() -> PathBuf {
        get_contract_paths().0
    }

    pub fn get_contract_storage_path() -> PathBuf {
        get_contract_paths().1
    }

    pub async fn deploy_mailme(
        wallet_with_gas: &WalletUnlocked,
    ) -> ContractId {

        // deploy with salt:
        let mut rng = rand::thread_rng();
        let salt = rng.gen::<[u8; 32]>();
        // let salt_bytes_vec = hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap();
        // let salt: [u8; 32] = salt_bytes_vec.try_into().unwrap();

        println!("MailMe salt: {}", hex::encode(salt));

        // println!("get_contract_storage_path : {}", get_contract_storage_path().display());
        // println!("get_contract_binary_path  : {}", get_contract_binary_path().display());

        let storage_configuration = StorageConfiguration::default()
            .add_slot_overrides_from_file(get_contract_storage_path())
            .unwrap();

        let configuration = LoadConfiguration::default()
            .with_storage_configuration(storage_configuration)
            .with_salt(salt);

        let mailme_b32cid = Contract::load_from(
            get_contract_binary_path(),
            configuration,
        )
        .unwrap()
        .deploy(wallet_with_gas, TxPolicies::default())
        .await
        .unwrap();

        let mailme_cid = ContractId::from_bytes_ref(&mailme_b32cid.hash);

        mailme_cid.to_owned()
    }

    pub async fn call_send_mail_get_hash(
        contract_id: ContractId,
        wallet_with_gas: &WalletUnlocked,
        from_addr: Address,
        to_addr: Address,
        message: String,
    ) -> [u8; 32] {

        let mailme_instance = MailMe::new(
            contract_id.clone(),
            wallet_with_gas.clone()
        );

        let fcr = mailme_instance
            .methods()
            .send_mail_get_hash(
                from_addr,
                to_addr,
                message,
            )
            .call()
            .await
            .unwrap();
        let hash = fcr.value;
        hash.0
    }

}


pub mod mail_me_ethereum_interface {
    use super::*;

    abigen!(
        Contract(
            name = "MailMe",
            abi = "./contracts/src16-typed-data/ethereum_example/out/debug/src16_ethereum_typed_data-abi.json"
        ),
    );

    fn get_project_root() -> PathBuf {
        let current_dir = env::current_dir().expect("Failed to get current directory");
        current_dir.ancestors()
            .find(|path| path.join("contracts").exists())
            .unwrap_or(&current_dir)
            .to_path_buf()
    }

    fn get_contract_paths() -> (PathBuf, PathBuf, PathBuf) {
        let project_root = get_project_root();
        let contract_dir = project_root.join("contracts")
            .join("src16-typed-data")
            .join("ethereum_example")
            .join("out")
            .join("debug");

        (
            contract_dir.join("src16_ethereum_typed_data.bin"),
            contract_dir.join("src16_ethereum_typed_data-storage_slots.json"),
            contract_dir.join("src16_ethereum_typed_data-abi.json")
        )
    }

    pub fn get_contract_binary_path() -> PathBuf {
        get_contract_paths().0
    }

    pub fn get_contract_storage_path() -> PathBuf {
        get_contract_paths().1
    }

    pub async fn deploy_mailme(
        wallet_with_gas: &WalletUnlocked,
    ) -> ContractId {

        // deploy with salt:
        // let mut rng = rand::thread_rng();
        // let salt = rng.gen::<[u8; 32]>();

        // Use a static salt because we have hardcoded the
        let salt_bytes_vec = hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap();
        let salt: [u8; 32] = salt_bytes_vec.try_into().unwrap();

        println!("MailMe salt: {}", hex::encode(salt));

        // println!("get_contract_storage_path : {}", get_contract_storage_path().display());
        // println!("get_contract_binary_path  : {}", get_contract_binary_path().display());

        let storage_configuration = StorageConfiguration::default()
            .add_slot_overrides_from_file(get_contract_storage_path())
            .unwrap();

        let configuration = LoadConfiguration::default()
            .with_storage_configuration(storage_configuration)
            .with_salt(salt);

        let mailme_b32cid = Contract::load_from(
            get_contract_binary_path(),
            configuration,
        )
        .unwrap()
        .deploy(wallet_with_gas, TxPolicies::default())
        .await
        .unwrap();

        let mailme_cid = ContractId::from_bytes_ref(&mailme_b32cid.hash);

        mailme_cid.to_owned()
    }

    pub async fn call_send_mail_get_hash(
        contract_id: ContractId,
        wallet_with_gas: &WalletUnlocked,
        from_addr: Address,
        to_addr: Address,
        message: String,
    ) -> [u8; 32] {

        let mailme_instance = MailMe::new(
            contract_id.clone(),
            wallet_with_gas.clone()
        );

        let fcr = mailme_instance
            .methods()
            .send_mail_get_hash(
                Bits256(from_addr.try_into().expect("slice with incorrect length")),
                Bits256(to_addr.try_into().expect("slice with incorrect length")),
                message,
            )
            .call()
            .await
            .unwrap();
        let hash = fcr.value;
        hash.0
    }

}
