use tokio::io::Error;
use fuels::prelude::*;

/// Setup an environment that deploys the demo MailMe contract that utilizes the SRC16Domain
pub mod setup_test_environment_fuelmailme {
    use super::*;
    use crate::interfaces::mail_me_fuel_interface::*;

    pub async fn setup_assets_sdk_provider() -> std::result::Result<(
        Provider,
        ContractId,         // MailMe contractid.
        WalletUnlocked,
    ), Error> {

        let mut node_config = NodeConfig::default();
        node_config.starting_gas_price = 1;

        let wallets_config = WalletsConfig::new(
                Some(1),
                Some(1),
                Some(1_000_000_000_000),
        );

        let mut wallets = launch_custom_provider_and_get_wallets(
            wallets_config,
            Some(node_config),
            None,
        )
        .await
        .unwrap();
        let wallet = wallets.pop().unwrap();
        let provider = wallet.provider().clone().unwrap();

        // deploy a MailMe contract.
        let mailme_contractid = deploy_fuel_mailme(&wallet).await;

        println!("\n----------------------------------------------------------------------------- (addresses):");
        println!("MailMe contractid  : {}", hex::encode(mailme_contractid));
        println!("SDK Wallet address : {}", hex::encode(wallet.address().hash));

        Ok((
            provider.clone(),
            mailme_contractid,
            wallet
        ))
    }

    /// Deploy a fresh MailMe contract.
    pub async fn deploy_fuel_mailme(
        wallet_with_gas: &WalletUnlocked,
    ) -> ContractId {

        println!("Deploying SRC16Domin validated MailMe contract.");
        let mailme_cid = deploy_mailme(wallet_with_gas).await;

        mailme_cid
    }

}

/// Setup an environment that deploys the demo MailMe contract that utilizes the EIP712Domain
pub mod setup_test_environment_ethereummailme {
    use super::*;
    use crate::interfaces::mail_me_ethereum_interface::*;

    pub async fn setup_assets_sdk_provider() -> std::result::Result<(
        Provider,
        ContractId,         // MailMe contractid.
        WalletUnlocked,
    ), Error> {

        let mut node_config = NodeConfig::default();
        node_config.starting_gas_price = 1;

        let wallets_config = WalletsConfig::new(
                Some(1),
                Some(1),
                Some(1_000_000_000_000),
        );

        let mut wallets = launch_custom_provider_and_get_wallets(
            wallets_config,
            Some(node_config),
            None,
        )
        .await
        .unwrap();
        let wallet = wallets.pop().unwrap();
        let provider = wallet.provider().clone().unwrap();

        // deploy a MailMe contract.
        let mailme_contractid = deploy_fuel_mailme(&wallet).await;

        println!("\n----------------------------------------------------------------------------- (addresses):");
        println!("MailMe contractid  : {}", hex::encode(mailme_contractid));
        println!("SDK Wallet address : {}", hex::encode(wallet.address().hash));

        Ok((
            provider.clone(),
            mailme_contractid,
            wallet
        ))
    }

    /// Deploy a fresh MailMe contract.
    pub async fn deploy_fuel_mailme(
        wallet_with_gas: &WalletUnlocked,
    ) -> ContractId {

        println!("Deploying EIP712 validated MailMe contract.");
        let mailme_cid = deploy_mailme(wallet_with_gas).await;

        mailme_cid
    }

}
