use tokio::io::Error;
use fuels::prelude::*;

pub mod setup_test_environment {
    use super::*;
    use crate::interfaces::mail_me_interface::*;

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

        let mailme_contractid = deploy_token_minter_mint_to(&wallet).await;

        println!("\n----------------------------------------------------------------------------- (addresses):");
        println!("MailMe contractid  : {}", hex::encode(mailme_contractid));
        println!("SDK Wallet address : {}", hex::encode(wallet.address().hash));
        println!("\n\n");

        Ok((
            provider.clone(),
            mailme_contractid,
            wallet
        ))
    }

    /// Deploy a fresh MailMe contract.
    pub async fn deploy_token_minter_mint_to(
        wallet_with_gas: &WalletUnlocked,
    ) -> ContractId {

        println!("Deploying MailMe contract.");
        let mailme_cid = deploy_mailme(wallet_with_gas).await;

        mailme_cid
    }

}
