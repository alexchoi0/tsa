use async_trait::async_trait;
use tsa_auth_core::{Account, AccountRepository, Result};
use uuid::Uuid;

use super::super::client::BigtableClient;

const ENTITY_TYPE: &str = "account";

#[derive(Clone)]
pub struct BigtableAccountRepository {
    client: BigtableClient,
}

impl BigtableAccountRepository {
    pub fn new(client: BigtableClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl AccountRepository for BigtableAccountRepository {
    async fn create(&self, account: &Account) -> Result<Account> {
        self.client
            .create_entity(ENTITY_TYPE, &account.id.to_string(), account)
            .await?;
        Ok(account.clone())
    }

    async fn find_by_provider(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> Result<Option<Account>> {
        let accounts: Vec<Account> = self.client.list_entities(ENTITY_TYPE).await?;
        for account in accounts {
            if account.provider == provider && account.provider_account_id == provider_account_id {
                return Ok(Some(account));
            }
        }
        Ok(None)
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<Account>> {
        self.client
            .find_all_by_field(ENTITY_TYPE, "user_id", &user_id.to_string())
            .await
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_entity(ENTITY_TYPE, &id.to_string())
            .await
    }
}
