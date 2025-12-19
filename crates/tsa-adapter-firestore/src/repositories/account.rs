use async_trait::async_trait;
use tsa_core::{Account, AccountRepository, Result};
use uuid::Uuid;

use crate::{client::FirestoreClient, COLLECTION_ACCOUNTS};

#[derive(Clone)]
pub struct FirestoreAccountRepository {
    client: FirestoreClient,
}

impl FirestoreAccountRepository {
    pub fn new(client: FirestoreClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl AccountRepository for FirestoreAccountRepository {
    async fn create(&self, account: &Account) -> Result<Account> {
        self.client
            .create_document(COLLECTION_ACCOUNTS, &account.id.to_string(), account)
            .await?;
        Ok(account.clone())
    }

    async fn find_by_provider(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> Result<Option<Account>> {
        let accounts: Vec<Account> = self.client.list_documents(COLLECTION_ACCOUNTS).await?;
        for account in accounts {
            if account.provider == provider && account.provider_account_id == provider_account_id {
                return Ok(Some(account));
            }
        }
        Ok(None)
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<Account>> {
        self.client
            .find_all_by_field(COLLECTION_ACCOUNTS, "user_id", &user_id.to_string())
            .await
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_document(COLLECTION_ACCOUNTS, &id.to_string())
            .await
    }
}
