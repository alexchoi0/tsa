use async_trait::async_trait;
use futures::TryStreamExt;
use mongodb::{bson::doc, Collection};
use tsa_core::{Account, AccountRepository, Result, TsaError};
use uuid::Uuid;

#[derive(Clone)]
pub struct MongoDbAccountRepository {
    collection: Collection<Account>,
}

impl MongoDbAccountRepository {
    pub fn new(collection: Collection<Account>) -> Self {
        Self { collection }
    }
}

#[async_trait]
impl AccountRepository for MongoDbAccountRepository {
    async fn create(&self, account: &Account) -> Result<Account> {
        self.collection
            .insert_one(account)
            .await
            .map_err(|e| {
                if e.to_string().contains("duplicate key") {
                    TsaError::AccountAlreadyLinked
                } else {
                    TsaError::Database(e.to_string())
                }
            })?;
        Ok(account.clone())
    }

    async fn find_by_provider(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> Result<Option<Account>> {
        self.collection
            .find_one(doc! {
                "provider": provider,
                "provider_account_id": provider_account_id
            })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<Account>> {
        let cursor = self
            .collection
            .find(doc! { "user_id": user_id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        cursor
            .try_collect()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.collection
            .delete_one(doc! { "id": id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
    }
}
