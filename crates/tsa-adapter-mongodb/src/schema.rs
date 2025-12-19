use async_trait::async_trait;
use mongodb::{
    bson::doc,
    options::IndexOptions,
    Database, IndexModel,
};
use tsa_core::{Result, SchemaManager, TsaError};

pub struct MongoDbSchemaManager {
    db: Database,
}

impl MongoDbSchemaManager {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    async fn create_index(
        &self,
        collection: &str,
        keys: mongodb::bson::Document,
        unique: bool,
    ) -> Result<()> {
        let options = IndexOptions::builder().unique(unique).build();
        let index = IndexModel::builder().keys(keys).options(options).build();

        self.db
            .collection::<mongodb::bson::Document>(collection)
            .create_index(index)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(())
    }

    async fn create_ttl_index(
        &self,
        collection: &str,
        field: &str,
        expire_after_seconds: u64,
    ) -> Result<()> {
        let options = IndexOptions::builder()
            .expire_after(std::time::Duration::from_secs(expire_after_seconds))
            .build();
        let index = IndexModel::builder()
            .keys(doc! { field: 1 })
            .options(options)
            .build();

        self.db
            .collection::<mongodb::bson::Document>(collection)
            .create_index(index)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(())
    }

    async fn ensure_users_indexes(&self) -> Result<()> {
        self.create_index("users", doc! { "id": 1 }, true).await?;
        self.create_index("users", doc! { "email": 1 }, true).await?;
        self.create_index("users", doc! { "phone": 1 }, false).await?;
        Ok(())
    }

    async fn ensure_sessions_indexes(&self) -> Result<()> {
        self.create_index("sessions", doc! { "id": 1 }, true).await?;
        self.create_index("sessions", doc! { "token_hash": 1 }, true).await?;
        self.create_index("sessions", doc! { "user_id": 1 }, false).await?;
        self.create_ttl_index("sessions", "expires_at", 0).await?;
        Ok(())
    }

    async fn ensure_accounts_indexes(&self) -> Result<()> {
        self.create_index("accounts", doc! { "id": 1 }, true).await?;
        self.create_index("accounts", doc! { "provider": 1, "provider_account_id": 1 }, true).await?;
        self.create_index("accounts", doc! { "user_id": 1 }, false).await?;
        Ok(())
    }

    async fn ensure_verification_tokens_indexes(&self) -> Result<()> {
        self.create_index("verification_tokens", doc! { "id": 1 }, true).await?;
        self.create_index("verification_tokens", doc! { "token_hash": 1 }, true).await?;
        self.create_index("verification_tokens", doc! { "user_id": 1 }, false).await?;
        self.create_ttl_index("verification_tokens", "expires_at", 0).await?;
        Ok(())
    }

    async fn ensure_two_factors_indexes(&self) -> Result<()> {
        self.create_index("two_factors", doc! { "id": 1 }, true).await?;
        self.create_index("two_factors", doc! { "user_id": 1 }, true).await?;
        Ok(())
    }

    async fn ensure_organizations_indexes(&self) -> Result<()> {
        self.create_index("organizations", doc! { "id": 1 }, true).await?;
        self.create_index("organizations", doc! { "slug": 1 }, true).await?;
        Ok(())
    }

    async fn ensure_organization_members_indexes(&self) -> Result<()> {
        self.create_index("organization_members", doc! { "id": 1 }, true).await?;
        self.create_index(
            "organization_members",
            doc! { "organization_id": 1, "user_id": 1 },
            true,
        ).await?;
        self.create_index("organization_members", doc! { "organization_id": 1 }, false).await?;
        self.create_index("organization_members", doc! { "user_id": 1 }, false).await?;
        Ok(())
    }

    async fn ensure_organization_invitations_indexes(&self) -> Result<()> {
        self.create_index("organization_invitations", doc! { "id": 1 }, true).await?;
        self.create_index("organization_invitations", doc! { "token_hash": 1 }, true).await?;
        self.create_index("organization_invitations", doc! { "organization_id": 1 }, false).await?;
        self.create_index("organization_invitations", doc! { "email": 1 }, false).await?;
        self.create_index(
            "organization_invitations",
            doc! { "organization_id": 1, "email": 1, "status": 1 },
            false,
        ).await?;
        self.create_ttl_index("organization_invitations", "expires_at", 0).await?;
        Ok(())
    }

    async fn ensure_api_keys_indexes(&self) -> Result<()> {
        self.create_index("api_keys", doc! { "id": 1 }, true).await?;
        self.create_index("api_keys", doc! { "key_hash": 1 }, true).await?;
        self.create_index("api_keys", doc! { "prefix": 1 }, true).await?;
        self.create_index("api_keys", doc! { "user_id": 1 }, false).await?;
        self.create_index("api_keys", doc! { "organization_id": 1 }, false).await?;
        Ok(())
    }

    async fn ensure_passkeys_indexes(&self) -> Result<()> {
        self.create_index("passkeys", doc! { "id": 1 }, true).await?;
        self.create_index("passkeys", doc! { "credential_id": 1 }, true).await?;
        self.create_index("passkeys", doc! { "user_id": 1 }, false).await?;
        Ok(())
    }

    async fn ensure_passkey_challenges_indexes(&self) -> Result<()> {
        self.create_index("passkey_challenges", doc! { "id": 1 }, true).await?;
        self.create_index("passkey_challenges", doc! { "challenge": 1 }, true).await?;
        self.create_ttl_index("passkey_challenges", "expires_at", 0).await?;
        Ok(())
    }
}

#[async_trait]
impl SchemaManager for MongoDbSchemaManager {
    async fn ensure_schema(&self) -> Result<()> {
        self.ensure_users_indexes().await?;
        self.ensure_sessions_indexes().await?;
        self.ensure_accounts_indexes().await?;
        self.ensure_verification_tokens_indexes().await?;
        self.ensure_two_factors_indexes().await?;
        self.ensure_organizations_indexes().await?;
        self.ensure_organization_members_indexes().await?;
        self.ensure_organization_invitations_indexes().await?;
        self.ensure_api_keys_indexes().await?;
        self.ensure_passkeys_indexes().await?;
        self.ensure_passkey_challenges_indexes().await?;
        Ok(())
    }

    async fn drop_schema(&self) -> Result<()> {
        let collections = [
            "users",
            "sessions",
            "accounts",
            "verification_tokens",
            "two_factors",
            "organizations",
            "organization_members",
            "organization_invitations",
            "api_keys",
            "passkeys",
            "passkey_challenges",
        ];

        for collection in collections {
            self.db
                .collection::<mongodb::bson::Document>(collection)
                .drop()
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }

        Ok(())
    }
}
