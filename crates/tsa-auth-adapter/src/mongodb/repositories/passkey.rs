use async_trait::async_trait;
use futures::TryStreamExt;
use mongodb::{bson::doc, Collection};
use serde::{Deserialize, Serialize};
use tsa_auth_core::{Passkey, PasskeyRepository, Result, TsaError};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PasskeyDocument {
    pub id: Uuid,
    pub user_id: Uuid,
    #[serde(with = "serde_bytes")]
    pub credential_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    pub counter: u32,
    pub name: String,
    pub transports: Option<Vec<String>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<PasskeyDocument> for Passkey {
    fn from(doc: PasskeyDocument) -> Self {
        Passkey {
            id: doc.id,
            user_id: doc.user_id,
            credential_id: doc.credential_id,
            public_key: doc.public_key,
            counter: doc.counter,
            name: doc.name,
            transports: doc.transports,
            created_at: doc.created_at,
            last_used_at: doc.last_used_at,
        }
    }
}

impl From<&Passkey> for PasskeyDocument {
    fn from(passkey: &Passkey) -> Self {
        PasskeyDocument {
            id: passkey.id,
            user_id: passkey.user_id,
            credential_id: passkey.credential_id.clone(),
            public_key: passkey.public_key.clone(),
            counter: passkey.counter,
            name: passkey.name.clone(),
            transports: passkey.transports.clone(),
            created_at: passkey.created_at,
            last_used_at: passkey.last_used_at,
        }
    }
}

#[derive(Clone)]
pub struct MongoDbPasskeyRepository {
    collection: Collection<PasskeyDocument>,
}

impl MongoDbPasskeyRepository {
    pub fn from_database(db: &mongodb::Database) -> Self {
        Self {
            collection: db.collection("passkeys"),
        }
    }
}

#[async_trait]
impl PasskeyRepository for MongoDbPasskeyRepository {
    async fn create(&self, passkey: &Passkey) -> Result<Passkey> {
        let doc = PasskeyDocument::from(passkey);
        self.collection.insert_one(&doc).await.map_err(|e| {
            if e.to_string().contains("duplicate key") {
                TsaError::PasskeyAlreadyRegistered
            } else {
                TsaError::Database(e.to_string())
            }
        })?;
        Ok(passkey.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Passkey>> {
        self.collection
            .find_one(doc! { "id": id })
            .await
            .map(|opt| opt.map(Passkey::from))
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_credential_id(&self, credential_id: &[u8]) -> Result<Option<Passkey>> {
        use mongodb::bson::Binary;
        let binary = Binary {
            subtype: mongodb::bson::spec::BinarySubtype::Generic,
            bytes: credential_id.to_vec(),
        };
        self.collection
            .find_one(doc! { "credential_id": binary })
            .await
            .map(|opt| opt.map(Passkey::from))
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<Passkey>> {
        let cursor = self
            .collection
            .find(doc! { "user_id": user_id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        let docs: Vec<PasskeyDocument> = cursor
            .try_collect()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(docs.into_iter().map(Passkey::from).collect())
    }

    async fn update(&self, passkey: &Passkey) -> Result<Passkey> {
        let doc = PasskeyDocument::from(passkey);
        self.collection
            .replace_one(doc! { "id": passkey.id }, &doc)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(passkey.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.collection
            .delete_one(doc! { "id": id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
    }

    async fn delete_by_user(&self, user_id: Uuid) -> Result<()> {
        self.collection
            .delete_many(doc! { "user_id": user_id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
    }
}
