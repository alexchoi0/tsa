use async_trait::async_trait;
use chrono::Utc;
use mongodb::{bson::doc, Collection};
use serde::{Deserialize, Serialize};
use tsa_auth_core::{PasskeyChallenge, PasskeyChallengeRepository, PasskeyChallengeType, Result, TsaError};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PasskeyChallengeDocument {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    #[serde(with = "serde_bytes")]
    pub challenge: Vec<u8>,
    pub challenge_type: PasskeyChallengeType,
    #[serde(with = "serde_bytes")]
    pub state: Vec<u8>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<PasskeyChallengeDocument> for PasskeyChallenge {
    fn from(doc: PasskeyChallengeDocument) -> Self {
        PasskeyChallenge {
            id: doc.id,
            user_id: doc.user_id,
            challenge: doc.challenge,
            challenge_type: doc.challenge_type,
            state: doc.state,
            expires_at: doc.expires_at,
            created_at: doc.created_at,
        }
    }
}

impl From<&PasskeyChallenge> for PasskeyChallengeDocument {
    fn from(challenge: &PasskeyChallenge) -> Self {
        PasskeyChallengeDocument {
            id: challenge.id,
            user_id: challenge.user_id,
            challenge: challenge.challenge.clone(),
            challenge_type: challenge.challenge_type.clone(),
            state: challenge.state.clone(),
            expires_at: challenge.expires_at,
            created_at: challenge.created_at,
        }
    }
}

#[derive(Clone)]
pub struct MongoDbPasskeyChallengeRepository {
    collection: Collection<PasskeyChallengeDocument>,
}

impl MongoDbPasskeyChallengeRepository {
    pub fn from_database(db: &mongodb::Database) -> Self {
        Self {
            collection: db.collection("passkey_challenges"),
        }
    }
}

#[async_trait]
impl PasskeyChallengeRepository for MongoDbPasskeyChallengeRepository {
    async fn create(&self, challenge: &PasskeyChallenge) -> Result<PasskeyChallenge> {
        let doc = PasskeyChallengeDocument::from(challenge);
        self.collection
            .insert_one(&doc)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(challenge.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<PasskeyChallenge>> {
        self.collection
            .find_one(doc! { "id": id })
            .await
            .map(|opt| opt.map(PasskeyChallenge::from))
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_challenge(&self, challenge: &[u8]) -> Result<Option<PasskeyChallenge>> {
        use mongodb::bson::Binary;
        let binary = Binary {
            subtype: mongodb::bson::spec::BinarySubtype::Generic,
            bytes: challenge.to_vec(),
        };
        self.collection
            .find_one(doc! { "challenge": binary })
            .await
            .map(|opt| opt.map(PasskeyChallenge::from))
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.collection
            .delete_one(doc! { "id": id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
    }

    async fn delete_expired(&self) -> Result<u64> {
        let result = self
            .collection
            .delete_many(doc! { "expires_at": { "$lt": Utc::now() } })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(result.deleted_count)
    }
}
