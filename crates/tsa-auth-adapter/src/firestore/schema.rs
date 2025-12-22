use async_trait::async_trait;
use gcloud_sdk::google::firestore::v1::{
    firestore_client::FirestoreClient as GrpcFirestoreClient, ListDocumentsRequest,
};
use gcloud_sdk::{GoogleApi, GoogleAuthMiddleware};
use tsa_auth_core::{Result, SchemaManager, TsaError};

use super::{
    COLLECTION_ACCOUNTS, COLLECTION_API_KEYS, COLLECTION_ORGANIZATIONS,
    COLLECTION_ORGANIZATION_INVITATIONS, COLLECTION_ORGANIZATION_MEMBERS, COLLECTION_PASSKEYS,
    COLLECTION_PASSKEY_CHALLENGES, COLLECTION_SESSIONS, COLLECTION_TWO_FACTORS, COLLECTION_USERS,
    COLLECTION_VERIFICATION_TOKENS,
};

pub struct FirestoreSchemaManager {
    client: GoogleApi<GrpcFirestoreClient<GoogleAuthMiddleware>>,
    project_id: String,
    database_id: String,
}

impl FirestoreSchemaManager {
    pub async fn new(project_id: &str, database_id: &str) -> Result<Self> {
        let client = GoogleApi::from_function(
            GrpcFirestoreClient::new,
            "https://firestore.googleapis.com",
            None,
        )
        .await
        .map_err(|e| TsaError::Database(format!("Failed to create Firestore client: {}", e)))?;

        Ok(Self {
            client,
            project_id: project_id.to_string(),
            database_id: database_id.to_string(),
        })
    }

    fn documents_path(&self) -> String {
        format!(
            "projects/{}/databases/{}/documents",
            self.project_id, self.database_id
        )
    }

    async fn ensure_collection(&self, collection: &str) -> Result<()> {
        let request = ListDocumentsRequest {
            parent: self.documents_path(),
            collection_id: collection.to_string(),
            page_size: 1,
            page_token: String::new(),
            order_by: String::new(),
            mask: None,
            show_missing: false,
            consistency_selector: None,
        };

        match self.client.get().list_documents(request).await {
            Ok(_) => Ok(()),
            Err(_) => Ok(()),
        }
    }
}

#[async_trait]
impl SchemaManager for FirestoreSchemaManager {
    async fn ensure_schema(&self) -> Result<()> {
        let collections = [
            COLLECTION_USERS,
            COLLECTION_SESSIONS,
            COLLECTION_ACCOUNTS,
            COLLECTION_VERIFICATION_TOKENS,
            COLLECTION_TWO_FACTORS,
            COLLECTION_ORGANIZATIONS,
            COLLECTION_ORGANIZATION_MEMBERS,
            COLLECTION_ORGANIZATION_INVITATIONS,
            COLLECTION_API_KEYS,
            COLLECTION_PASSKEYS,
            COLLECTION_PASSKEY_CHALLENGES,
        ];

        for collection in collections {
            self.ensure_collection(collection).await?;
        }

        Ok(())
    }

    async fn drop_schema(&self) -> Result<()> {
        Ok(())
    }
}
