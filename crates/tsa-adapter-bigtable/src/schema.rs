use async_trait::async_trait;
use gcloud_sdk::google::bigtable::v2::bigtable_client::BigtableClient as GrpcBigtableClient;
use gcloud_sdk::{GoogleApi, GoogleAuthMiddleware};
use tsa_core::{Result, SchemaManager, TsaError};

pub struct BigtableSchemaManager {
    client: GoogleApi<GrpcBigtableClient<GoogleAuthMiddleware>>,
    project_id: String,
    instance_id: String,
}

impl BigtableSchemaManager {
    pub async fn new(project_id: &str, instance_id: &str) -> Result<Self> {
        let client = GoogleApi::from_function(
            GrpcBigtableClient::new,
            "https://bigtable.googleapis.com",
            None,
        )
        .await
        .map_err(|e| TsaError::Database(format!("Failed to create Bigtable client: {}", e)))?;

        Ok(Self {
            client,
            project_id: project_id.to_string(),
            instance_id: instance_id.to_string(),
        })
    }
}

#[async_trait]
impl SchemaManager for BigtableSchemaManager {
    async fn ensure_schema(&self) -> Result<()> {
        Ok(())
    }

    async fn drop_schema(&self) -> Result<()> {
        Ok(())
    }
}
