use gcloud_sdk::google::bigtable::v2::{
    bigtable_client::BigtableClient as GrpcBigtableClient, mutation, row_range,
    MutateRowRequest, Mutation, ReadRowsRequest, RowRange, RowSet,
};
use gcloud_sdk::{GoogleApi, GoogleAuthMiddleware};
use serde::{de::DeserializeOwned, Serialize};
use tsa_auth_core::{Result, TsaError};

use crate::{CF_DATA, TABLE_NAME};

#[derive(Clone)]
pub struct BigtableClient {
    client: GoogleApi<GrpcBigtableClient<GoogleAuthMiddleware>>,
    project_id: String,
    instance_id: String,
}

impl BigtableClient {
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

    fn table_name(&self) -> String {
        format!(
            "projects/{}/instances/{}/tables/{}",
            self.project_id, self.instance_id, TABLE_NAME
        )
    }

    fn row_key(entity_type: &str, id: &str) -> String {
        format!("{}#{}", entity_type, id)
    }

    pub async fn create_entity<T: Serialize>(
        &self,
        entity_type: &str,
        id: &str,
        data: &T,
    ) -> Result<()> {
        let json = serde_json::to_vec(data)
            .map_err(|e| TsaError::Database(format!("Serialization error: {}", e)))?;

        let row_key = Self::row_key(entity_type, id);

        let mutation = Mutation {
            mutation: Some(mutation::Mutation::SetCell(mutation::SetCell {
                family_name: CF_DATA.to_string(),
                column_qualifier: b"json".to_vec(),
                timestamp_micros: -1,
                value: json,
            })),
        };

        let request = MutateRowRequest {
            table_name: self.table_name(),
            app_profile_id: String::new(),
            authorized_view_name: String::new(),
            row_key: row_key.into_bytes(),
            mutations: vec![mutation],
            idempotency: None,
        };

        self.client
            .get()
            .mutate_row(request)
            .await
            .map_err(|e| TsaError::Database(format!("Failed to create entity: {}", e)))?;

        Ok(())
    }

    pub async fn get_entity<T: DeserializeOwned>(
        &self,
        entity_type: &str,
        id: &str,
    ) -> Result<Option<T>> {
        let row_key = Self::row_key(entity_type, id);

        let request = ReadRowsRequest {
            table_name: self.table_name(),
            app_profile_id: String::new(),
            authorized_view_name: String::new(),
            materialized_view_name: String::new(),
            rows: Some(RowSet {
                row_keys: vec![row_key.into_bytes()],
                row_ranges: vec![],
            }),
            filter: None,
            rows_limit: 1,
            request_stats_view: 0,
            reversed: false,
        };

        let mut response = self
            .client
            .get()
            .read_rows(request)
            .await
            .map_err(|e| TsaError::Database(format!("Failed to read entity: {}", e)))?
            .into_inner();

        while let Some(chunk_response) = response
            .message()
            .await
            .map_err(|e| TsaError::Database(format!("Failed to read response: {}", e)))?
        {
            for chunk in chunk_response.chunks {
                if !chunk.value.is_empty() {
                    let data: T = serde_json::from_slice(&chunk.value)
                        .map_err(|e| TsaError::Database(format!("Deserialization error: {}", e)))?;
                    return Ok(Some(data));
                }
            }
        }

        Ok(None)
    }

    pub async fn update_entity<T: Serialize>(
        &self,
        entity_type: &str,
        id: &str,
        data: &T,
    ) -> Result<()> {
        self.create_entity(entity_type, id, data).await
    }

    pub async fn delete_entity(&self, entity_type: &str, id: &str) -> Result<()> {
        let row_key = Self::row_key(entity_type, id);

        let mutation = Mutation {
            mutation: Some(mutation::Mutation::DeleteFromRow(
                mutation::DeleteFromRow {},
            )),
        };

        let request = MutateRowRequest {
            table_name: self.table_name(),
            app_profile_id: String::new(),
            authorized_view_name: String::new(),
            row_key: row_key.into_bytes(),
            mutations: vec![mutation],
            idempotency: None,
        };

        self.client
            .get()
            .mutate_row(request)
            .await
            .map_err(|e| TsaError::Database(format!("Failed to delete entity: {}", e)))?;

        Ok(())
    }

    pub async fn list_entities<T: DeserializeOwned>(&self, entity_type: &str) -> Result<Vec<T>> {
        let prefix = format!("{}#", entity_type);
        let prefix_end = format!("{}$", entity_type);

        let request = ReadRowsRequest {
            table_name: self.table_name(),
            app_profile_id: String::new(),
            authorized_view_name: String::new(),
            materialized_view_name: String::new(),
            rows: Some(RowSet {
                row_keys: vec![],
                row_ranges: vec![RowRange {
                    start_key: Some(row_range::StartKey::StartKeyClosed(prefix.into_bytes())),
                    end_key: Some(row_range::EndKey::EndKeyOpen(prefix_end.into_bytes())),
                }],
            }),
            filter: None,
            rows_limit: 0,
            request_stats_view: 0,
            reversed: false,
        };

        let mut response = self
            .client
            .get()
            .read_rows(request)
            .await
            .map_err(|e| TsaError::Database(format!("Failed to list entities: {}", e)))?
            .into_inner();

        let mut results = Vec::new();
        while let Some(chunk_response) = response
            .message()
            .await
            .map_err(|e| TsaError::Database(format!("Failed to read response: {}", e)))?
        {
            for chunk in chunk_response.chunks {
                if !chunk.value.is_empty() {
                    if let Ok(data) = serde_json::from_slice::<T>(&chunk.value) {
                        results.push(data);
                    }
                }
            }
        }

        Ok(results)
    }

    pub async fn find_by_field<T: DeserializeOwned + Serialize>(
        &self,
        entity_type: &str,
        field: &str,
        value: &str,
    ) -> Result<Option<T>> {
        let entities = self.list_entities::<T>(entity_type).await?;
        for entity in entities {
            let json = serde_json::to_value(&entity)
                .map_err(|e| TsaError::Database(format!("Serialization error: {}", e)))?;
            if let Some(field_value) = json.get(field) {
                if field_value.as_str() == Some(value) {
                    return Ok(Some(entity));
                }
            }
        }
        Ok(None)
    }

    pub async fn find_all_by_field<T: DeserializeOwned + Serialize>(
        &self,
        entity_type: &str,
        field: &str,
        value: &str,
    ) -> Result<Vec<T>> {
        let entities = self.list_entities::<T>(entity_type).await?;
        let mut results = Vec::new();
        for entity in entities {
            let json = serde_json::to_value(&entity)
                .map_err(|e| TsaError::Database(format!("Serialization error: {}", e)))?;
            if let Some(field_value) = json.get(field) {
                if field_value.as_str() == Some(value) {
                    results.push(entity);
                }
            }
        }
        Ok(results)
    }
}
