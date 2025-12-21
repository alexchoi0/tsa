use gcloud_sdk::google::firestore::v1::{
    firestore_client::FirestoreClient as GrpcFirestoreClient, value::ValueType,
    CreateDocumentRequest, DeleteDocumentRequest, Document, GetDocumentRequest,
    ListDocumentsRequest, UpdateDocumentRequest,
};
use gcloud_sdk::{GoogleApi, GoogleAuthMiddleware};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use tsa_auth_core::{Result, TsaError};

#[derive(Clone)]
pub struct FirestoreClient {
    client: GoogleApi<GrpcFirestoreClient<GoogleAuthMiddleware>>,
    project_id: String,
    database_id: String,
}

impl FirestoreClient {
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

    pub fn database_path(&self) -> String {
        format!(
            "projects/{}/databases/{}",
            self.project_id, self.database_id
        )
    }

    pub fn documents_path(&self) -> String {
        format!("{}/documents", self.database_path())
    }

    pub fn collection_path(&self, collection: &str) -> String {
        format!("{}/{}", self.documents_path(), collection)
    }

    pub fn document_path(&self, collection: &str, document_id: &str) -> String {
        format!("{}/{}", self.collection_path(collection), document_id)
    }

    pub async fn create_document<T: Serialize>(
        &self,
        collection: &str,
        document_id: &str,
        data: &T,
    ) -> Result<()> {
        let fields = serialize_to_fields(data)?;
        let request = CreateDocumentRequest {
            parent: self.documents_path(),
            collection_id: collection.to_string(),
            document_id: document_id.to_string(),
            document: Some(Document {
                name: String::new(),
                fields,
                create_time: None,
                update_time: None,
            }),
            mask: None,
        };

        self.client
            .get()
            .create_document(request)
            .await
            .map_err(|e| TsaError::Database(format!("Failed to create document: {}", e)))?;

        Ok(())
    }

    pub async fn get_document<T: DeserializeOwned>(
        &self,
        collection: &str,
        document_id: &str,
    ) -> Result<Option<T>> {
        let request = GetDocumentRequest {
            name: self.document_path(collection, document_id),
            mask: None,
            consistency_selector: None,
        };

        match self.client.get().get_document(request).await {
            Ok(response) => {
                let doc = response.into_inner();
                let data = deserialize_from_fields(&doc.fields)?;
                Ok(Some(data))
            }
            Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
            Err(e) => Err(TsaError::Database(format!("Failed to get document: {}", e))),
        }
    }

    pub async fn update_document<T: Serialize>(
        &self,
        collection: &str,
        document_id: &str,
        data: &T,
    ) -> Result<()> {
        let fields = serialize_to_fields(data)?;
        let request = UpdateDocumentRequest {
            document: Some(Document {
                name: self.document_path(collection, document_id),
                fields,
                create_time: None,
                update_time: None,
            }),
            update_mask: None,
            mask: None,
            current_document: None,
        };

        self.client
            .get()
            .update_document(request)
            .await
            .map_err(|e| TsaError::Database(format!("Failed to update document: {}", e)))?;

        Ok(())
    }

    pub async fn delete_document(&self, collection: &str, document_id: &str) -> Result<()> {
        let request = DeleteDocumentRequest {
            name: self.document_path(collection, document_id),
            current_document: None,
        };

        self.client
            .get()
            .delete_document(request)
            .await
            .map_err(|e| TsaError::Database(format!("Failed to delete document: {}", e)))?;

        Ok(())
    }

    pub async fn find_by_field<T: DeserializeOwned + Serialize>(
        &self,
        collection: &str,
        field: &str,
        value: &str,
    ) -> Result<Option<T>> {
        let docs = self.list_documents::<T>(collection).await?;
        for doc in docs {
            let json = serde_json::to_value(&doc)
                .map_err(|e| TsaError::Database(format!("Serialization error: {}", e)))?;
            if let Some(field_value) = json.get(field) {
                if field_value.as_str() == Some(value) {
                    return Ok(Some(doc));
                }
            }
        }
        Ok(None)
    }

    pub async fn find_all_by_field<T: DeserializeOwned + Serialize>(
        &self,
        collection: &str,
        field: &str,
        value: &str,
    ) -> Result<Vec<T>> {
        let docs = self.list_documents::<T>(collection).await?;
        let mut results = Vec::new();
        for doc in docs {
            let json = serde_json::to_value(&doc)
                .map_err(|e| TsaError::Database(format!("Serialization error: {}", e)))?;
            if let Some(field_value) = json.get(field) {
                if field_value.as_str() == Some(value) {
                    results.push(doc);
                }
            }
        }
        Ok(results)
    }

    pub async fn list_documents<T: DeserializeOwned>(&self, collection: &str) -> Result<Vec<T>> {
        let request = ListDocumentsRequest {
            parent: self.documents_path(),
            collection_id: collection.to_string(),
            page_size: 1000,
            page_token: String::new(),
            order_by: String::new(),
            mask: None,
            show_missing: false,
            consistency_selector: None,
        };

        let response = self
            .client
            .get()
            .list_documents(request)
            .await
            .map_err(|e| TsaError::Database(format!("Failed to list documents: {}", e)))?;

        let mut results = Vec::new();
        for doc in response.into_inner().documents {
            let data: T = deserialize_from_fields(&doc.fields)?;
            results.push(data);
        }

        Ok(results)
    }
}

use gcloud_sdk::google::firestore::v1::Value;

fn serialize_to_fields<T: Serialize>(data: &T) -> Result<HashMap<String, Value>> {
    let json = serde_json::to_value(data)
        .map_err(|e| TsaError::Database(format!("Serialization error: {}", e)))?;

    let obj = json
        .as_object()
        .ok_or_else(|| TsaError::Database("Expected JSON object".to_string()))?;

    let mut fields = HashMap::new();
    for (key, value) in obj {
        fields.insert(key.clone(), json_to_firestore_value(value));
    }

    Ok(fields)
}

fn deserialize_from_fields<T: DeserializeOwned>(fields: &HashMap<String, Value>) -> Result<T> {
    let mut obj = serde_json::Map::new();
    for (key, value) in fields {
        obj.insert(key.clone(), firestore_value_to_json(value));
    }

    serde_json::from_value(serde_json::Value::Object(obj))
        .map_err(|e| TsaError::Database(format!("Deserialization error: {}", e)))
}

fn json_to_firestore_value(value: &serde_json::Value) -> Value {
    let value_type = match value {
        serde_json::Value::Null => ValueType::NullValue(0),
        serde_json::Value::Bool(b) => ValueType::BooleanValue(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                ValueType::IntegerValue(i)
            } else if let Some(f) = n.as_f64() {
                ValueType::DoubleValue(f)
            } else {
                ValueType::StringValue(n.to_string())
            }
        }
        serde_json::Value::String(s) => ValueType::StringValue(s.clone()),
        serde_json::Value::Array(arr) => {
            use gcloud_sdk::google::firestore::v1::ArrayValue;
            ValueType::ArrayValue(ArrayValue {
                values: arr.iter().map(json_to_firestore_value).collect(),
            })
        }
        serde_json::Value::Object(obj) => {
            use gcloud_sdk::google::firestore::v1::MapValue;
            let mut fields = HashMap::new();
            for (k, v) in obj {
                fields.insert(k.clone(), json_to_firestore_value(v));
            }
            ValueType::MapValue(MapValue { fields })
        }
    };

    Value {
        value_type: Some(value_type),
    }
}

fn firestore_value_to_json(value: &Value) -> serde_json::Value {
    match &value.value_type {
        Some(ValueType::NullValue(_)) => serde_json::Value::Null,
        Some(ValueType::BooleanValue(b)) => serde_json::Value::Bool(*b),
        Some(ValueType::IntegerValue(i)) => serde_json::json!(*i),
        Some(ValueType::DoubleValue(d)) => serde_json::json!(*d),
        Some(ValueType::StringValue(s)) => serde_json::Value::String(s.clone()),
        Some(ValueType::ArrayValue(arr)) => {
            serde_json::Value::Array(arr.values.iter().map(firestore_value_to_json).collect())
        }
        Some(ValueType::MapValue(map)) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in &map.fields {
                obj.insert(k.clone(), firestore_value_to_json(v));
            }
            serde_json::Value::Object(obj)
        }
        Some(ValueType::TimestampValue(ts)) => {
            use chrono::{TimeZone, Utc};
            let dt = Utc.timestamp_opt(ts.seconds, ts.nanos as u32).unwrap();
            serde_json::Value::String(dt.to_rfc3339())
        }
        Some(ValueType::BytesValue(bytes)) => serde_json::Value::String(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            bytes,
        )),
        Some(ValueType::ReferenceValue(r)) => serde_json::Value::String(r.clone()),
        Some(ValueType::GeoPointValue(geo)) => {
            serde_json::json!({"latitude": geo.latitude, "longitude": geo.longitude})
        }
        None => serde_json::Value::Null,
    }
}
