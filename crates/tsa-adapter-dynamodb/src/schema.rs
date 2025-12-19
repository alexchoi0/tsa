use async_trait::async_trait;
use aws_sdk_dynamodb::{
    types::{
        AttributeDefinition, BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType,
        Projection, ProjectionType, ScalarAttributeType, TimeToLiveSpecification,
    },
    Client,
};
use tsa_core::{Result, SchemaManager, TsaError};

use crate::{
    TABLE_ACCOUNTS, TABLE_API_KEYS, TABLE_ORGANIZATIONS, TABLE_ORGANIZATION_INVITATIONS,
    TABLE_ORGANIZATION_MEMBERS, TABLE_PASSKEYS, TABLE_PASSKEY_CHALLENGES, TABLE_SESSIONS,
    TABLE_TWO_FACTORS, TABLE_USERS, TABLE_VERIFICATION_TOKENS,
};

pub struct DynamoDbSchemaManager {
    client: Client,
    table_prefix: String,
}

impl DynamoDbSchemaManager {
    pub fn new(client: Client, table_prefix: &str) -> Self {
        Self {
            client,
            table_prefix: table_prefix.to_string(),
        }
    }

    fn table_name(&self, base: &str) -> String {
        format!("{}{}", self.table_prefix, base)
    }

    fn attr_def(name: &str, attr_type: ScalarAttributeType) -> AttributeDefinition {
        AttributeDefinition::builder()
            .attribute_name(name)
            .attribute_type(attr_type)
            .build()
            .unwrap()
    }

    fn key_schema(name: &str, key_type: KeyType) -> KeySchemaElement {
        KeySchemaElement::builder()
            .attribute_name(name)
            .key_type(key_type)
            .build()
            .unwrap()
    }

    fn gsi(name: &str, hash_key: &str) -> GlobalSecondaryIndex {
        GlobalSecondaryIndex::builder()
            .index_name(name)
            .key_schema(Self::key_schema(hash_key, KeyType::Hash))
            .projection(
                Projection::builder()
                    .projection_type(ProjectionType::All)
                    .build(),
            )
            .build()
            .unwrap()
    }

    async fn create_table_with_gsis(
        &self,
        table_name: &str,
        attributes: Vec<(&str, ScalarAttributeType)>,
        gsi_keys: Vec<&str>,
        ttl_attribute: Option<&str>,
    ) -> Result<()> {
        let mut attr_defs: Vec<AttributeDefinition> = vec![Self::attr_def("id", ScalarAttributeType::S)];
        for (name, attr_type) in &attributes {
            attr_defs.push(Self::attr_def(name, attr_type.clone()));
        }

        let gsis: Vec<GlobalSecondaryIndex> = gsi_keys
            .iter()
            .map(|key| Self::gsi(&format!("{}-index", key), key))
            .collect();

        let mut builder = self
            .client
            .create_table()
            .table_name(table_name)
            .billing_mode(BillingMode::PayPerRequest)
            .key_schema(Self::key_schema("id", KeyType::Hash));

        for attr_def in attr_defs {
            builder = builder.attribute_definitions(attr_def);
        }

        for gsi in gsis {
            builder = builder.global_secondary_indexes(gsi);
        }

        builder
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        if let Some(ttl_attr) = ttl_attribute {
            self.client
                .update_time_to_live()
                .table_name(table_name)
                .time_to_live_specification(
                    TimeToLiveSpecification::builder()
                        .enabled(true)
                        .attribute_name(ttl_attr)
                        .build()
                        .unwrap(),
                )
                .send()
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }

        Ok(())
    }

    async fn delete_table(&self, table_name: &str) -> Result<()> {
        self.client
            .delete_table()
            .table_name(table_name)
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl SchemaManager for DynamoDbSchemaManager {
    async fn ensure_schema(&self) -> Result<()> {
        self.create_table_with_gsis(
            &self.table_name(TABLE_USERS),
            vec![
                ("email", ScalarAttributeType::S),
                ("phone", ScalarAttributeType::S),
            ],
            vec!["email", "phone"],
            None,
        )
        .await?;

        self.create_table_with_gsis(
            &self.table_name(TABLE_SESSIONS),
            vec![
                ("token_hash", ScalarAttributeType::S),
                ("user_id", ScalarAttributeType::S),
            ],
            vec!["token_hash", "user_id"],
            Some("ttl"),
        )
        .await?;

        self.create_table_with_gsis(
            &self.table_name(TABLE_ACCOUNTS),
            vec![
                ("provider_key", ScalarAttributeType::S),
                ("user_id", ScalarAttributeType::S),
            ],
            vec!["provider_key", "user_id"],
            None,
        )
        .await?;

        self.create_table_with_gsis(
            &self.table_name(TABLE_VERIFICATION_TOKENS),
            vec![("token_hash", ScalarAttributeType::S)],
            vec!["token_hash"],
            Some("ttl"),
        )
        .await?;

        self.create_table_with_gsis(
            &self.table_name(TABLE_TWO_FACTORS),
            vec![("user_id", ScalarAttributeType::S)],
            vec!["user_id"],
            None,
        )
        .await?;

        self.create_table_with_gsis(
            &self.table_name(TABLE_ORGANIZATIONS),
            vec![("slug", ScalarAttributeType::S)],
            vec!["slug"],
            None,
        )
        .await?;

        self.create_table_with_gsis(
            &self.table_name(TABLE_ORGANIZATION_MEMBERS),
            vec![
                ("org_user_key", ScalarAttributeType::S),
                ("organization_id", ScalarAttributeType::S),
                ("user_id", ScalarAttributeType::S),
            ],
            vec!["org_user_key", "organization_id", "user_id"],
            None,
        )
        .await?;

        self.create_table_with_gsis(
            &self.table_name(TABLE_ORGANIZATION_INVITATIONS),
            vec![
                ("token_hash", ScalarAttributeType::S),
                ("organization_id", ScalarAttributeType::S),
                ("email", ScalarAttributeType::S),
            ],
            vec!["token_hash", "organization_id", "email"],
            Some("ttl"),
        )
        .await?;

        self.create_table_with_gsis(
            &self.table_name(TABLE_API_KEYS),
            vec![
                ("key_hash", ScalarAttributeType::S),
                ("prefix", ScalarAttributeType::S),
                ("user_id", ScalarAttributeType::S),
                ("organization_id", ScalarAttributeType::S),
            ],
            vec!["key_hash", "prefix", "user_id", "organization_id"],
            None,
        )
        .await?;

        self.create_table_with_gsis(
            &self.table_name(TABLE_PASSKEYS),
            vec![
                ("credential_id_b64", ScalarAttributeType::S),
                ("user_id", ScalarAttributeType::S),
            ],
            vec!["credential_id_b64", "user_id"],
            None,
        )
        .await?;

        self.create_table_with_gsis(
            &self.table_name(TABLE_PASSKEY_CHALLENGES),
            vec![("challenge_b64", ScalarAttributeType::S)],
            vec!["challenge_b64"],
            Some("ttl"),
        )
        .await?;

        Ok(())
    }

    async fn drop_schema(&self) -> Result<()> {
        let tables = [
            TABLE_USERS,
            TABLE_SESSIONS,
            TABLE_ACCOUNTS,
            TABLE_VERIFICATION_TOKENS,
            TABLE_TWO_FACTORS,
            TABLE_ORGANIZATIONS,
            TABLE_ORGANIZATION_MEMBERS,
            TABLE_ORGANIZATION_INVITATIONS,
            TABLE_API_KEYS,
            TABLE_PASSKEYS,
            TABLE_PASSKEY_CHALLENGES,
        ];

        for table in tables {
            let _ = self.delete_table(&self.table_name(table)).await;
        }

        Ok(())
    }
}
