use aws_sdk_dynamodb::types::AttributeValue;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use tsa_core::TsaError;
use uuid::Uuid;

pub fn get_string(item: &HashMap<String, AttributeValue>, key: &str) -> Result<String, TsaError> {
    item.get(key)
        .and_then(|v| v.as_s().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| TsaError::Database(format!("Missing or invalid field: {}", key)))
}

pub fn get_string_opt(item: &HashMap<String, AttributeValue>, key: &str) -> Option<String> {
    item.get(key).and_then(|v| v.as_s().ok()).map(|s| s.to_string())
}

pub fn get_bool(item: &HashMap<String, AttributeValue>, key: &str) -> Result<bool, TsaError> {
    item.get(key)
        .and_then(|v| v.as_bool().ok())
        .copied()
        .ok_or_else(|| TsaError::Database(format!("Missing or invalid field: {}", key)))
}

pub fn get_uuid(item: &HashMap<String, AttributeValue>, key: &str) -> Result<Uuid, TsaError> {
    let s = get_string(item, key)?;
    Uuid::parse_str(&s).map_err(|e| TsaError::Database(format!("Invalid UUID: {}", e)))
}

pub fn get_uuid_opt(item: &HashMap<String, AttributeValue>, key: &str) -> Result<Option<Uuid>, TsaError> {
    match get_string_opt(item, key) {
        Some(s) => Uuid::parse_str(&s)
            .map(Some)
            .map_err(|e| TsaError::Database(format!("Invalid UUID: {}", e))),
        None => Ok(None),
    }
}

pub fn get_datetime(
    item: &HashMap<String, AttributeValue>,
    key: &str,
) -> Result<DateTime<Utc>, TsaError> {
    let s = get_string(item, key)?;
    DateTime::parse_from_rfc3339(&s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| TsaError::Database(format!("Invalid datetime: {}", e)))
}

pub fn get_datetime_opt(
    item: &HashMap<String, AttributeValue>,
    key: &str,
) -> Result<Option<DateTime<Utc>>, TsaError> {
    match get_string_opt(item, key) {
        Some(s) => DateTime::parse_from_rfc3339(&s)
            .map(|dt| Some(dt.with_timezone(&Utc)))
            .map_err(|e| TsaError::Database(format!("Invalid datetime: {}", e))),
        None => Ok(None),
    }
}

pub fn get_u32(item: &HashMap<String, AttributeValue>, key: &str) -> Result<u32, TsaError> {
    item.get(key)
        .and_then(|v| v.as_n().ok())
        .and_then(|n| n.parse::<u32>().ok())
        .ok_or_else(|| TsaError::Database(format!("Missing or invalid field: {}", key)))
}

pub fn get_string_vec(item: &HashMap<String, AttributeValue>, key: &str) -> Vec<String> {
    item.get(key)
        .and_then(|v| v.as_l().ok())
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_s().ok().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

pub fn get_bytes(item: &HashMap<String, AttributeValue>, key: &str) -> Result<Vec<u8>, TsaError> {
    item.get(key)
        .and_then(|v| v.as_b().ok())
        .map(|b| b.as_ref().to_vec())
        .ok_or_else(|| TsaError::Database(format!("Missing or invalid field: {}", key)))
}

pub fn string_vec_to_attr(vec: &[String]) -> AttributeValue {
    AttributeValue::L(vec.iter().map(|s| AttributeValue::S(s.clone())).collect())
}

pub fn opt_string_vec_to_attr(vec: &Option<Vec<String>>) -> AttributeValue {
    match vec {
        Some(v) => string_vec_to_attr(v),
        None => AttributeValue::Null(true),
    }
}
