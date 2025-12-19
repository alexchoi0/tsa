use chrono::Duration;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use tsa_core::{ApprovalDecision, ApprovalRequest, ApprovalResponse, ApprovalStatus, ApprovalToken};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApprovalRequest {
    pub organization_id: Uuid,
    pub requester_id: Uuid,
    pub policy_name: String,
    pub permission: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub reason: Option<String>,
    pub context: Option<serde_json::Value>,
}

pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim().to_lowercase();

    if let Some(hours) = s.strip_suffix('h') {
        hours.parse::<i64>().ok().map(Duration::hours)
    } else if let Some(minutes) = s.strip_suffix('m') {
        minutes.parse::<i64>().ok().map(Duration::minutes)
    } else if let Some(days) = s.strip_suffix('d') {
        days.parse::<i64>().ok().map(Duration::days)
    } else if let Some(seconds) = s.strip_suffix('s') {
        seconds.parse::<i64>().ok().map(Duration::seconds)
    } else {
        s.parse::<i64>().ok().map(Duration::seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("24h"), Some(Duration::hours(24)));
        assert_eq!(parse_duration("30m"), Some(Duration::minutes(30)));
        assert_eq!(parse_duration("7d"), Some(Duration::days(7)));
        assert_eq!(parse_duration("60s"), Some(Duration::seconds(60)));
        assert_eq!(parse_duration("3600"), Some(Duration::seconds(3600)));
    }

    #[test]
    fn test_parse_duration_with_whitespace() {
        assert_eq!(parse_duration("  24h  "), Some(Duration::hours(24)));
        assert_eq!(parse_duration(" 30M "), Some(Duration::minutes(30)));
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert_eq!(parse_duration("abc"), None);
        assert_eq!(parse_duration("24x"), None);
    }
}
