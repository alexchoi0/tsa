use async_trait::async_trait;
use serde::Serialize;
use tsa_auth_core::{ApprovalRequest, Result, TsaError};

use crate::{ApprovalChannelDef, ApprovalChannelType};

pub type EmailSenderFn = Box<dyn Fn(&str, &str, &str) -> Result<()> + Send + Sync>;

#[async_trait]
pub trait ApprovalChannel: Send + Sync {
    fn channel_type(&self) -> ApprovalChannelType;

    async fn send_approval_request(
        &self,
        request: &ApprovalRequest,
        approve_url: &str,
        deny_url: &str,
    ) -> Result<()>;
}

pub struct MagicLinkChannel {
    pub send_email: EmailSenderFn,
}

#[async_trait]
impl ApprovalChannel for MagicLinkChannel {
    fn channel_type(&self) -> ApprovalChannelType {
        ApprovalChannelType::MagicLink
    }

    async fn send_approval_request(
        &self,
        request: &ApprovalRequest,
        approve_url: &str,
        deny_url: &str,
    ) -> Result<()> {
        let subject = format!("Approval Required: {}", request.permission);
        let body = format!(
            r#"An approval request requires your attention.

Permission: {}
Reason: {}

To approve: {}
To deny: {}

This request expires at: {}"#,
            request.permission,
            request.reason.as_deref().unwrap_or("No reason provided"),
            approve_url,
            deny_url,
            request.expires_at,
        );

        (self.send_email)(&subject, &body, approve_url)
    }
}

#[derive(Debug, Serialize)]
struct SlackMessage {
    channel: Option<String>,
    text: String,
    blocks: Vec<SlackBlock>,
}

#[derive(Debug, Serialize)]
struct SlackBlock {
    #[serde(rename = "type")]
    block_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<SlackText>,
    #[serde(skip_serializing_if = "Option::is_none")]
    elements: Option<Vec<SlackElement>>,
}

#[derive(Debug, Serialize)]
struct SlackText {
    #[serde(rename = "type")]
    text_type: String,
    text: String,
}

#[derive(Debug, Serialize)]
struct SlackElement {
    #[serde(rename = "type")]
    element_type: String,
    text: SlackText,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    style: Option<String>,
}

pub struct SlackChannel {
    webhook_url: String,
    channel: Option<String>,
    client: reqwest::Client,
}

impl SlackChannel {
    pub fn new(webhook_url: String, channel: Option<String>) -> Self {
        Self {
            webhook_url,
            channel,
            client: reqwest::Client::new(),
        }
    }

    pub fn from_config(config: &ApprovalChannelDef) -> Result<Self> {
        let webhook_url = config
            .webhook_url
            .clone()
            .ok_or_else(|| TsaError::Configuration("Slack channel requires webhook_url".into()))?;

        Ok(Self::new(webhook_url, config.channel.clone()))
    }
}

#[async_trait]
impl ApprovalChannel for SlackChannel {
    fn channel_type(&self) -> ApprovalChannelType {
        ApprovalChannelType::Slack
    }

    async fn send_approval_request(
        &self,
        request: &ApprovalRequest,
        approve_url: &str,
        deny_url: &str,
    ) -> Result<()> {
        let message = SlackMessage {
            channel: self.channel.clone(),
            text: format!("Approval Required: {}", request.permission),
            blocks: vec![
                SlackBlock {
                    block_type: "header".to_string(),
                    text: Some(SlackText {
                        text_type: "plain_text".to_string(),
                        text: "Approval Required".to_string(),
                    }),
                    elements: None,
                },
                SlackBlock {
                    block_type: "section".to_string(),
                    text: Some(SlackText {
                        text_type: "mrkdwn".to_string(),
                        text: format!(
                            "*Permission:* `{}`\n*Reason:* {}\n*Expires:* {}",
                            request.permission,
                            request.reason.as_deref().unwrap_or("_No reason provided_"),
                            request.expires_at.format("%Y-%m-%d %H:%M UTC"),
                        ),
                    }),
                    elements: None,
                },
                SlackBlock {
                    block_type: "actions".to_string(),
                    text: None,
                    elements: Some(vec![
                        SlackElement {
                            element_type: "button".to_string(),
                            text: SlackText {
                                text_type: "plain_text".to_string(),
                                text: "Approve".to_string(),
                            },
                            url: approve_url.to_string(),
                            style: Some("primary".to_string()),
                        },
                        SlackElement {
                            element_type: "button".to_string(),
                            text: SlackText {
                                text_type: "plain_text".to_string(),
                                text: "Deny".to_string(),
                            },
                            url: deny_url.to_string(),
                            style: Some("danger".to_string()),
                        },
                    ]),
                },
            ],
        };

        let response = self
            .client
            .post(&self.webhook_url)
            .json(&message)
            .send()
            .await
            .map_err(|e| TsaError::Internal(format!("Failed to send Slack message: {}", e)))?;

        if !response.status().is_success() {
            return Err(TsaError::Internal(format!(
                "Slack webhook returned error: {}",
                response.status()
            )));
        }

        Ok(())
    }
}

pub struct WebhookChannel {
    url: String,
    method: String,
    headers: std::collections::HashMap<String, String>,
    client: reqwest::Client,
}

impl WebhookChannel {
    pub fn new(
        url: String,
        method: Option<String>,
        headers: std::collections::HashMap<String, String>,
    ) -> Self {
        Self {
            url,
            method: method.unwrap_or_else(|| "POST".to_string()),
            headers,
            client: reqwest::Client::new(),
        }
    }

    pub fn from_config(config: &ApprovalChannelDef) -> Result<Self> {
        let url = config
            .url
            .clone()
            .ok_or_else(|| TsaError::Configuration("Webhook channel requires url".into()))?;

        Ok(Self::new(
            url,
            config.method.clone(),
            config.headers.clone(),
        ))
    }
}

#[derive(Debug, Serialize)]
struct WebhookPayload {
    request_id: String,
    permission: String,
    reason: Option<String>,
    context: Option<serde_json::Value>,
    approve_url: String,
    deny_url: String,
    expires_at: String,
}

#[async_trait]
impl ApprovalChannel for WebhookChannel {
    fn channel_type(&self) -> ApprovalChannelType {
        ApprovalChannelType::Webhook
    }

    async fn send_approval_request(
        &self,
        request: &ApprovalRequest,
        approve_url: &str,
        deny_url: &str,
    ) -> Result<()> {
        let payload = WebhookPayload {
            request_id: request.id.to_string(),
            permission: request.permission.clone(),
            reason: request.reason.clone(),
            context: request.context.clone(),
            approve_url: approve_url.to_string(),
            deny_url: deny_url.to_string(),
            expires_at: request.expires_at.to_rfc3339(),
        };

        let mut req = match self.method.to_uppercase().as_str() {
            "POST" => self.client.post(&self.url),
            "PUT" => self.client.put(&self.url),
            _ => self.client.post(&self.url),
        };

        for (key, value) in &self.headers {
            req = req.header(key, value);
        }

        let response = req
            .json(&payload)
            .send()
            .await
            .map_err(|e| TsaError::Internal(format!("Failed to send webhook: {}", e)))?;

        if !response.status().is_success() {
            return Err(TsaError::Internal(format!(
                "Webhook returned error: {}",
                response.status()
            )));
        }

        Ok(())
    }
}

pub fn create_channel(config: &ApprovalChannelDef) -> Result<Box<dyn ApprovalChannel>> {
    match config.channel_type {
        ApprovalChannelType::Slack => Ok(Box::new(SlackChannel::from_config(config)?)),
        ApprovalChannelType::Webhook => Ok(Box::new(WebhookChannel::from_config(config)?)),
        ApprovalChannelType::MagicLink | ApprovalChannelType::Email => {
            Err(TsaError::Configuration(
                "MagicLink and Email channels require custom implementation via callbacks".into(),
            ))
        }
    }
}
