use anyhow::{anyhow, Result};
use reqwest::{Client, Response};
use serde::{de::DeserializeOwned, Serialize};

pub struct TsaClient {
    base_url: String,
    token: Option<String>,
    client: Client,
}

impl TsaClient {
    pub fn new(base_url: &str, token: Option<&str>) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.map(|t| t.to_string()),
            client: Client::new(),
        }
    }

    pub fn api_url(&self, path: &str) -> String {
        format!("{}/api/v1{}", self.base_url, path)
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let mut req = self.client.get(self.api_url(path));

        if let Some(ref token) = self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        let response = req.send().await?;
        self.handle_response(response).await
    }

    pub async fn post<T: DeserializeOwned, B: Serialize>(&self, path: &str, body: &B) -> Result<T> {
        let mut req = self.client.post(self.api_url(path)).json(body);

        if let Some(ref token) = self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        let response = req.send().await?;
        self.handle_response(response).await
    }

    pub async fn put<T: DeserializeOwned, B: Serialize>(&self, path: &str, body: &B) -> Result<T> {
        let mut req = self.client.put(self.api_url(path)).json(body);

        if let Some(ref token) = self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        let response = req.send().await?;
        self.handle_response(response).await
    }

    pub async fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let mut req = self.client.delete(self.api_url(path));

        if let Some(ref token) = self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        let response = req.send().await?;
        self.handle_response(response).await
    }

    async fn handle_response<T: DeserializeOwned>(&self, response: Response) -> Result<T> {
        let status = response.status();

        if status.is_success() {
            Ok(response.json().await?)
        } else {
            let error: serde_json::Value = response.json().await.unwrap_or_else(|_| {
                serde_json::json!({
                    "error": {
                        "code": "UNKNOWN",
                        "message": format!("Request failed with status {}", status)
                    }
                })
            });

            let message = error
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown error");

            Err(anyhow!("{}", message))
        }
    }
}
