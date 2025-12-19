use async_trait::async_trait;
use oauth2::{
    basic::BasicTokenType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EmptyExtraTokenFields, EndpointNotSet, EndpointSet, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, RevocationErrorResponseType, Scope, StandardErrorResponse,
    StandardRevocableToken, StandardTokenIntrospectionResponse, StandardTokenResponse,
    TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use tsa_core::{Result, TsaError};

pub type ConfiguredClient = oauth2::Client<
    StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
    StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    StandardTokenIntrospectionResponse<EmptyExtraTokenFields, BasicTokenType>,
    StandardRevocableToken,
    StandardErrorResponse<RevocationErrorResponseType>,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthUserInfo {
    pub provider_user_id: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub image: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<std::time::Duration>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuthorizationUrl {
    pub url: String,
    pub csrf_token: String,
    pub pkce_verifier: Option<String>,
}

#[async_trait]
pub trait OAuthProvider: Send + Sync {
    fn name(&self) -> &'static str;

    fn client(&self) -> &ConfiguredClient;

    fn scopes(&self) -> Vec<Scope>;

    fn use_pkce(&self) -> bool {
        true
    }

    fn authorization_url(&self) -> AuthorizationUrl {
        let client = self.client();

        if self.use_pkce() {
            let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

            let mut builder = client
                .authorize_url(CsrfToken::new_random)
                .set_pkce_challenge(pkce_challenge);

            for scope in self.scopes() {
                builder = builder.add_scope(scope);
            }

            let (url, csrf_token) = builder.url();

            AuthorizationUrl {
                url: url.to_string(),
                csrf_token: csrf_token.secret().clone(),
                pkce_verifier: Some(pkce_verifier.secret().clone()),
            }
        } else {
            let mut builder = client.authorize_url(CsrfToken::new_random);

            for scope in self.scopes() {
                builder = builder.add_scope(scope);
            }

            let (url, csrf_token) = builder.url();

            AuthorizationUrl {
                url: url.to_string(),
                csrf_token: csrf_token.secret().clone(),
                pkce_verifier: None,
            }
        }
    }

    async fn exchange_code(&self, code: &str, pkce_verifier: Option<&str>) -> Result<OAuthTokens> {
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| TsaError::Internal(e.to_string()))?;

        let code = AuthorizationCode::new(code.to_string());

        let token_result = if let Some(verifier) = pkce_verifier {
            self.client()
                .exchange_code(code)
                .set_pkce_verifier(PkceCodeVerifier::new(verifier.to_string()))
                .request_async(&http_client)
                .await
        } else {
            self.client()
                .exchange_code(code)
                .request_async(&http_client)
                .await
        };

        let token_response = token_result
            .map_err(|e| TsaError::Internal(format!("Token exchange failed: {}", e)))?;

        Ok(OAuthTokens {
            access_token: token_response.access_token().secret().clone(),
            refresh_token: token_response.refresh_token().map(|t| t.secret().clone()),
            expires_in: token_response.expires_in(),
            scopes: token_response
                .scopes()
                .map(|s| s.iter().map(|scope| scope.to_string()).collect())
                .unwrap_or_default(),
        })
    }

    async fn get_user_info(&self, access_token: &str) -> Result<OAuthUserInfo>;
}

pub fn create_oauth_client(
    client_id: &str,
    client_secret: &str,
    auth_url: &str,
    token_url: &str,
    redirect_url: &str,
) -> Result<ConfiguredClient> {
    use oauth2::basic::BasicClient;

    let auth_url =
        AuthUrl::new(auth_url.to_string()).map_err(|e| TsaError::Configuration(e.to_string()))?;
    let token_url =
        TokenUrl::new(token_url.to_string()).map_err(|e| TsaError::Configuration(e.to_string()))?;
    let redirect_url = RedirectUrl::new(redirect_url.to_string())
        .map_err(|e| TsaError::Configuration(e.to_string()))?;

    let client = BasicClient::new(ClientId::new(client_id.to_string()))
        .set_client_secret(ClientSecret::new(client_secret.to_string()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(redirect_url);

    Ok(client)
}
