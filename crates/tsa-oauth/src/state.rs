use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tsa_core::{Result, TsaError};

#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthState {
    pub csrf_token: String,
    pub pkce_verifier: Option<String>,
    pub provider: String,
    signature: String,
}

impl OAuthState {
    pub fn new(provider: &str, csrf_token: String, pkce_verifier: Option<String>, secret: &str) -> Self {
        let mut state = Self {
            csrf_token,
            pkce_verifier,
            provider: provider.to_string(),
            signature: String::new(),
        };
        state.signature = state.compute_signature(secret);
        state
    }

    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_string(self)
            .map_err(|e| TsaError::Internal(e.to_string()))?;
        Ok(URL_SAFE_NO_PAD.encode(json.as_bytes()))
    }

    pub fn decode(encoded: &str, secret: &str) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| TsaError::InvalidToken)?;

        let state: Self = serde_json::from_slice(&bytes)
            .map_err(|_| TsaError::InvalidToken)?;

        let expected_sig = state.compute_signature(secret);
        if state.signature != expected_sig {
            return Err(TsaError::InvalidToken);
        }

        Ok(state)
    }

    fn compute_signature(&self, secret: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.csrf_token.as_bytes());
        hasher.update(self.provider.as_bytes());
        if let Some(ref pkce) = self.pkce_verifier {
            hasher.update(pkce.as_bytes());
        }
        hasher.update(secret.as_bytes());
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &str = "test_secret_key_12345";

    #[test]
    fn test_state_creation() {
        let state = OAuthState::new("google", "csrf123".to_string(), None, TEST_SECRET);
        assert_eq!(state.provider, "google");
        assert_eq!(state.csrf_token, "csrf123");
        assert!(state.pkce_verifier.is_none());
        assert!(!state.signature.is_empty());
    }

    #[test]
    fn test_state_with_pkce() {
        let state = OAuthState::new(
            "github",
            "csrf456".to_string(),
            Some("pkce_verifier".to_string()),
            TEST_SECRET,
        );
        assert_eq!(state.provider, "github");
        assert_eq!(state.pkce_verifier, Some("pkce_verifier".to_string()));
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = OAuthState::new("discord", "csrf789".to_string(), None, TEST_SECRET);

        let encoded = original.encode().unwrap();
        assert!(!encoded.is_empty());

        let decoded = OAuthState::decode(&encoded, TEST_SECRET).unwrap();
        assert_eq!(decoded.provider, original.provider);
        assert_eq!(decoded.csrf_token, original.csrf_token);
        assert_eq!(decoded.pkce_verifier, original.pkce_verifier);
    }

    #[test]
    fn test_encode_decode_with_pkce() {
        let original = OAuthState::new(
            "microsoft",
            "my_csrf".to_string(),
            Some("my_pkce_verifier".to_string()),
            TEST_SECRET,
        );

        let encoded = original.encode().unwrap();
        let decoded = OAuthState::decode(&encoded, TEST_SECRET).unwrap();

        assert_eq!(decoded.pkce_verifier, Some("my_pkce_verifier".to_string()));
    }

    #[test]
    fn test_decode_wrong_secret_fails() {
        let state = OAuthState::new("apple", "csrf000".to_string(), None, TEST_SECRET);
        let encoded = state.encode().unwrap();

        let result = OAuthState::decode(&encoded, "wrong_secret");
        assert!(matches!(result, Err(TsaError::InvalidToken)));
    }

    #[test]
    fn test_decode_invalid_base64_fails() {
        let result = OAuthState::decode("not_valid_base64!!!", TEST_SECRET);
        assert!(matches!(result, Err(TsaError::InvalidToken)));
    }

    #[test]
    fn test_decode_invalid_json_fails() {
        let invalid_json = URL_SAFE_NO_PAD.encode(b"not json at all");
        let result = OAuthState::decode(&invalid_json, TEST_SECRET);
        assert!(matches!(result, Err(TsaError::InvalidToken)));
    }

    #[test]
    fn test_different_providers_different_signatures() {
        let state1 = OAuthState::new("google", "same_csrf".to_string(), None, TEST_SECRET);
        let state2 = OAuthState::new("github", "same_csrf".to_string(), None, TEST_SECRET);

        assert_ne!(state1.signature, state2.signature);
    }

    #[test]
    fn test_different_csrf_different_signatures() {
        let state1 = OAuthState::new("google", "csrf1".to_string(), None, TEST_SECRET);
        let state2 = OAuthState::new("google", "csrf2".to_string(), None, TEST_SECRET);

        assert_ne!(state1.signature, state2.signature);
    }

    #[test]
    fn test_pkce_affects_signature() {
        let state1 = OAuthState::new("google", "csrf".to_string(), None, TEST_SECRET);
        let state2 = OAuthState::new(
            "google",
            "csrf".to_string(),
            Some("pkce".to_string()),
            TEST_SECRET,
        );

        assert_ne!(state1.signature, state2.signature);
    }
}
