use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizationV1 {
    pub auth_id: String,
    pub issuer: String,
    pub audience: String,
    pub intent_hash: String,
    pub state_hash: String,
    pub policy_id: String,
    pub decision: String,
    pub issued_at: i64,
    pub expiry: i64,
    pub alg: String,
    pub kid: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeySet {
    pub issuer: String,
    pub version: String,
    pub keys: Vec<Key>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Key {
    pub kid: String,
    pub alg: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Violation {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerificationResult {
    pub status: String,
    pub violations: Vec<Violation>,
}

impl VerificationResult {
    pub fn ok() -> Self {
        Self {
            status: "ok".to_string(),
            violations: vec![],
        }
    }

    pub fn invalid(code: &str, message: &str) -> Self {
        Self {
            status: "invalid".to_string(),
            violations: vec![Violation {
                code: code.to_string(),
                message: message.to_string(),
            }],
        }
    }
}
