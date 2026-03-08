use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier};
use serde_json::Value;

use crate::canonical::authorization_signing_input;
use crate::keyset::resolve_ed25519_key;
use crate::types::{AuthorizationV1, KeySet, VerificationResult};

fn required_non_empty(v: &str) -> bool {
    !v.trim().is_empty()
}

pub fn verify_authorization(
    auth: &AuthorizationV1,
    keyset: &KeySet,
    expected_audience: &str,
    now_unix: i64,
) -> VerificationResult {
    if !required_non_empty(&auth.auth_id)
        || !required_non_empty(&auth.issuer)
        || !required_non_empty(&auth.audience)
        || !required_non_empty(&auth.intent_hash)
        || !required_non_empty(&auth.state_hash)
        || !required_non_empty(&auth.policy_id)
        || !required_non_empty(&auth.alg)
        || !required_non_empty(&auth.kid)
        || !required_non_empty(&auth.signature)
    {
        return VerificationResult::invalid("AUTH_MISSING_FIELD", "one or more required fields are missing");
    }

    if auth.decision != "ALLOW" {
        return VerificationResult::invalid("AUTH_DECISION_INVALID", "authorization decision must be ALLOW");
    }

    if auth.expiry <= now_unix {
        return VerificationResult::invalid("AUTH_EXPIRED", "authorization has expired");
    }

    if auth.audience != expected_audience {
        return VerificationResult::invalid("AUTH_AUDIENCE_MISMATCH", "audience does not match expectedAudience");
    }

    let key = match resolve_ed25519_key(keyset, &auth.issuer, &auth.kid, &auth.alg) {
        Ok(k) => k,
        Err(err) => {
            let (code, msg) = err
                .split_once(": ")
                .map(|(c, m)| (c, m))
                .unwrap_or(("AUTH_VERIFICATION_ERROR", err.as_str()));
            return VerificationResult::invalid(code, msg);
        }
    };

    let mut payload = match serde_json::to_value(auth) {
        Ok(v) => v,
        Err(_) => {
            return VerificationResult::invalid("AUTH_MALFORMED", "authorization payload serialization failed")
        }
    };

    if let Value::Object(ref mut map) = payload {
        map.remove("signature");
    } else {
        return VerificationResult::invalid("AUTH_MALFORMED", "authorization payload must be an object");
    }

    let signing_input = match authorization_signing_input(&payload) {
        Ok(v) => v,
        Err(_) => {
            return VerificationResult::invalid("AUTH_MALFORMED", "failed to construct canonical signing input")
        }
    };

    let sig_bytes = match STANDARD.decode(&auth.signature) {
        Ok(v) => v,
        Err(_) => return VerificationResult::invalid("AUTH_SIGNATURE_INVALID", "signature verification failed"),
    };

    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(v) => v,
        Err(_) => return VerificationResult::invalid("AUTH_SIGNATURE_INVALID", "signature verification failed"),
    };

    if key.verify(&signing_input, &signature).is_err() {
        return VerificationResult::invalid("AUTH_SIGNATURE_INVALID", "signature verification failed");
    }

    VerificationResult::ok()
}
