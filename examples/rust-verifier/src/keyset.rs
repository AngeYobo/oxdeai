use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::VerifyingKey;

use crate::types::KeySet;

pub fn resolve_ed25519_key(keyset: &KeySet, issuer: &str, kid: &str, alg: &str) -> Result<VerifyingKey, String> {
    if issuer != keyset.issuer {
        return Err("AUTH_ISSUER_MISMATCH: issuer not trusted".to_string());
    }

    if alg != "Ed25519" {
        return Err("AUTH_ALG_UNSUPPORTED: unsupported signature algorithm".to_string());
    }

    let key = keyset
        .keys
        .iter()
        .find(|k| k.kid == kid && k.alg == alg)
        .ok_or_else(|| "AUTH_KID_UNKNOWN: kid not found for issuer/alg".to_string())?;

    let raw = STANDARD
        .decode(&key.public_key)
        .map_err(|_| "AUTH_KEY_MALFORMED: public key base64 decode failed".to_string())?;

    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| "AUTH_KEY_MALFORMED: expected Ed25519 32-byte public key".to_string())?;

    VerifyingKey::from_bytes(&arr)
        .map_err(|_| "AUTH_KEY_MALFORMED: invalid Ed25519 public key bytes".to_string())
}
