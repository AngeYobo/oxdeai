use serde_json::{Map, Value};

pub const AUTH_DOMAIN: &str = "OXDEAI_AUTH_V1";

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for k in keys {
                out.insert(k.clone(), canonicalize(&obj[k]));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}

pub fn canonical_json(value: &Value) -> Result<String, String> {
    serde_json::to_string(&canonicalize(value)).map_err(|e| format!("canonical json failed: {e}"))
}

pub fn authorization_signing_input(payload_without_signature: &Value) -> Result<Vec<u8>, String> {
    let canonical = canonical_json(payload_without_signature)?;
    let mut bytes = Vec::with_capacity(AUTH_DOMAIN.len() + 1 + canonical.len());
    bytes.extend_from_slice(AUTH_DOMAIN.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(canonical.as_bytes());
    Ok(bytes)
}
