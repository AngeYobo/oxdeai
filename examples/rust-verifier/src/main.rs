use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use oxdeai_rust_verifier::types::{AuthorizationV1, KeySet};
use oxdeai_rust_verifier::verify_authorization::verify_authorization;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: cargo run -- <auth.json> <keyset.json> <expected_audience>");
        std::process::exit(2);
    }

    let auth_raw = match fs::read_to_string(&args[1]) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("DENY (AUTH_MALFORMED: failed to read auth file)");
            std::process::exit(1);
        }
    };

    let keyset_raw = match fs::read_to_string(&args[2]) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("DENY (AUTH_KEY_MALFORMED: failed to read keyset file)");
            std::process::exit(1);
        }
    };

    let auth: AuthorizationV1 = match serde_json::from_str(&auth_raw) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("DENY (AUTH_MALFORMED: invalid auth json)");
            std::process::exit(1);
        }
    };

    let keyset: KeySet = match serde_json::from_str(&keyset_raw) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("DENY (AUTH_KEY_MALFORMED: invalid keyset json)");
            std::process::exit(1);
        }
    };

    let result = verify_authorization(&auth, &keyset, &args[3], now_unix());

    if result.status == "ok" {
        println!("ALLOW");
        return;
    }

    if let Some(v) = result.violations.first() {
        eprintln!("DENY ({}: {})", v.code, v.message);
    } else {
        eprintln!("DENY (AUTH_VERIFICATION_ERROR: unknown)");
    }
    std::process::exit(1);
}
