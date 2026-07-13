//! Proof-of-Possession (PoP) primitives for ISEKAI Link P2P Connect.
//!
//! These helpers let the MASQUE Proxy verify, *offline*, that a request was
//! signed by the Endpoint private key that a given Endpoint Token is bound to.
//! The Endpoint's ECDSA P-256 public key is carried inside the Endpoint Token
//! as an RFC 7800 `cnf.jwk` confirmation key (decision D-2 in
//! `docs/p2p_connect_implementation_plan.md`), so no round-trip to the Identity
//! API is required.
//!
//! This module implements the crypto building blocks from the spec
//! (`docs/p2p_connect_spec.md`):
//!
//! * §4.2 — Endpoint ID = `SHA256(JWK Thumbprint)`
//! * §8.0 — the PoP canonical request string and its ECDSA P-256 / SHA-256
//!   signature
//! * RFC 7638 — the JWK thumbprint itself
//!
//! It performs **no** timestamp-skew or nonce-replay checking; those are
//! stateful concerns handled by the request middleware (implementation-plan
//! phase 1).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Prefix that all Endpoint IDs carry (spec §8.1).
pub const ENDPOINT_ID_PREFIX: &str = "ep:";

/// Errors produced while deriving identifiers from, or verifying signatures
/// against, an Endpoint JWK.
#[derive(Debug, thiserror::Error)]
pub enum PopError {
    /// The supplied JWK value was not a JSON object.
    #[error("JWK is not a JSON object")]
    JwkNotObject,
    /// A required JWK member (`kty`, `crv`, `x`, `y`) was absent or not a string.
    #[error("JWK is missing required member `{0}`")]
    JwkMissingField(&'static str),
    /// The key is not an EC P-256 key, the only type P2P Connect supports.
    #[error("unsupported key: expected an EC P-256 JWK")]
    UnsupportedKey,
    /// The JWK could not be parsed into a usable public key.
    #[error("invalid JWK public key: {0}")]
    InvalidPublicKey(String),
    /// The signature was not valid base64url.
    #[error("PoP signature is not valid base64url")]
    SignatureEncoding,
    /// The signature bytes were neither a 64-byte fixed (P1363) nor a DER ECDSA
    /// signature.
    #[error("PoP signature is malformed")]
    SignatureMalformed,
    /// The signature did not verify against the canonical string and key.
    #[error("PoP signature verification failed")]
    VerificationFailed,
}

/// Compute the RFC 7638 JWK thumbprint (SHA-256) of an EC P-256 public key.
///
/// Only the required members for an EC key — `crv`, `kty`, `x`, `y` — are
/// included, serialized as a whitespace-free JSON object with the members in
/// lexicographic order, exactly as RFC 7638 §3.2 prescribes.
pub fn jwk_thumbprint(jwk: &Value) -> Result<[u8; 32], PopError> {
    if !jwk.is_object() {
        return Err(PopError::JwkNotObject);
    }
    // Reject a non-EC/P-256 key up front so an unsupported key type is never
    // mistaken for a merely malformed EC key.
    if jwk_str(jwk, "kty")? != "EC" {
        return Err(PopError::UnsupportedKey);
    }
    if jwk_str(jwk, "crv")? != "P-256" {
        return Err(PopError::UnsupportedKey);
    }
    let kty = "EC";
    let crv = "P-256";
    let x = jwk_str(jwk, "x")?;
    let y = jwk_str(jwk, "y")?;

    // RFC 7638 §3.2: required members only, lexicographic order (crv < kty < x
    // < y), no whitespace. `json_string` handles quoting/escaping of values.
    let canonical = format!(
        "{{\"crv\":{},\"kty\":{},\"x\":{},\"y\":{}}}",
        json_string(crv),
        json_string(kty),
        json_string(x),
        json_string(y),
    );
    Ok(Sha256::digest(canonical.as_bytes()).into())
}

/// Derive the canonical (untruncated) Endpoint ID from an Endpoint JWK.
///
/// Per spec §4.2, `Endpoint ID = SHA256(JWK Thumbprint)`, rendered as
/// `"ep:" + lowercase-hex`. Note the spec applies SHA-256 to the thumbprint
/// (which is itself a SHA-256 digest); this is implemented literally.
pub fn endpoint_id_from_jwk(jwk: &Value) -> Result<String, PopError> {
    let thumbprint = jwk_thumbprint(jwk)?;
    let digest = Sha256::digest(thumbprint);
    Ok(format!("{ENDPOINT_ID_PREFIX}{}", hex_encode(&digest)))
}

/// Check that a presented Endpoint ID identifies the given JWK.
///
/// The spec (§8.1) allows an Endpoint ID to be presented truncated to the
/// leading 6–64 lowercase hex characters of the canonical value. A presented
/// id matches when it is `"ep:"` followed by an even-length lowercase-hex
/// prefix (6–64 chars) of the canonical hex digest.
pub fn endpoint_id_matches(presented: &str, jwk: &Value) -> Result<bool, PopError> {
    let Some(hex) = presented.strip_prefix(ENDPOINT_ID_PREFIX) else {
        return Ok(false);
    };
    if !(6..=64).contains(&hex.len()) || hex.len() % 2 != 0 {
        return Ok(false);
    }
    if !hex
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Ok(false);
    }
    let full = endpoint_id_from_jwk(jwk)?;
    Ok(full[ENDPOINT_ID_PREFIX.len()..].starts_with(hex))
}

/// Build the PoP canonical request string (spec §8.0).
///
/// ```text
/// <HTTP-METHOD>\n
/// <path-with-query>\n
/// <X-Endpoint-Id>\n
/// <X-PoP-Timestamp>\n
/// <X-PoP-Nonce>\n
/// BASE64URL(SHA256(request-body))
/// ```
///
/// `body` is hashed even when empty (an absent body uses `SHA256("")`), and the
/// final line carries no trailing newline.
pub fn canonical_pop_string(
    method: &str,
    path_with_query: &str,
    endpoint_id: &str,
    timestamp: &str,
    nonce: &str,
    body: &[u8],
) -> String {
    let body_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(body));
    format!("{method}\n{path_with_query}\n{endpoint_id}\n{timestamp}\n{nonce}\n{body_hash}")
}

/// Verify a PoP signature over `canonical` using the Endpoint's `cnf` JWK.
///
/// The signature must be an ECDSA P-256 / SHA-256 signature (spec §8.0),
/// base64url-encoded, in either 64-byte fixed (IEEE P1363 `r || s`, as produced
/// by WebCrypto and JWS ES256) or ASN.1 DER form. Returns `Ok(())` on success.
pub fn verify_pop(jwk: &Value, canonical: &str, signature_b64url: &str) -> Result<(), PopError> {
    use p256::ecdsa::signature::Verifier;

    let public_key = p256::PublicKey::from_jwk_str(&jwk.to_string())
        .map_err(|e| PopError::InvalidPublicKey(e.to_string()))?;
    let verifying_key = p256::ecdsa::VerifyingKey::from(public_key);

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64url)
        .map_err(|_| PopError::SignatureEncoding)?;
    let signature = p256::ecdsa::Signature::from_slice(&sig_bytes)
        .or_else(|_| p256::ecdsa::Signature::from_der(&sig_bytes))
        .map_err(|_| PopError::SignatureMalformed)?;

    verifying_key
        .verify(canonical.as_bytes(), &signature)
        .map_err(|_| PopError::VerificationFailed)
}

fn jwk_str<'a>(jwk: &'a Value, key: &'static str) -> Result<&'a str, PopError> {
    jwk.get(key)
        .and_then(Value::as_str)
        .ok_or(PopError::JwkMissingField(key))
}

/// Serialize a string as a JSON string literal (quoted and escaped).
fn json_string(s: &str) -> String {
    serde_json::to_string(s).expect("serializing a &str to JSON is infallible")
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).expect("nibble is < 16"));
        out.push(char::from_digit((b & 0x0f) as u32, 16).expect("nibble is < 16"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;

    /// Build a deterministic signing key and its `cnf`-shaped public JWK.
    fn test_key() -> (p256::ecdsa::SigningKey, Value) {
        // Fixed non-zero scalar → deterministic (RFC 6979) signatures, so the
        // whole test is reproducible without an RNG.
        let signing_key = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let public_key = p256::PublicKey::from(*signing_key.verifying_key());
        let jwk: Value = serde_json::from_str(&public_key.to_jwk_string()).unwrap();
        (signing_key, jwk)
    }

    #[test]
    fn sha256_empty_body_matches_known_vector() {
        // The last line of the canonical string for an empty body is a fixed,
        // well-known value; this pins the base64url(SHA256("")) encoding.
        let canonical = canonical_pop_string("GET", "/", "ep:abc", "t", "n", b"");
        let last = canonical.rsplit('\n').next().unwrap();
        assert_eq!(last, "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
    }

    #[test]
    fn canonical_string_has_six_lines_and_no_trailing_newline() {
        let s = canonical_pop_string(
            "POST",
            "/v1/peer/connect?x=1",
            "ep:f4d9c3",
            "2026-07-13T08:10:00Z",
            "4mQx",
            b"{}",
        );
        assert_eq!(s.lines().count(), 6);
        assert!(!s.ends_with('\n'));
        assert!(s.starts_with("POST\n/v1/peer/connect?x=1\nep:f4d9c3\n"));
    }

    #[test]
    fn thumbprint_uses_rfc7638_canonical_ordering() {
        let (_sk, jwk) = test_key();
        let crv = jwk["crv"].as_str().unwrap();
        let kty = jwk["kty"].as_str().unwrap();
        let x = jwk["x"].as_str().unwrap();
        let y = jwk["y"].as_str().unwrap();
        // Independently constructed canonical form (members in lexicographic
        // order, no whitespace) must hash to the same digest.
        let expected_canonical = format!(r#"{{"crv":"{crv}","kty":"{kty}","x":"{x}","y":"{y}"}}"#);
        let expected: [u8; 32] = Sha256::digest(expected_canonical.as_bytes()).into();
        assert_eq!(jwk_thumbprint(&jwk).unwrap(), expected);
    }

    #[test]
    fn thumbprint_rejects_non_ec_key() {
        let rsa = serde_json::json!({ "kty": "RSA", "n": "aa", "e": "AQAB" });
        assert!(matches!(
            jwk_thumbprint(&rsa),
            Err(PopError::UnsupportedKey)
        ));
        let missing = serde_json::json!({ "kty": "EC", "crv": "P-256", "x": "aa" });
        assert!(matches!(
            jwk_thumbprint(&missing),
            Err(PopError::JwkMissingField("y"))
        ));
    }

    #[test]
    fn endpoint_id_is_stable_and_prefixed() {
        let (_sk, jwk) = test_key();
        let id = endpoint_id_from_jwk(&jwk).unwrap();
        assert!(id.starts_with("ep:"));
        assert_eq!(id.len(), ENDPOINT_ID_PREFIX.len() + 64); // hex of SHA-256
        assert_eq!(endpoint_id_from_jwk(&jwk).unwrap(), id); // deterministic
    }

    #[test]
    fn endpoint_id_matches_truncated_prefix() {
        let (_sk, jwk) = test_key();
        let full = endpoint_id_from_jwk(&jwk).unwrap();
        let hex = &full[ENDPOINT_ID_PREFIX.len()..];

        assert!(endpoint_id_matches(&full, &jwk).unwrap());
        assert!(endpoint_id_matches(&format!("ep:{}", &hex[..12]), &jwk).unwrap());
        // Too short (< 6 hex), wrong prefix, and uppercase are all rejected.
        assert!(!endpoint_id_matches("ep:ab", &jwk).unwrap());
        assert!(!endpoint_id_matches("ep:ffffffffffff", &jwk).unwrap());
        assert!(!endpoint_id_matches(&hex[..12], &jwk).unwrap()); // no "ep:"
    }

    #[test]
    fn verify_pop_accepts_valid_p1363_signature() {
        let (signing_key, jwk) = test_key();
        let endpoint_id = endpoint_id_from_jwk(&jwk).unwrap();
        let canonical = canonical_pop_string(
            "POST",
            "/v1/peer/connect",
            &endpoint_id,
            "2026-07-13T08:40:00Z",
            "nonce-abc",
            b"{\"capability\":\"cap_x\"}",
        );
        let signature: p256::ecdsa::Signature = signing_key.sign(canonical.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        assert!(verify_pop(&jwk, &canonical, &sig_b64).is_ok());
    }

    #[test]
    fn verify_pop_accepts_der_signature() {
        let (signing_key, jwk) = test_key();
        let canonical =
            canonical_pop_string("GET", "/v1/peer/connections/x", "ep:a", "t", "n", b"");
        let signature: p256::ecdsa::Signature = signing_key.sign(canonical.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes());

        assert!(verify_pop(&jwk, &canonical, &sig_b64).is_ok());
    }

    #[test]
    fn verify_pop_rejects_tampered_message_and_signature() {
        let (signing_key, jwk) = test_key();
        let canonical = canonical_pop_string("POST", "/v1/peer/connect", "ep:a", "t", "n", b"body");
        let signature: p256::ecdsa::Signature = signing_key.sign(canonical.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        // Tampered canonical string → verification fails.
        let tampered = canonical.replacen("POST", "GET", 1);
        assert!(matches!(
            verify_pop(&jwk, &tampered, &sig_b64),
            Err(PopError::VerificationFailed)
        ));

        // Flipped signature byte → still fails (as verification, not a parse
        // error, since the length stays valid).
        let mut raw = signature.to_bytes();
        raw[0] ^= 0x01;
        let bad_b64 = URL_SAFE_NO_PAD.encode(raw);
        assert!(verify_pop(&jwk, &canonical, &bad_b64).is_err());

        // Non-base64url signature.
        assert!(matches!(
            verify_pop(&jwk, &canonical, "not*base64*"),
            Err(PopError::SignatureEncoding)
        ));
    }
}
