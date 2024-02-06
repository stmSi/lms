use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, errors::Result as JwtResult};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::env;
use axum::extract::{FromRequest, Request};
use axum::async_trait;
use axum::http::StatusCode;

#[derive(Debug, Serialize, Deserialize)]

pub struct TokenData {
    pub user_id: i64,
    pub exp: i64,
}

pub struct Keys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}

impl Keys {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }

    pub fn encode(&self, token_data: &TokenData) -> JwtResult<String> {
        encode(&Header::default(), token_data, &self.encoding)
    }

    pub fn decode(token: &str, decoding_key: &DecodingKey) -> JwtResult<jsonwebtoken::TokenData<TokenData>> {
        decode::<TokenData>(token, decoding_key, &Validation::default())
    }
}

pub static KEYS: Lazy<Keys> = Lazy::new(|| {
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    Keys::new(secret.as_bytes())
});

#[derive(Debug)]
pub struct AuthState {
    pub is_authenticated: bool,
    pub token_data: Option<TokenData>,
}

#[async_trait]
impl<T> FromRequest<T> for AuthState
where
    T: Send + Sync, // Ensure B meets all trait bounds required by Axum for body types
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request(request: Request, _state: &T) -> Result<Self, Self::Rejection> {
        // Attempt to extract Bearer Token from the request Cookie Authorization header
        let failed_auth = AuthState {
            is_authenticated: false,
            token_data: None,
        };

        let cookies = match request.headers().get(axum::http::header::COOKIE) {
            Some(c) => c.to_str().unwrap(),
            None => return Ok(failed_auth),
        };
                // Attempt to find the Authorization cookie
        let token = cookies.split(';').find_map(|cookie| {
            let cookie = cookie.trim_start();
            if cookie.starts_with("Authorization=Bearer ") {
                Some(cookie.trim_start_matches("Authorization=Bearer ").to_string())
            } else {
                None
            }
        });

        // If the Authorization cookie is not found or the token is not prefixed correctly, return failed auth
        if token.is_none() {
            return Ok(failed_auth);
        }

        let token_data = match decode(&token.unwrap(), &KEYS.decoding, &Validation::default()) {
            Ok(td) => td,
            Err(_) => return Ok(failed_auth),
        };

        Ok(AuthState {
            is_authenticated: true,
            token_data: Some(token_data.claims),
        })
    }
}
