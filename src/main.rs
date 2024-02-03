use axum::{
    async_trait,
    extract::Form,
    extract::FromRequestParts,
    extract::Request,
    extract::State,
    http::{request::Parts, StatusCode, header},
    middleware,
    middleware::Next,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, RequestPartsExt, Router,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};

use sqlx::{FromRow, PgPool};
use std::sync::Arc;
use thiserror::Error;

use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tera::{Context, Tera};

struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Keys {
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenData {
    user_id: i64,
}

#[derive(Debug, Serialize)]
struct AuthBody {
    access_token: String,
    token_type: String,
}

impl AuthBody {
    fn new(access_token: String) -> Self {
        Self {
            access_token,
            token_type: "Bearer".to_string(),
        }
    }
}
#[derive(Debug, Deserialize)]
struct LoginAuthForm {
    username_or_email: String,
    password: String,
}

impl LoginAuthForm {
    fn new(username_or_email: String, password: String) -> Self {
        Self {
            username_or_email,
            password,
        }
    }
}

#[derive(Debug)]
enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
}

#[async_trait]
impl<S> FromRequestParts<S> for TokenData
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;
        // Decode the user data
        let token_data =
            decode::<TokenData>(bearer.token(), &KEYS.decoding, &Validation::default())
                .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}
static KEYS: Lazy<Keys> = Lazy::new(|| {
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    Keys::new(secret.as_bytes())
});

#[derive(FromRow, Debug)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub role_id: i32,
}

#[derive(FromRow)]
pub struct Role {
    pub id: i32,
    pub name: String,
}

#[derive(Deserialize)]
pub struct RegisterForm {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error("database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("I/O error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("user already exists")]
    UserAlreadyExistsError,

    #[error("user not found")]
    UserNotFoundError,

    #[error("user login failed")]
    UserLoginFailedError,

    #[error("an unexpected error occurred")]
    UnexpectedError,
}

async fn create_user(
    pool: &PgPool,
    username: &str,
    email: &str,
    password_hash: &str,
    role_name: &str,
) -> Result<User, AppError> {
    let role = sqlx::query_as!(Role, "SELECT * FROM roles WHERE name = $1", role_name)
        .fetch_one(pool)
        .await
        .map_err(|e| {
            tracing::error!("Error fetching role: {}", e);
            e
        })
        .unwrap();

    // Check if the user already exists
    let user_exists = sqlx::query!(
        "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1 OR email = $2)",
        &username,
        &email
    )
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::error!("Database error: {}", e);
        e
    })
    .unwrap()
    .exists
    .unwrap();

    if user_exists {
        return Err(AppError::UserAlreadyExistsError.into());
    }

    let user = sqlx::query_as!(
        User,
        "INSERT INTO users (username, email, password_hash, role_id) VALUES ($1, $2, $3, $4) RETURNING *",
        username,
        email,
        password_hash,
        role.id
    )
    .fetch_one(pool)
    .await?;

    Ok(user)
}

async fn connect_to_db() -> Result<PgPool, AppError> {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    tracing::info!("Connecting to DB: {}", database_url);
    let pool = PgPool::connect(&database_url)
        .await
        .map_err(AppError::DatabaseError)?;

    tracing::info!("Connected to DB: {}", database_url);

    Ok(pool)
}

async fn trace_middleware(req: Request, next: Next) -> Result<impl IntoResponse, Response> {
    let span = tracing::info_span!("request", method = %req.method(), uri = %req.uri());
    let _enter = span.enter();

    tracing::info!("Handling request: {} {}", req.method(), req.uri());
    Ok(next.run(req).await)
}

#[tracing::instrument]
async fn index_page(
    State(state): State<Arc<ApplicationState>>,
) -> Result<impl IntoResponse, Response> {
    let tera = state.tera.clone();
    let ctx = Context::new();

    let body = tera.render("index.html", &ctx).unwrap();
    Ok(Html(body))
}

#[tracing::instrument]
async fn index_content(
    State(state): State<Arc<ApplicationState>>,
) -> Result<impl IntoResponse, Response> {
    let tera = state.tera.clone();
    let ctx = Context::new();

    let body = tera.render("index.content.html", &ctx).unwrap();
    Ok(Html(body))
}

#[tracing::instrument]
async fn login_page(
    State(state): State<Arc<ApplicationState>>,
) -> Result<impl IntoResponse, Response> {
    let tera = state.tera.clone();
    let ctx = Context::new();

    let body = tera.render("login.html", &ctx).unwrap();
    Ok(Html(body))
}

#[tracing::instrument]
async fn register_page(
    State(state): State<Arc<ApplicationState>>,
) -> Result<impl IntoResponse, Response> {
    let tera = state.tera.clone();
    let ctx = Context::new();

    let body = tera.render("register.html", &ctx).unwrap();
    Ok(Html(body))
}

async fn register(
    State(state): State<Arc<ApplicationState>>,
    Form(form): Form<RegisterForm>,
) -> Result<impl IntoResponse, Response> {
    let pool = state.db.clone();
    match create_user(
        &pool,
        &form.username,
        &form.email,
        &form.password,
        "student",
    )
    .await
    {
        Ok(user) => Ok(Html(format!("User created: {:?}", user))),
        Err(e) => {
            tracing::error!("Error creating user: {}", e);
            Err((
                StatusCode::BAD_REQUEST,
                format!("Could not create user: {}", e),
            )
                .into_response())
        }
    }
}

async fn login(State(app_state): State<Arc<ApplicationState>> ,Form(form): Form<LoginAuthForm>) -> Response {
    let username_or_email = form.username_or_email;
    let password = form.password;
    let pool = app_state.db.clone();

    if username_or_email.is_empty() || password.is_empty() {
        // return Err(AuthError::MissingCredentials.into());
    }

    // Check if the user exists
    let user_result = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE username = $1 OR email = $2 AND password_hash = $3", 
        &username_or_email,
        &username_or_email,
        &password
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        tracing::error!("Database error: {}", e);
        e
    });

    if user_result.is_err() {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("Failed to login".into())
            .unwrap();
    }

    // generate auth jwt token from user data
    let token_data = TokenData {
        user_id: user_result.unwrap().id,
    };

    let token = match encode(&Header::default(), &token_data, &KEYS.encoding) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Error creating token: {}", e);
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body("Token creation error".into())
                .unwrap();
        }
    };
    let cookie = format!(
        "Authorization={}; HttpOnly; Secure; SameSite=Strict; Path=/;",
        token
    );

    Response::builder()
        .status(StatusCode::OK)
        .header(header::SET_COOKIE, cookie)
        .body("Logged in successfully".into())
        .unwrap()
}

#[derive(Debug)]
struct ApplicationState {
    tera: Arc<Tera>,
    db: PgPool,
}

async fn seed_roles(pool: &PgPool) -> Result<(), AppError> {
    let roles = vec![
        "student",
        "teacher",
        "admin",
        "guest",
        "staffs",
        "operators",
    ];

    for role in roles {
        sqlx::query!(
            "INSERT INTO roles (name) VALUES ($1) ON CONFLICT (name) DO NOTHING",
            role
        )
        .execute(pool)
        .await?;
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().expect("Failed to load .env file");
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_origin(Any)
        .allow_headers(Any);

    let tera = match Tera::new("templates/**/*") {
        Ok(t) => Arc::new(t),
        Err(e) => {
            tracing::error!("Parsing error(s): {}", e);
            std::process::exit(1);
        }
    };

    let db = match connect_to_db().await {
        Ok(db) => db,
        Err(e) => {
            tracing::error!("Error connecting to DB: {}", e);
            std::process::exit(1);
        }
    };

    match seed_roles(&db).await {
        Ok(_) => tracing::info!("Roles have been seeded."),
        Err(e) => {
            tracing::error!("Error DB Seeding Roles: {}", e);
            std::process::exit(1);
        }
    }

    let app_state = ApplicationState {
        tera: tera.clone(),
        db: db.clone(),
    };

    let shared_state = Arc::new(app_state);

    let app = Router::new()
        .route("/", get(index_page))
        .route("/index-content", get(index_content))
        .route("/login", get(login_page))
        .route("/login", post(login))
        .route("/register", get(register_page))
        .route("/register", post(register))
        .nest_service("/static", ServeDir::new("static"))
        .layer(middleware::from_fn(trace_middleware))
        .with_state(shared_state)
        .layer(cors);

    let port = std::env::var("PORT").unwrap_or_else(|_| "6969".to_string());
    tracing::info!("Listening on port: http://0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
