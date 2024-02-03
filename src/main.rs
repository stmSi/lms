use axum::{
    extract::Form,
    extract::Request,
    extract::State,
    http::{Error, StatusCode},
    middleware,
    middleware::Next,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use sqlx::{FromRow, PgPool};
use std::sync::Arc;
use thiserror::Error;

use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

use tera::{Context, Tera};

#[derive(FromRow, Debug)]
pub struct User {
    pub id: i32,
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
    let pool = PgPool::connect("postgres://postgres:password@localhost:5432/lms")
        .await
        .map_err(|e| AppError::DatabaseError(e))?;
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
            Err((StatusCode::BAD_REQUEST, format!("Could not create user: {}", e)).into_response())
        }
    }
}

async fn login(req: Request) -> impl IntoResponse {
    "Login"
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

    println!("Roles have been seeded.");
    Ok(())
}

#[tokio::main]
async fn main() {
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
        Ok(_) => println!("Roles have been seeded."),
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
