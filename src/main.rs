mod jwt;
use jwt::*;

mod service_boostrap;
use service_boostrap::*;

use rand::distributions::Alphanumeric;
use rand::Rng;

use axum::{
    extract::Form,
    extract::State,
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use jsonwebtoken::{encode, Header};
use sqlx::{FromRow, PgPool};
use std::sync::Arc;
use thiserror::Error;

use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

use serde::Deserialize;
use tera::{Context, Tera};

#[derive(Debug, Deserialize)]
struct LoginAuthForm {
    username_or_email: String,
    password: String,
}

// ---- Database Models ----

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

#[derive(Deserialize, Debug, FromRow)]
pub struct TeacherDetail {
    pub user_id: i64,
    pub additional_info: Option<String>, // Change to Option<String> if the additional_info can be NULL
}

// StudentDetail struct corresponds to the student_details table in the database
#[derive(Deserialize, Debug, FromRow)]
pub struct StudentDetail {
    pub user_id: i64,
    pub enrollment_info: Option<String>, // Change to Option<String> if the enrollment_info can be NULL
}

// Class struct corresponds to the classes table in the database
#[derive(Deserialize, Debug, FromRow)]
pub struct Class {
    pub class_id: i32,
    pub title: String,
    pub user_id: i32,
}

// StudentClassEnrollment struct corresponds to the student_classes_enrollment table in the database
#[derive(Deserialize, Debug, FromRow)]
pub struct StudentClassEnrollment {
    pub enrollment_id: i32,
    pub class_id: i32,
    pub user_id: i64,
}

// Assignment struct corresponds to the assignments table in the database
#[derive(Deserialize, Debug, FromRow)]
pub struct Assignment {
    pub assignment_id: i32,
    pub title: String,
    pub description: String,
    pub class_id: i32,
}

// AssignmentQuestion struct corresponds to the assignment_questions table in the database
#[derive(Deserialize, Debug, FromRow)]
pub struct AssignmentQuestion {
    pub question_id: i32,
    pub assignment_id: i32,
    pub question_text: String,
}

// AssignmentAnswer struct corresponds to the assignment_answers table in the database
#[derive(Deserialize, Debug, FromRow)]
pub struct AssignmentAnswer {
    pub answer_id: i32,
    pub question_id: i32,
    pub user_id: i64,
    pub answer_text: String,
}

// Exam struct corresponds to the exams table in the database
#[derive(Deserialize, Debug, FromRow)]
pub struct Exam {
    pub exam_id: i32,
    pub title: String,
    pub class_id: i32,
    pub timer: std::time::Duration,
    pub marking_schema: Option<String>, // Change to Option<String> if the marking_schema can be NULL
}

// StudentExam struct corresponds to the student_exams table in the database
#[derive(Deserialize, Debug, FromRow)]
pub struct StudentExam {
    pub student_exam_id: i32,
    pub exam_id: i32,
    pub user_id: i64,
    pub score: Option<f64>, // Change to Option<f64> if the score can be NULL
}

// StudentPortfolio struct corresponds to the student_portfolio table in the database
#[derive(Deserialize, Debug, FromRow)]
pub struct StudentPortfolio {
    pub portfolio_id: i32,
    pub user_id: i64,
    pub content_html_or_markdown: Option<String>, // Change to Option<String> if the content can be NULL
}

// TeacherPortfolio struct corresponds to the teacher_portfolio table in the database
#[derive(Deserialize, Debug, FromRow)]
pub struct TeacherPortfolio {
    pub portfolio_id: i32,
    pub user_id: i64,
    pub content_html_or_markdown: Option<String>, // Change to Option<String> if the content can be NULL
}

// --- Database Models End ---

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
    .map_err(AppError::DatabaseError)?
    .exists
    .unwrap_or(false);

    if user_exists {
        return Err(AppError::UserAlreadyExistsError);
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

#[tracing::instrument]
async fn index_page(
    State(state): State<Arc<ApplicationState>>,
    auth_state: AuthState,
) -> Result<impl IntoResponse, Response> {
    let tera = state.tera.clone();
    let mut ctx = Context::new();
    ctx.insert("is_authenticated", &auth_state.is_authenticated);

    let body = tera.render("index.html", &ctx).unwrap();
    Ok(Html(body))
}

#[tracing::instrument]
async fn index_content(
    State(state): State<Arc<ApplicationState>>,
    auth_state: AuthState,
) -> Result<impl IntoResponse, Response> {
    let tera = state.tera.clone();
    let mut ctx = Context::new();

    ctx.insert("is_authenticated", &auth_state.is_authenticated);

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

fn generate_salt(length: usize) -> String {
    let salt: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();
    salt
}

async fn register(
    State(state): State<Arc<ApplicationState>>,
    Form(form): Form<RegisterForm>,
) -> Result<impl IntoResponse, Response> {
    let pool = state.db.clone();
    // hash the password with salt
    let salt = generate_salt(16);
    let password_hash = argon2::hash_encoded(form.password.as_bytes(), salt.as_bytes(), &argon2::Config::default()).unwrap();

    // generate salt
    match create_user(
        &pool,
        &form.username,
        &form.email,
        &password_hash,
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

async fn login(
    State(app_state): State<Arc<ApplicationState>>,
    Form(form): Form<LoginAuthForm>,
) -> Response {
    let username_or_email = form.username_or_email;
    let password = form.password;
    let pool = app_state.db.clone();

    if username_or_email.is_empty() || password.is_empty() {
        // return Err(AuthError::MissingCredentials.into());
    }

    // Check if the user exists
    let user_result = sqlx::query!(
        "SELECT users.id, users.username, users.email, users.password_hash, roles.name as role_name FROM users 
        INNER JOIN roles ON users.role_id = roles.id
        WHERE username = $1 OR email = $2
        ",
        &username_or_email,
        &username_or_email,
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

    let user = user_result.unwrap();
    let matches = argon2::verify_encoded(&user.password_hash, password.as_bytes()).unwrap();
    if !matches {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("Failed to login".into())
            .unwrap();
    }

    // generate auth jwt token from user data
    let token_data = TokenData {
        user_id: user.id,
        role: user.role_name,
        exp: 10000000000,
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
        "Authorization=Bearer {}; HttpOnly; Secure; SameSite=Strict; Path=/;",
        token
    );

    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::SET_COOKIE, cookie)
        .header(header::LOCATION, "/") // Redirect to the home page
        .body("Logged in successfully! Redirecting...".into())
        .unwrap()
}

async fn logout_handler() -> Response {
    let cookie = "Authorization=; Path=/; HttpOnly; Secure; SameSite=Strict; Expires=Thu, 01 Jan 1970 00:00:00 GMT;";
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::SET_COOKIE, cookie)
        .header(header::LOCATION, "/") // Redirect to the home page
        .body("Redirecting...".into())
        .unwrap()
}

async fn admin_index_page(
    State(state): State<Arc<ApplicationState>>,
    auth_state: AuthState,
) -> Result<impl IntoResponse, Response> {
    let tera = state.tera.clone();
    let mut ctx = Context::new();
    ctx.insert("is_authenticated", &auth_state.is_authenticated);

    let body = tera.render("admin/index.html", &ctx).unwrap();
    Ok(Html(body))
}

#[derive(Debug)]
struct ApplicationState {
    tera: Arc<Tera>,
    db: PgPool,
}

pub async fn authorize_admin_access(auth_state: AuthState, next: Next) -> Result<impl IntoResponse, Response> {
    if !auth_state.is_authenticated {
        return Err(Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, "/")
            .body("Redirecting to home...".into())
            .unwrap());
    }

    if auth_state.token_data.unwrap().role != "admin" {
        return Err(Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, "/")
            .body("Redirecting to home...".into())
            .unwrap());
    }
    Ok(next.run(auth_state.req).await)
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

    match sqlx::migrate!().run(&db).await {
        Ok(_) => tracing::info!("Database migration successful."),
        Err(e) => {
            tracing::error!("Error running migration: {}", e);
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

    let admin_routes = Router::new()
        .route("/", get(admin_index_page))
        .layer(middleware::from_fn(authorize_admin_access));

    let app = Router::new()
        .route("/", get(index_page))
        .route("/index-content", get(index_content))
        .route("/login", get(login_page))
        .route("/login", post(login))
        .route("/register", get(register_page))
        .route("/register", post(register))
        .route("/logout", get(logout_handler))

        .nest("/admin", admin_routes)
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
