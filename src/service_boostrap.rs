use axum::{extract::Request, middleware::Next, response::{IntoResponse, Response}};
use sqlx::PgPool;

use crate::AppError;


pub async fn connect_to_db() -> Result<PgPool, AppError> {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    tracing::info!("Connecting to DB: {}", database_url);
    let pool = PgPool::connect(&database_url)
        .await
        .map_err(AppError::DatabaseError)?;

    tracing::info!("Connected to DB: {}", database_url);

    Ok(pool)
}

pub async fn trace_middleware(req: Request, next: Next) -> Result<impl IntoResponse, Response> {
    let span = tracing::info_span!("request", method = %req.method(), uri = %req.uri());
    let _enter = span.enter();

    tracing::info!("Handling request: {} {}", req.method(), req.uri());
    Ok(next.run(req).await)
}


pub async fn seed_roles(pool: &PgPool) -> Result<(), AppError> {
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

