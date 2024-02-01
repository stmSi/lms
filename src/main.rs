use std::sync::Arc;

use axum::{
    extract::Request,
    middleware,
    middleware::Next,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};

use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

use tera::{Context, Tera};

async fn trace_middleware(req: Request, next: Next) -> Result<impl IntoResponse, Response> {
    let span = tracing::info_span!("request", method = %req.method(), uri = %req.uri());
    let _enter = span.enter();

    tracing::info!("Handling request: {} {}", req.method(), req.uri());
    Ok(next.run(req).await)
}

#[tracing::instrument]
async fn index_page(tera: Arc<Tera>) -> Result<impl IntoResponse, Response> {
    let ctx = Context::new();

    let body = tera.render("index.html", &ctx).unwrap();
    Ok(Html(body))
}

#[tracing::instrument]
async fn login_page(tera: Arc<Tera>) -> Result<impl IntoResponse, Response> {
    let ctx = Context::new();

    let body = tera.render("login.html", &ctx).unwrap();
    Ok(Html(body))
}

async fn login() -> impl IntoResponse {
    "Login"
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

    let app = Router::new()
        .route(
            "/",
            get({
                let tera = tera.clone();
                move || index_page(tera)
            }),
        )
        .route(
            "/login",
            get({
                let tera = tera.clone();
                move || login_page(tera)
            }),
        )
        .route("/login", post(login))
        .nest_service("/static", ServeDir::new("static"))
        .layer(middleware::from_fn(trace_middleware))
        .layer(cors);

    let port = std::env::var("PORT").unwrap_or_else(|_| "6969".to_string());
    tracing::info!("Listening on port: http://0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
