use std::{
    collections::HashMap, fs::File, io::{Error, Read}, sync::Arc
};

use axum::{
    extract::Request,
    http::StatusCode,
    middleware,
    middleware::Next,
    response::{Html, IntoResponse, Response},
    routing::{get, get_service, post},
    Router,
};

use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

use tera::{Tera, Context};

async fn trace_middleware(req: Request, next: Next) -> Result<impl IntoResponse, Response> {
    let span = tracing::info_span!("request", method = %req.method(), uri = %req.uri());
    let _enter = span.enter();

    tracing::info!("Handling request: {} {}", req.method(), req.uri());
    Ok(next.run(req).await)
}

#[tracing::instrument]
async fn index_page(tera: Arc<Tera>) -> Result<impl IntoResponse, Response> {
    let mut ctx = Context::new();

    let body = tera.render("index.html", &ctx).unwrap();
    Ok(Html(body))
}

#[tracing::instrument]
async fn login_page(tera: Arc<Tera>) -> Result<impl IntoResponse, Response> {
    let mut ctx = Context::new();

    let body = tera.render("login.html", &ctx).unwrap();
    Ok(Html(body))
}

async fn clickMe() -> &'static str {
    "You clicked me!"
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
        .route("/", get({
            let tera = tera.clone();
            move || index_page(tera)
        }))
        .route("/login", get({
            let tera = tera.clone();
            move || login_page(tera)
        }))
        .route("/login", post(clickMe))
        // .route("/test-navigation", get(test_navigation))
        .nest_service("/static", ServeDir::new("static"))
        .layer(middleware::from_fn(trace_middleware))
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:6969").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
