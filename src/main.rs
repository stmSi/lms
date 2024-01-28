use askama::Template;
use axum::{
    extract::Request,
    middleware,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post, get_service},
    Router, http::StatusCode,
};
use tower_http::services::ServeDir;
use tower_http::cors::{CorsLayer, Any};

async fn trace_middleware(req: Request, next: Next) -> Result<impl IntoResponse, Response> {
    let span = tracing::info_span!("request", method = %req.method(), uri = %req.uri());
    let _enter = span.enter();

    tracing::info!("Handling request: {} {}", req.method(), req.uri());
    Ok(next.run(req).await)
}

#[derive(Template)]
#[template(path = "base.html")]
struct BaseTemplate<'a> {
    title: &'a str,
}

#[derive(Template)]
#[template(path = "home.html")]
struct HomeTemplate<'a> {
    name: &'a str,
}

#[tracing::instrument]
async fn home() -> HomeTemplate<'static> {
    HomeTemplate { name: "World" }
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

    let app = Router::new()
        .route("/", get(home))
        .route("/click-me", post(clickMe))
        .nest_service("/static", ServeDir::new("static"))
        .layer(middleware::from_fn(trace_middleware))
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
