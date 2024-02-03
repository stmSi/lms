# LMS (Learning Management System)

### Tech Stack
-   [Rust](https://www.rust-lang.org/)
-   [Axum](https://github.com/tokio-rs/axum)
-   [SQLx] (https://github.com/launchbadge/sqlx)
-   [TailwindCSS](https://tailwindcss.com/)
-   [PostCSS](https://postcss.org/)
-   [HTMX](https://htmx.org/)
-   [Tera] (https://github.com/Keats/tera)
-   [PostgreSQL](https://www.postgresql.org/)

Why? Don't ask!


### Pre-requisites

-   Install Rust and Cargo via [Rustup](https://rustup.rs/)
-   [Node.js](https://nodejs.org/en/download/) and [NPM](https://www.npmjs.com/get-npm) (for the building tailwindcss and postcss-cli)
-   [PostgreSQL](https://www.postgresql.org/download/)
    -   or `docker run --name postgres -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres`
-   [sqlx-cli](https://github.com/launchbadge/sqlx/tree/main/sqlx-cli) for creating db and running migrations
    ```bash
    cargo install sqlx-cli --no-default-features --features=postgres
    ```

### How to Run?
```bash
# Create a database
sqlx database create # Make sure you have postgres running

# Run the migrations
sqlx migrate run

cargo run
```
