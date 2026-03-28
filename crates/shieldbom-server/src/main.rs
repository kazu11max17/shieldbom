mod db;
mod errors;
mod routes;

use std::sync::Mutex;

use rusqlite::Connection;
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub struct AppState {
    pub db: std::sync::Arc<Mutex<Connection>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let conn = Connection::open("shieldbom-server.db")?;
    db::init(&conn)?;

    let state = AppState {
        db: std::sync::Arc::new(Mutex::new(conn)),
    };

    let app = routes::router(state);

    let addr = "0.0.0.0:3000";
    tracing::info!("ShieldBOM server listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
