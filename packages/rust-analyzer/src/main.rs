mod analyzer;
mod detector;
mod models;
mod server;
mod simulator;
mod exploit_patterns;

use actix_web::{middleware, App, HttpServer};
use env_logger::Env;
use log::info;
use std::sync::Arc;

use crate::analyzer::ChainAnalyzer;
use crate::server::configure_routes;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let bind_address = std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let solana_rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());

    info!("Initializing Dynamo Chain Analyzer");
    info!("Solana RPC: {}", solana_rpc_url);

    let analyzer = Arc::new(ChainAnalyzer::new(&solana_rpc_url));

    info!("Starting HTTP server on {}", bind_address);

    HttpServer::new(move || {
        App::new()
            .app_data(actix_web::web::Data::new(analyzer.clone()))
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            .configure(configure_routes)
    })
    .bind(&bind_address)?
    .run()
    .await
}

