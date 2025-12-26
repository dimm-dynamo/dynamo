use crate::analyzer::ChainAnalyzer;
use crate::models::*;
use actix_web::{get, post, web, HttpResponse, Responder};
use std::sync::Arc;
use std::time::SystemTime;

lazy_static::lazy_static! {
    static ref START_TIME: SystemTime = SystemTime::now();
}

#[get("/health")]
async fn health() -> impl Responder {
    let uptime = START_TIME.elapsed().unwrap_or_default().as_secs();
    
    HttpResponse::Ok().json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
    })
}

#[post("/analyze/transaction")]
async fn analyze_transaction(
    analyzer: web::Data<Arc<ChainAnalyzer>>,
    request: web::Json<AnalysisRequest>,
) -> impl Responder {
    match analyzer.analyze_transaction(request.into_inner()).await {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

#[post("/audit/contract")]
async fn audit_contract(
    analyzer: web::Data<Arc<ChainAnalyzer>>,
    request: web::Json<ContractAuditRequest>,
) -> impl Responder {
    match analyzer.audit_contract(request.into_inner()).await {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(health)
        .service(analyze_transaction)
        .service(audit_contract);
}

