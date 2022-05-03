use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};

#[derive(Debug, Clone)]
pub struct Configuration {
    address: String,
    port: u16,
}

impl Configuration {
    pub fn new(address: String, port: u16) -> Self {
        Configuration { address, port }
    }
}

#[get("/metrics")]
async fn metrics() -> impl Responder {
    HttpResponse::Ok().body("HELLO")
}

pub async fn start(config: Configuration) -> std::io::Result<()> {
    HttpServer::new(move || App::new().service(metrics))
        .bind((config.address, config.port))?
        .run()
        .await
}
