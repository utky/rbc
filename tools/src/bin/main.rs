extern crate actix_web;
extern crate structopt ;
use log::{debug, error, log_enabled, info, Level};
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use structopt::StructOpt;
use prometheus::{opts, labels, register_int_counter, default_registry, gather, TextEncoder};
use tokio::spawn;
use std::collections::HashMap;

#[derive(Debug, StructOpt)]
#[structopt(name = "rbc", about = "An example of StructOpt usage.")]
enum Command {
    Server {
        #[structopt(short, long)]
        address: String,
        #[structopt(short, long)]
        port: u16,
    }
}

#[get("/metrics")]
async fn metrics() -> impl Responder {
    let encoder = TextEncoder::new();
    let metric_families = gather();
    HttpResponse::Ok().body(encoder.encode_to_string(&metric_families).unwrap())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let command = Command::from_args();
    match command {
        Command::Server { address, port } => {
            let counter = register_int_counter!("conter", "number of loop").unwrap();
            info!("starting HTTP server");
            let _handle = tokio::spawn(async move {
                loop {
                    info!("looping");
                    counter.inc();
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            });

            info!("starting HTTP server");
            HttpServer::new(move || {
                App::new()
                .service(metrics)
            })
            .bind((address, port))?
            .run()
            .await   
        },
    }
}
