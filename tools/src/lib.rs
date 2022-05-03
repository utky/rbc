extern crate actix_web;
extern crate libbpf_rs;
extern crate structopt;

use futures::join;
use std::{
    io::{Error, ErrorKind, Result},
    sync::Arc,
};

#[path = "bpf/.output/minimal.skel.rs"]
mod minimal;

mod http;
mod scheduler;
mod task;

fn map_libbpf_err(e: libbpf_rs::Error) -> Error {
    Error::new(ErrorKind::Other, e.to_string())
}

fn run_minimal(wait: u64) -> Result<()> {
    let builder = minimal::MinimalSkelBuilder::default();
    let open_skel = builder.open().map_err(map_libbpf_err)?;
    let mut loaded = open_skel.load().map_err(map_libbpf_err)?;
    let link = loaded
        .progs_mut()
        .handle_tp()
        .attach()
        .map_err(map_libbpf_err)?;
    Ok(())
}

pub async fn start_server() -> std::io::Result<()> {
    tokio::spawn(async { scheduler::start().await });
    let config = http::Configuration::new(String::from("127.0.0.1"), 8080);
    http::start(config.clone()).await
}
