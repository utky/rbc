extern crate libbpf_rs;

use std::io::{Result, Error, ErrorKind};

#[path = "bpf/.output/minimal.skel.rs"]
mod minimal;

fn map_libbpf_err(e: libbpf_rs::Error) -> Error {
    Error::new(ErrorKind::Other, e.to_string())
}

fn run_minimal(wait: u64) -> Result<()> {
    let builder = minimal::MinimalSkelBuilder::default();
    let open_skel = builder.open().map_err(map_libbpf_err)?;
    let mut loaded = open_skel.load().map_err(map_libbpf_err)?;
    let link = loaded.progs_mut().handle_tp().attach().map_err(map_libbpf_err)?;
    Ok(())
}
