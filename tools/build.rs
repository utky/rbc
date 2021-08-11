extern crate libbpf_cargo;
use std::io::{Result, Error, ErrorKind};
use std::path::PathBuf;
use std::{fs, path::Path};
use libbpf_cargo::SkeletonBuilder;

fn gen(indir: &Path, outdir: &Path) -> Result<Vec<PathBuf>> {
    fs::create_dir_all(outdir)?;
    let mut output_files = Vec::new();
    for e in fs::read_dir(indir)? {
        let source_path = e?.path();
        let metadata = fs::metadata(&source_path)?;
        if metadata.is_file() {
            let builder = SkeletonBuilder::new(&source_path);
            let output_skelton_filename = source_path
                .file_name().unwrap()
                .to_str().unwrap()
                .replace(".bpf.c", ".skel.rs");
            match builder.generate(outdir.join(&output_skelton_filename)) {
                Ok(_) => {
                    output_files.push(source_path);
                },
                Err(libbpf_error) => {
                    println!("cargo:warning=failed to build {:?} : {:?}", source_path, libbpf_error);
                    return Err(Error::new(ErrorKind::Other, libbpf_error.to_string()));
                }
            }
        }
    }
    Ok(output_files)
}

fn main() {
    let indir = Path::new("src/bpf/");
    let outdir = Path::new("src/bpf/.output");
    match gen(indir, outdir) {
        Ok(output_files) => {
            for output_file in output_files {
                println!("cargo:rerun-if-changed={}", output_file.display());
            }
        },
        Err(e) => {
            panic!("failed {}", e)
        }
    }
}
