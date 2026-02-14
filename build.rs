use std::io::Result;
use std::path::Path;

fn main() -> Result<()> {
    // Skip proto compilation if output already exists (for environments without protoc)
    let output_path = Path::new("src/api/softkms.rs");
    if output_path.exists() {
        println!("cargo:rerun-if-changed=proto/softkms.proto");
        return Ok(());
    }

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir("src/api")
        .compile(&["proto/softkms.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=proto/softkms.proto");
    Ok(())
}
