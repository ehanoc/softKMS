use std::io::Result;

fn main() -> Result<()> {
    // Always regenerate proto code to pick up changes
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir("src/api")
        .compile(&["proto/softkms.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=proto/softkms.proto");
    Ok(())
}
